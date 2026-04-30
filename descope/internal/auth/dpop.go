package auth

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/descope/go-sdk/descope"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// dpopIATWindow is the backward tolerance for the DPoP proof iat claim (RFC 9449 §4.3 step 11).
const dpopIATWindow = 60 * time.Second

// dpopIATFutureWindow is the forward tolerance for the iat claim.
// A tight window prevents pre-generated proofs from extending their effective lifetime.
const dpopIATFutureWindow = 5 * time.Second

// dpopAllowedAlgs is the set of permitted DPoP proof signing algorithms.
// Matches dpop_signing_alg_values_supported in the OIDC discovery document.
// An explicit allow-list is used so unknown or future algorithm strings are rejected by default.
var dpopAllowedAlgs = map[string]bool{
	"RS256": true,
	"RS384": true,
	"RS512": true,
	"ES256": true,
	"ES384": true,
	"ES512": true,
	"PS256": true,
	"PS384": true,
	"PS512": true,
}

func dpopIsAllowedAlg(alg string) bool {
	return dpopAllowedAlgs[alg]
}

func dpopThumbprint(key jwk.Key) (string, error) {
	tp, err := key.Thumbprint(crypto.SHA256)
	if err != nil { // notest
		return "", descope.ErrInvalidToken.WithMessage("failed to compute JWK thumbprint")
	}
	return base64.RawURLEncoding.EncodeToString(tp), nil
}

// ValidateDPoPProof validates a DPoP proof at the resource server (RFC 9449 §7.1–7.2).
// storedJKT is the cnf.jkt value from the validated access token.
// If storedJKT is empty, returns nil — plain Bearer token, no DPoP required.
// If storedJKT is non-empty and proof is empty, returns ErrInvalidToken (downgrade attack).
func ValidateDPoPProof(proof, method, requestURL, accessToken, storedJKT string) error {
	return validateDPoPProof(proof, method, requestURL, accessToken, storedJKT, time.Now)
}

func validateDPoPProof(proof, method, requestURL, accessToken, storedJKT string, clock func() time.Time) error {
	if storedJKT == "" {
		return nil
	}
	if proof == "" {
		return descope.ErrInvalidToken.WithMessage("DPoP proof required: access token is DPoP-bound (cnf.jkt present)")
	}

	msg, err := jws.Parse([]byte(proof))
	if err != nil {
		return descope.ErrInvalidToken.WithMessage("malformed DPoP JWT")
	}
	sigs := msg.Signatures()
	if len(sigs) != 1 {
		return descope.ErrInvalidToken.WithMessage("expected exactly one JWS signature")
	}
	hdrs := sigs[0].ProtectedHeaders()

	if hdrs.Type() != "dpop+jwt" {
		return descope.ErrInvalidToken.WithMessage("typ must be dpop+jwt")
	}

	alg := hdrs.Algorithm()
	if !dpopIsAllowedAlg(string(alg)) {
		return descope.ErrInvalidToken.WithMessage("rejected algorithm in DPoP proof")
	}

	embeddedKey := hdrs.JWK()
	if embeddedKey == nil {
		return descope.ErrInvalidToken.WithMessage("missing jwk header")
	}
	if _, isPriv := embeddedKey.(jwk.RSAPrivateKey); isPriv {
		return descope.ErrInvalidToken.WithMessage("jwk must not contain a private key")
	}
	if _, isPriv := embeddedKey.(jwk.ECDSAPrivateKey); isPriv {
		return descope.ErrInvalidToken.WithMessage("jwk must not contain a private key")
	}
	if _, isPriv := embeddedKey.(jwk.OKPPrivateKey); isPriv {
		return descope.ErrInvalidToken.WithMessage("jwk must not contain a private key")
	}
	if embeddedKey.KeyType() == jwa.OctetSeq {
		return descope.ErrInvalidToken.WithMessage("symmetric key not allowed in DPoP proof")
	}
	if _, err = jws.Verify([]byte(proof), jws.WithKey(alg, embeddedKey)); err != nil {
		return descope.ErrInvalidToken.WithMessage("signature verification failed")
	}

	token, err := jwt.Parse([]byte(proof),
		jwt.WithKey(alg, embeddedKey),
		jwt.WithValidate(false),
	)
	if err != nil {
		return descope.ErrInvalidToken.WithMessage("failed to parse DPoP JWT claims") // notest
	}

	jtiRaw, ok := token.Get("jti")
	if !ok {
		return descope.ErrInvalidToken.WithMessage("missing jti claim")
	}
	jti, ok := jtiRaw.(string)
	if !ok || jti == "" {
		return descope.ErrInvalidToken.WithMessage("jti must be non-empty string")
	}

	htmRaw, ok := token.Get("htm")
	if !ok {
		return descope.ErrInvalidToken.WithMessage("missing htm claim")
	}
	htm, ok := htmRaw.(string)
	if !ok || htm == "" {
		return descope.ErrInvalidToken.WithMessage("htm must be non-empty string")
	}

	htuRaw, ok := token.Get("htu")
	if !ok {
		return descope.ErrInvalidToken.WithMessage("missing htu claim")
	}
	htu, ok := htuRaw.(string)
	if !ok || htu == "" {
		return descope.ErrInvalidToken.WithMessage("htu must be non-empty string")
	}

	if htm != method {
		return descope.ErrInvalidToken.WithMessage("htm mismatch")
	}

	if !dpopHtuMatches(htu, requestURL) {
		return descope.ErrInvalidToken.WithMessage("htu mismatch")
	}

	iat := token.IssuedAt()
	if iat.IsZero() {
		return descope.ErrInvalidToken.WithMessage("missing iat claim")
	}
	diff := clock().Sub(iat)
	// Asymmetric window: 60s backward tolerance, 5s forward tolerance.
	// The tight forward window prevents pre-generated proofs from extending their effective lifetime.
	if diff <= -dpopIATFutureWindow || diff >= dpopIATWindow {
		return descope.ErrInvalidToken.WithMessage("iat out of acceptable window")
	}

	athRaw, ok := token.Get("ath")
	if !ok {
		return descope.ErrInvalidToken.WithMessage("missing ath claim in DPoP proof (required at resource server)")
	}
	ath, ok := athRaw.(string)
	if !ok || ath == "" {
		return descope.ErrInvalidToken.WithMessage("ath must be a non-empty string")
	}
	hash := sha256.Sum256([]byte(accessToken))
	expected := base64.RawURLEncoding.EncodeToString(hash[:])
	if ath != expected {
		return descope.ErrInvalidToken.WithMessage("ath does not match access token hash")
	}

	tp, err := dpopThumbprint(embeddedKey)
	if err != nil { // notest
		return err
	}
	if tp != storedJKT {
		return descope.ErrInvalidToken.WithMessage("DPoP proof key does not match cnf.jkt in access token")
	}

	return nil
}

// dpopHtuMatches compares URIs per RFC 9449 §4.1:
// ignores query string and fragment, normalises scheme and host to lowercase,
// strips default ports (443 for https, 80 for http).
// Both URIs must be absolute (scheme + host present) — path-only URIs are rejected.
func dpopHtuMatches(htu, rawURL string) bool {
	a, err := url.Parse(htu)
	if err != nil {
		return false
	}
	b, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	// Require absolute URIs
	if a.Scheme == "" || a.Host == "" || b.Scheme == "" || b.Host == "" {
		return false
	}
	a.RawQuery, a.Fragment = "", ""
	b.RawQuery, b.Fragment = "", ""
	a.Scheme = strings.ToLower(a.Scheme)
	b.Scheme = strings.ToLower(b.Scheme)
	a.Host = dpopNormalizeHost(a.Host, a.Scheme)
	b.Host = dpopNormalizeHost(b.Host, b.Scheme)
	return a.String() == b.String()
}

// dpopNormalizeHost lowercases the host and strips default ports (443 for https, 80 for http).
func dpopNormalizeHost(h, scheme string) string {
	host, port, err := net.SplitHostPort(h)
	if err != nil {
		// No port component — just lowercase
		return strings.ToLower(h)
	}
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		return strings.ToLower(host)
	}
	return strings.ToLower(h)
}

// dpopRequestURL reconstructs the absolute URL for DPoP htu comparison.
// For httptest.NewRequest with a full URL, r.URL is already absolute.
// For real server requests, scheme and host are derived from r.TLS and r.Host.
func dpopRequestURL(r *http.Request) string {
	if r.URL.IsAbs() {
		return r.URL.String()
	}
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	u := *r.URL
	u.Scheme = scheme
	u.Host = r.Host
	return u.String()
}
