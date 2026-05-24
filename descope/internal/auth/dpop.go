package auth

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/descope/go-sdk/descope"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// dpopJTIStore tracks recently seen DPoP proof JTIs for replay detection (RFC 9449 §11.1).
// JTIs are retained for dpopJTITTL. The TTL must be at least iatWindow+iatFutureWindow (65s)
// to cover the full proof acceptance window; we use 2×iatWindow (120s) matching the backend.
// Entries are evicted lazily on each write.
type dpopJTIStore struct {
	mu      sync.Mutex
	entries map[string]time.Time // jti → expiry
}

func newDPoPJTIStore() *dpopJTIStore {
	return &dpopJTIStore{entries: make(map[string]time.Time)}
}

// seenOrAdd returns true (replay detected) if jti was already recorded, otherwise
// records it with an expiry of now+dpopJTITTL and returns false.
func (s *dpopJTIStore) seenOrAdd(jti string, now time.Time) bool {
	expiry := now.Add(dpopJTITTL)
	s.mu.Lock()
	defer s.mu.Unlock()
	// Lazy eviction: purge entries that have expired (inclusive boundary).
	for k, exp := range s.entries {
		if !now.Before(exp) {
			delete(s.entries, k)
		}
	}
	if _, seen := s.entries[jti]; seen {
		return true
	}
	s.entries[jti] = expiry
	return false
}

// dpopIATWindow is the backward tolerance for the DPoP proof iat claim (RFC 9449 §4.3 step 11).
const dpopIATWindow = 60 * time.Second

// dpopIATFutureWindow is the forward tolerance for the iat claim.
// A tight window prevents pre-generated proofs from extending their effective lifetime.
const dpopIATFutureWindow = 5 * time.Second

// dpopJTITTL is the retention window for seen JTI values in the replay store.
// Must be ≥ iatWindow+iatFutureWindow (65s): a proof with iat near the future boundary
// is accepted for iatFutureWindow, then accepted again for the full iatWindow after the
// clock catches up — total exposure is 65s. 2×iatWindow (120s) safely covers this,
// matching the backend's JTITTL constant.
const dpopJTITTL = 2 * dpopIATWindow

// maxDPoPJTILen caps the jti claim length to prevent map-key memory inflation (RFC 9449 §11.1).
// Matches the backend's maxJTILen constant.
const maxDPoPJTILen = 128

// maxDPoPProofLen caps an incoming DPoP proof (RFC 9449 §11.1 — limit memory exposure).
const maxDPoPProofLen = 8192

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
	"EdDSA": true,
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

// dpopSanitizeProof trims whitespace and enforces the maximum proof size.
func dpopSanitizeProof(proof string) (string, error) {
	proof = strings.TrimSpace(proof)
	if len(proof) > maxDPoPProofLen {
		return "", descope.ErrInvalidToken.WithMessage("DPoP proof exceeds maximum length")
	}
	return proof, nil
}

// validateDPoPProof validates a DPoP proof at the resource server (RFC 9449 §7.1–7.2).
// storedJKT must be non-empty (the cnf.jkt from the validated access token).
// If proof is empty, returns ErrInvalidToken (downgrade attack prevention).
// jtiStore, when non-nil, enforces replay protection by tracking seen JTI values.
func validateDPoPProof(proof, method, requestURL, accessToken, storedJKT string, clock func() time.Time, jtiStore *dpopJTIStore) error {
	now := clock() // capture once; used for both replay-store and iat window checks

	var err error
	proof, err = dpopSanitizeProof(proof)
	if err != nil {
		return err
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
		jwt.WithVerify(false), // already verified by jws.Verify above
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
	if len(jti) > maxDPoPJTILen {
		return descope.ErrInvalidToken.WithMessage("jti exceeds maximum length")
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
	diff := now.Sub(iat)
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

	// Burn the JTI only after all other checks pass (matching backend ordering):
	// burning early would let an attacker consume a legitimate client's JTI by
	// submitting a proof that fails a later check (e.g. ath mismatch).
	if jtiStore != nil && jtiStore.seenOrAdd(jti, now) {
		return descope.ErrInvalidToken.WithMessage("Cannot use the same DPoP header twice (replay protection).")
	}

	return nil
}

// dpopHtuMatches compares URIs per RFC 9449 §4.1:
// ignores query string and fragment, normalises scheme and host to lowercase,
// strips default ports (443 for https, 80 for http).
// Both htu and rawURL must be absolute (scheme + host present).
func dpopHtuMatches(htu, rawURL string) bool {
	a, err := url.Parse(htu)
	if err != nil {
		return false // notest — url.Parse does not error on non-nil inputs in Go
	}
	b, err := url.Parse(rawURL)
	if err != nil {
		return false // notest
	}
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
// Honors X-Forwarded-Proto and X-Forwarded-Host when present — trust these
// only when running behind a proxy you control.
func dpopRequestURL(r *http.Request) string {
	if r.URL.IsAbs() {
		return r.URL.String()
	}
	scheme := "https"
	if fwdProto := r.Header.Get("X-Forwarded-Proto"); fwdProto != "" {
		if idx := strings.IndexByte(fwdProto, ','); idx >= 0 {
			fwdProto = fwdProto[:idx]
		}
		scheme = strings.ToLower(strings.TrimSpace(fwdProto))
	} else if r.TLS == nil {
		scheme = "http"
	}
	host := r.Host
	if fwdHost := r.Header.Get("X-Forwarded-Host"); fwdHost != "" {
		host = strings.TrimSpace(fwdHost)
	}
	u := *r.URL
	u.Scheme = scheme
	u.Host = host
	return u.String()
}
