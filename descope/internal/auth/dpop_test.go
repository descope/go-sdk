package auth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/tests/mocks"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---- Test helpers ----

func dpopNewKeyPair(t *testing.T) (priv jwk.Key, pub jwk.Key) {
	t.Helper()
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	priv, err = jwk.FromRaw(raw)
	require.NoError(t, err)
	require.NoError(t, priv.Set(jwk.AlgorithmKey, jwa.ES256))
	pub, err = priv.PublicKey()
	require.NoError(t, err)
	return priv, pub
}

func dpopRandomJTI() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func dpopAthFor(accessToken string) string {
	h := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

type dpopProofOpts struct {
	typ        string
	includeJWK bool
	iat        time.Time
	jti        string
	htm        string
	htu        string
	ath        string // "" = omit claim; use emptyATH to include an empty value

	// Fine-grained claim control
	omitJTI         bool // omit the jti claim entirely
	emptyJTI        bool // include jti="" (present but empty)
	omitHTM         bool // omit the htm claim entirely
	emptyHTM        bool // include htm=""
	omitHTU         bool // omit the htu claim entirely
	emptyHTU        bool // include htu=""
	omitIAT         bool // omit the iat claim entirely
	includeEmptyATH bool // include ath="" (present but empty)

	// Key override: embed this key in the JWK header instead of the derived public key.
	// Used to test that private keys are rejected.
	jwkOverride jwk.Key
}

func dpopMakeProof(t *testing.T, priv jwk.Key, opts dpopProofOpts) string {
	t.Helper()
	pub, err := priv.PublicKey()
	require.NoError(t, err)

	tok := jwt.New()
	switch {
	case opts.omitJTI:
		// omit entirely
	case opts.emptyJTI:
		require.NoError(t, tok.Set("jti", ""))
	default:
		require.NoError(t, tok.Set("jti", opts.jti))
	}
	switch {
	case opts.omitHTM:
		// omit entirely
	case opts.emptyHTM:
		require.NoError(t, tok.Set("htm", ""))
	default:
		require.NoError(t, tok.Set("htm", opts.htm))
	}
	switch {
	case opts.omitHTU:
		// omit entirely
	case opts.emptyHTU:
		require.NoError(t, tok.Set("htu", ""))
	default:
		require.NoError(t, tok.Set("htu", opts.htu))
	}
	if !opts.omitIAT {
		require.NoError(t, tok.Set(jwt.IssuedAtKey, opts.iat))
	}
	switch {
	case opts.includeEmptyATH:
		require.NoError(t, tok.Set("ath", ""))
	case opts.ath != "":
		require.NoError(t, tok.Set("ath", opts.ath))
	}

	typ := opts.typ
	if typ == "" {
		typ = "dpop+jwt"
	}
	hdrs := jws.NewHeaders()
	require.NoError(t, hdrs.Set(jws.TypeKey, typ))
	require.NoError(t, hdrs.Set(jws.AlgorithmKey, jwa.ES256))
	if opts.includeJWK {
		jwkToEmbed := pub
		if opts.jwkOverride != nil {
			jwkToEmbed = opts.jwkOverride
		}
		require.NoError(t, hdrs.Set(jws.JWKKey, jwkToEmbed))
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, priv, jws.WithProtectedHeaders(hdrs)))
	require.NoError(t, err)
	return string(signed)
}

func dpopValidOpts(method, url, accessToken string) dpopProofOpts {
	return dpopProofOpts{
		typ:        "dpop+jwt",
		includeJWK: true,
		iat:        time.Now(),
		jti:        dpopRandomJTI(),
		htm:        method,
		htu:        url,
		ath:        dpopAthFor(accessToken),
	}
}

func dpopJKTOf(t *testing.T, pub jwk.Key) string {
	t.Helper()
	tp, err := dpopThumbprint(pub)
	require.NoError(t, err)
	return tp
}

const dpopTestURL = "https://api.example.com/v1/resource"
const dpopTestToken = "the-access-token" //nolint:gosec

// ---- validateDPoPProof tests ----

func TestDPoP_BoundToken_MissingProof_Rejected(t *testing.T) {
	// storedJKT present but no proof → downgrade attack
	err := validateDPoPProof("", "GET", dpopTestURL, dpopTestToken, "some-jkt", time.Now)
	require.Error(t, err)
}

func TestDPoP_ValidProof_Accepted(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", dpopTestURL, dpopTestToken)
	proof := dpopMakeProof(t, priv, opts)
	require.NoError(t, validateDPoPProof(proof, "GET", dpopTestURL, dpopTestToken, storedJKT, time.Now))
}

func TestDPoP_KeyMismatch_Rejected(t *testing.T) {
	priv1, _ := dpopNewKeyPair(t)
	_, pub2 := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub2) // token bound to key2
	opts := dpopValidOpts("GET", dpopTestURL, dpopTestToken)
	proof := dpopMakeProof(t, priv1, opts) // but proof signed by key1
	require.Error(t, validateDPoPProof(proof, "GET", dpopTestURL, dpopTestToken, storedJKT, time.Now))
}

func TestDPoP_WrongHTM_Rejected(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("POST", dpopTestURL, dpopTestToken) // proof says POST
	proof := dpopMakeProof(t, priv, opts)
	require.Error(t, validateDPoPProof(proof, "GET", dpopTestURL, dpopTestToken, storedJKT, time.Now)) // request is GET
}

// Fix #1: htm comparison must be case-sensitive (RFC 7230 §3.1.1)
func TestDPoP_HTM_CaseSensitive_Rejected(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("post", dpopTestURL, dpopTestToken) // lowercase htm
	proof := dpopMakeProof(t, priv, opts)
	// "post" must NOT match "POST" — HTTP methods are case-sensitive
	require.Error(t, validateDPoPProof(proof, "POST", dpopTestURL, dpopTestToken, storedJKT, time.Now))
}

func TestDPoP_WrongHTU_Rejected(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", "https://evil.example.com/steal", dpopTestToken)
	proof := dpopMakeProof(t, priv, opts)
	require.Error(t, validateDPoPProof(proof, "GET", dpopTestURL, dpopTestToken, storedJKT, time.Now))
}

func TestDPoP_HTU_IgnoresQueryString(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", dpopTestURL, dpopTestToken) // htu without query
	proof := dpopMakeProof(t, priv, opts)
	// request URL has query — should still match
	require.NoError(t, validateDPoPProof(proof, "GET", dpopTestURL+"?foo=bar", dpopTestToken, storedJKT, time.Now))
}

// Fix #5: htu matching strips default ports (443/80)
func TestDPoP_HTU_DefaultPortStripped_Matches(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	// proof htu includes explicit :443, request URL omits it — must match
	opts := dpopValidOpts("GET", "https://api.example.com:443/v1/resource", dpopTestToken)
	proof := dpopMakeProof(t, priv, opts)
	require.NoError(t, validateDPoPProof(proof, "GET", "https://api.example.com/v1/resource", dpopTestToken, storedJKT, time.Now))
}

func TestDPoP_HTU_DefaultPortOmitted_Matches(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	// proof htu omits :443, request URL includes it — must match
	opts := dpopValidOpts("GET", "https://api.example.com/v1/resource", dpopTestToken)
	proof := dpopMakeProof(t, priv, opts)
	require.NoError(t, validateDPoPProof(proof, "GET", "https://api.example.com:443/v1/resource", dpopTestToken, storedJKT, time.Now))
}

func TestDPoP_HTU_NonDefaultPort_Rejected(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	// proof htu uses :8443, request URL uses default port — must NOT match
	opts := dpopValidOpts("GET", "https://api.example.com:8443/v1/resource", dpopTestToken)
	proof := dpopMakeProof(t, priv, opts)
	require.Error(t, validateDPoPProof(proof, "GET", "https://api.example.com/v1/resource", dpopTestToken, storedJKT, time.Now))
}

func TestDPoP_ExpiredIAT_Rejected(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", dpopTestURL, dpopTestToken)
	opts.iat = time.Now().Add(-2 * time.Minute)
	proof := dpopMakeProof(t, priv, opts)
	require.Error(t, validateDPoPProof(proof, "GET", dpopTestURL, dpopTestToken, storedJKT, time.Now))
}

// Fix #2: forward iat tolerance is 5s, not 60s
func TestDPoP_FutureIAT_BeyondFutureWindow_Rejected(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", dpopTestURL, dpopTestToken)
	// iat 10s in the future — beyond the 5s forward tolerance
	err := validateDPoPProof(
		dpopMakeProof(t, priv, opts),
		"GET", dpopTestURL, dpopTestToken, storedJKT,
		func() time.Time { return opts.iat.Add(-10 * time.Second) },
	)
	require.Error(t, err)
}

func TestDPoP_FutureIAT_WithinFutureWindow_Accepted(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", dpopTestURL, dpopTestToken)
	// iat 3s in the future — within the 5s forward tolerance
	err := validateDPoPProof(
		dpopMakeProof(t, priv, opts),
		"GET", dpopTestURL, dpopTestToken, storedJKT,
		func() time.Time { return opts.iat.Add(-3 * time.Second) },
	)
	require.NoError(t, err)
}

func TestDPoP_MissingAth_Rejected(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", dpopTestURL, dpopTestToken)
	opts.ath = "" // omit ath claim
	proof := dpopMakeProof(t, priv, opts)
	require.Error(t, validateDPoPProof(proof, "GET", dpopTestURL, dpopTestToken, storedJKT, time.Now))
}

func TestDPoP_WrongAth_Rejected(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", dpopTestURL, "wrong-token") // ath for wrong token
	proof := dpopMakeProof(t, priv, opts)
	require.Error(t, validateDPoPProof(proof, "GET", dpopTestURL, dpopTestToken, storedJKT, time.Now))
}

func TestDPoP_MalformedProof_Rejected(t *testing.T) {
	require.Error(t, validateDPoPProof("not-a-jwt", "GET", dpopTestURL, dpopTestToken, "some-jkt", time.Now))
}

func TestDPoP_WrongTypHeader_Rejected(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", dpopTestURL, dpopTestToken)
	opts.typ = "at+jwt"
	proof := dpopMakeProof(t, priv, opts)
	require.Error(t, validateDPoPProof(proof, "GET", dpopTestURL, dpopTestToken, storedJKT, time.Now))
}

func TestDPoP_MissingJWKHeader_Rejected(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", dpopTestURL, dpopTestToken)
	opts.includeJWK = false
	proof := dpopMakeProof(t, priv, opts)
	require.Error(t, validateDPoPProof(proof, "GET", dpopTestURL, dpopTestToken, storedJKT, time.Now))
}

// Fix #3: symmetric (OctetSeq) key in the JWK header must be rejected
func TestDPoP_SymmetricKeyInJWK_Rejected(t *testing.T) {
	// Build a JWS signed with HS256 and an OctetSeq JWK embedded in the header.
	rawSecret := make([]byte, 32)
	_, err := rand.Read(rawSecret)
	require.NoError(t, err)

	symKey, err := jwk.FromRaw(rawSecret)
	require.NoError(t, err)
	require.NoError(t, symKey.Set(jwk.AlgorithmKey, jwa.HS256))

	tok := jwt.New()
	require.NoError(t, tok.Set("jti", dpopRandomJTI()))
	require.NoError(t, tok.Set("htm", "GET"))
	require.NoError(t, tok.Set("htu", dpopTestURL))
	require.NoError(t, tok.Set(jwt.IssuedAtKey, time.Now()))
	require.NoError(t, tok.Set("ath", dpopAthFor(dpopTestToken)))

	hdrs := jws.NewHeaders()
	require.NoError(t, hdrs.Set(jws.TypeKey, "dpop+jwt"))
	require.NoError(t, hdrs.Set(jws.AlgorithmKey, jwa.HS256))
	require.NoError(t, hdrs.Set(jws.JWKKey, symKey))

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256, symKey, jws.WithProtectedHeaders(hdrs)))
	require.NoError(t, err)

	// HS256 is not in the allow-list, so it will be rejected at the alg check.
	// Even if alg were somehow allowed, OctetSeq key type must also be rejected.
	err = validateDPoPProof(string(signed), "GET", dpopTestURL, dpopTestToken, "any-jkt", time.Now)
	require.Error(t, err)
}

func dpopNewEd25519KeyPair(t *testing.T) (priv jwk.Key, pub jwk.Key) {
	t.Helper()
	edPubRaw, edPrivRaw, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	edPrivJWK, err := jwk.FromRaw(edPrivRaw)
	require.NoError(t, err)
	edPubJWK, err := jwk.FromRaw(edPubRaw)
	require.NoError(t, err)
	return edPrivJWK, edPubJWK
}

func dpopMakeEdDSAProof(t *testing.T, priv, pub jwk.Key, opts dpopProofOpts) string {
	t.Helper()
	tok := jwt.New()
	require.NoError(t, tok.Set("jti", opts.jti))
	require.NoError(t, tok.Set("htm", opts.htm))
	require.NoError(t, tok.Set("htu", opts.htu))
	require.NoError(t, tok.Set(jwt.IssuedAtKey, opts.iat))
	require.NoError(t, tok.Set("ath", opts.ath))

	hdrs := jws.NewHeaders()
	require.NoError(t, hdrs.Set(jws.TypeKey, "dpop+jwt"))
	require.NoError(t, hdrs.Set(jws.JWKKey, pub))

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.EdDSA, priv, jws.WithProtectedHeaders(hdrs)))
	require.NoError(t, err)
	return string(signed)
}

func TestDPoP_EdDSA_Accepted(t *testing.T) {
	priv, pub := dpopNewEd25519KeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", dpopTestURL, dpopTestToken)
	proof := dpopMakeEdDSAProof(t, priv, pub, opts)
	require.NoError(t, validateDPoPProof(proof, "GET", dpopTestURL, dpopTestToken, storedJKT, time.Now))
}

// "jwk must not contain a private key" — RSA private key embedded in JWK header.
func TestDPoP_RSAPrivateKeyInJWK_Rejected(t *testing.T) {
	rsaRaw, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaPrivJWK, err := jwk.FromRaw(rsaRaw)
	require.NoError(t, err)
	// RS256 is in the allow-list; the check for private key type fires before sig verification.
	tok := jwt.New()
	require.NoError(t, tok.Set("jti", dpopRandomJTI()))
	require.NoError(t, tok.Set("htm", "GET"))
	require.NoError(t, tok.Set("htu", dpopTestURL))
	require.NoError(t, tok.Set(jwt.IssuedAtKey, time.Now()))
	require.NoError(t, tok.Set("ath", dpopAthFor(dpopTestToken)))

	hdrs := jws.NewHeaders()
	require.NoError(t, hdrs.Set(jws.TypeKey, "dpop+jwt"))
	require.NoError(t, hdrs.Set(jws.JWKKey, rsaPrivJWK)) // private key in header

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, rsaPrivJWK, jws.WithProtectedHeaders(hdrs)))
	require.NoError(t, err)

	err = validateDPoPProof(string(signed), "GET", dpopTestURL, dpopTestToken, "any-jkt", time.Now)
	require.Error(t, err)
}

// "jwk must not contain a private key" — ECDSA private key embedded in JWK header.
func TestDPoP_ECDSAPrivateKeyInJWK_Rejected(t *testing.T) {
	priv, _ := dpopNewKeyPair(t)
	// Embed the private key (not the derived public key) in the JWK header.
	opts := dpopValidOpts("GET", dpopTestURL, dpopTestToken)
	opts.jwkOverride = priv
	proof := dpopMakeProof(t, priv, opts)
	err := validateDPoPProof(proof, "GET", dpopTestURL, dpopTestToken, "any-jkt", time.Now)
	require.Error(t, err)
}

// "signature verification failed" — valid structure but tampered signature bytes.
func TestDPoP_TamperedSignature_Rejected(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	proof := dpopMakeProof(t, priv, dpopValidOpts("GET", dpopTestURL, dpopTestToken))

	// Flip the first character of the base64url signature (third JWT segment).
	parts := strings.SplitN(proof, ".", 3)
	require.Len(t, parts, 3)
	sig := []byte(parts[2])
	if sig[0] == 'A' {
		sig[0] = 'B'
	} else {
		sig[0] = 'A'
	}
	tampered := parts[0] + "." + parts[1] + "." + string(sig)

	require.Error(t, validateDPoPProof(tampered, "GET", dpopTestURL, dpopTestToken, storedJKT, time.Now))
}

func TestDPoP_MissingJTI_Rejected(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", dpopTestURL, dpopTestToken)
	opts.omitJTI = true
	proof := dpopMakeProof(t, priv, opts)
	require.Error(t, validateDPoPProof(proof, "GET", dpopTestURL, dpopTestToken, storedJKT, time.Now))
}

func TestDPoP_EmptyJTI_Rejected(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", dpopTestURL, dpopTestToken)
	opts.emptyJTI = true
	proof := dpopMakeProof(t, priv, opts)
	require.Error(t, validateDPoPProof(proof, "GET", dpopTestURL, dpopTestToken, storedJKT, time.Now))
}

func TestDPoP_MissingHTM_Rejected(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", dpopTestURL, dpopTestToken)
	opts.omitHTM = true
	proof := dpopMakeProof(t, priv, opts)
	require.Error(t, validateDPoPProof(proof, "GET", dpopTestURL, dpopTestToken, storedJKT, time.Now))
}

func TestDPoP_EmptyHTM_Rejected(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", dpopTestURL, dpopTestToken)
	opts.emptyHTM = true
	proof := dpopMakeProof(t, priv, opts)
	require.Error(t, validateDPoPProof(proof, "GET", dpopTestURL, dpopTestToken, storedJKT, time.Now))
}

func TestDPoP_MissingHTU_Rejected(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", dpopTestURL, dpopTestToken)
	opts.omitHTU = true
	proof := dpopMakeProof(t, priv, opts)
	require.Error(t, validateDPoPProof(proof, "GET", dpopTestURL, dpopTestToken, storedJKT, time.Now))
}

func TestDPoP_EmptyHTU_Rejected(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", dpopTestURL, dpopTestToken)
	opts.emptyHTU = true
	proof := dpopMakeProof(t, priv, opts)
	require.Error(t, validateDPoPProof(proof, "GET", dpopTestURL, dpopTestToken, storedJKT, time.Now))
}

func TestDPoP_MissingIAT_Rejected(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", dpopTestURL, dpopTestToken)
	opts.omitIAT = true
	proof := dpopMakeProof(t, priv, opts)
	require.Error(t, validateDPoPProof(proof, "GET", dpopTestURL, dpopTestToken, storedJKT, time.Now))
}

func TestDPoP_EmptyATH_Rejected(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", dpopTestURL, dpopTestToken)
	opts.ath = ""               // clear the valid ath
	opts.includeEmptyATH = true // include ath="" (present but empty)
	proof := dpopMakeProof(t, priv, opts)
	require.Error(t, validateDPoPProof(proof, "GET", dpopTestURL, dpopTestToken, storedJKT, time.Now))
}

func TestDPoP_RejectedAlgs(t *testing.T) {
	assert.False(t, dpopIsAllowedAlg("none"))
	assert.False(t, dpopIsAllowedAlg("HS256"))
	assert.False(t, dpopIsAllowedAlg("HS384"))
	assert.False(t, dpopIsAllowedAlg("HS512"))
	assert.False(t, dpopIsAllowedAlg("unknown"))
	assert.True(t, dpopIsAllowedAlg("EdDSA"))
	assert.True(t, dpopIsAllowedAlg("ES256"))
	assert.True(t, dpopIsAllowedAlg("ES384"))
	assert.True(t, dpopIsAllowedAlg("ES512"))
	assert.True(t, dpopIsAllowedAlg("RS256"))
	assert.True(t, dpopIsAllowedAlg("RS384"))
	assert.True(t, dpopIsAllowedAlg("RS512"))
	assert.True(t, dpopIsAllowedAlg("PS256"))
	assert.True(t, dpopIsAllowedAlg("PS384"))
	assert.True(t, dpopIsAllowedAlg("PS512"))
}

func TestDPoP_ProofWhitespaceTrimmed_Accepted(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	proof := dpopMakeProof(t, priv, dpopValidOpts("GET", dpopTestURL, dpopTestToken))
	require.NoError(t, validateDPoPProof("  "+proof+"  ", "GET", dpopTestURL, dpopTestToken, storedJKT, time.Now))
}

func TestDPoP_ProofExceedsMaxLength_Rejected(t *testing.T) {
	oversized := strings.Repeat("x", maxDPoPProofLen+1)
	err := validateDPoPProof(oversized, "GET", dpopTestURL, dpopTestToken, "some-jkt", time.Now)
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidToken)
}

func TestDPoPSanitizeProof_TrimsAndPasses(t *testing.T) {
	proof, err := dpopSanitizeProof("  jwt-body  ")
	require.NoError(t, err)
	assert.Equal(t, "jwt-body", proof)
}

func TestDPoPSanitizeProof_RejectsOversized(t *testing.T) {
	_, err := dpopSanitizeProof(strings.Repeat("a", maxDPoPProofLen+1))
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidToken)
}

// ---- descope.Token.GetDPoPThumbprint ----

func TestToken_GetDPoPThumbprint_Present(t *testing.T) {
	tok := &descope.Token{
		Claims: map[string]any{
			"cnf": map[string]any{"jkt": "my-thumbprint"},
		},
	}
	assert.Equal(t, "my-thumbprint", tok.GetDPoPThumbprint())
}

func TestToken_GetDPoPThumbprint_Missing(t *testing.T) {
	tok := &descope.Token{Claims: map[string]any{}}
	assert.Equal(t, "", tok.GetDPoPThumbprint())
}

func TestToken_GetDPoPThumbprint_NilClaims(t *testing.T) {
	tok := &descope.Token{}
	assert.Equal(t, "", tok.GetDPoPThumbprint())
}

func TestToken_GetDPoPThumbprint_InvalidCnfType(t *testing.T) {
	tok := &descope.Token{Claims: map[string]any{"cnf": "not-a-map"}}
	assert.Equal(t, "", tok.GetDPoPThumbprint())
}

func TestToken_GetDPoPThumbprint_InvalidJKTType(t *testing.T) {
	tok := &descope.Token{Claims: map[string]any{"cnf": map[string]any{"jkt": 123}}}
	assert.Equal(t, "", tok.GetDPoPThumbprint())
}

// ---- ValidateSessionWithRequest DPoP integration tests ----

// dpopNewAuthForKey creates an authenticationService that accepts JWTs signed
// with the given private key (ES256, kid="dpop-test").
func dpopNewAuthForKey(t *testing.T, priv jwk.Key) *authenticationService {
	t.Helper()
	pub, err := priv.PublicKey()
	require.NoError(t, err)
	require.NoError(t, pub.Set(jwk.KeyIDKey, "dpop-test"))
	b, err := json.Marshal(pub)
	require.NoError(t, err)
	a, err := newTestAuthConf(
		&AuthParams{ProjectID: "a", PublicKey: string(b)},
		&api.ClientParams{ProjectID: "a"},
		nil,
	)
	require.NoError(t, err)
	return a
}

// dpopSignSessionJWT signs a minimal session JWT with the given key and optional extra claims.
func dpopSignSessionJWT(t *testing.T, priv jwk.Key, extraClaims map[string]any) string {
	t.Helper()
	tok := jwt.New()
	require.NoError(t, tok.Set(jwt.AudienceKey, []string{"test"}))
	require.NoError(t, tok.Set(jwt.SubjectKey, "someuser"))
	require.NoError(t, tok.Set(jwt.IssuedAtKey, time.Now()))
	require.NoError(t, tok.Set(jwt.ExpirationKey, time.Now().Add(time.Hour)))
	require.NoError(t, tok.Set("drn", "DS"))
	require.NoError(t, tok.Set("iss", "test"))
	for k, v := range extraClaims {
		require.NoError(t, tok.Set(k, v))
	}

	hdrs := jws.NewHeaders()
	require.NoError(t, hdrs.Set(jws.KeyIDKey, "dpop-test"))
	require.NoError(t, hdrs.Set(jws.TypeKey, "JWT"))
	require.NoError(t, hdrs.Set(jws.AlgorithmKey, jwa.ES256))

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, priv, jws.WithProtectedHeaders(hdrs)))
	require.NoError(t, err)
	return string(signed)
}

func TestValidateSessionWithRequest_DPoPScheme_NoCnfJKT_Rejected(t *testing.T) {
	// "Authorization: DPoP <token>" where the token has no cnf.jkt → rejected.
	// The DPoP scheme signals the client intends DPoP; a token without cnf.jkt is not DPoP-bound
	// and must not be accepted under the DPoP scheme.
	sessionPriv, _ := dpopNewKeyPair(t)
	a := dpopNewAuthForKey(t, sessionPriv)
	sessionToken := dpopSignSessionJWT(t, sessionPriv, nil)

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "DPoP "+sessionToken)

	ok, _, err := a.ValidateSessionWithRequest(req)
	require.Error(t, err)
	assert.False(t, ok)
	assert.ErrorIs(t, err, descope.ErrInvalidToken)
}

func TestValidateSessionWithRequest_DPoPBoundToken_ValidProof_Accepted(t *testing.T) {
	// Session token has cnf.jkt → DPoP proof is enforced.
	sessionPriv, _ := dpopNewKeyPair(t)
	a := dpopNewAuthForKey(t, sessionPriv)

	// DPoP client key pair
	dpopPriv, dpopPub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, dpopPub)

	sessionToken := dpopSignSessionJWT(t, sessionPriv, map[string]any{
		"cnf": map[string]any{"jkt": storedJKT},
	})

	const reqURL = "http://example.test/resource"
	opts := dpopValidOpts("GET", reqURL, sessionToken)
	proof := dpopMakeProof(t, dpopPriv, opts)

	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	req.Header.Set("Authorization", "DPoP "+sessionToken)
	req.Header.Set("DPoP", proof)

	ok, token, err := a.ValidateSessionWithRequest(req)
	require.NoError(t, err)
	require.True(t, ok)
	require.NotNil(t, token)
}

func TestValidateSessionWithRequest_DPoPBoundToken_MissingProof_Rejected(t *testing.T) {
	// Session token has cnf.jkt but no DPoP header → downgrade attack rejected.
	sessionPriv, _ := dpopNewKeyPair(t)
	a := dpopNewAuthForKey(t, sessionPriv)
	_, dpopPub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, dpopPub)
	sessionToken := dpopSignSessionJWT(t, sessionPriv, map[string]any{
		"cnf": map[string]any{"jkt": storedJKT},
	})

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "DPoP "+sessionToken)
	// No DPoP header

	ok, _, err := a.ValidateSessionWithRequest(req)
	require.Error(t, err)
	assert.False(t, ok)
}

func TestValidateSessionWithRequest_DPoPBoundToken_WrongKey_Rejected(t *testing.T) {
	// Session token has cnf.jkt for dpopPub2 but proof signed by dpopPriv1 → rejected.
	sessionPriv, _ := dpopNewKeyPair(t)
	a := dpopNewAuthForKey(t, sessionPriv)
	dpopPriv1, _ := dpopNewKeyPair(t)
	_, dpopPub2 := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, dpopPub2) // token bound to key2

	sessionToken := dpopSignSessionJWT(t, sessionPriv, map[string]any{
		"cnf": map[string]any{"jkt": storedJKT},
	})

	const reqURL = "http://example.test/resource"
	opts := dpopValidOpts("GET", reqURL, sessionToken)
	proof := dpopMakeProof(t, dpopPriv1, opts) // signed by key1 — mismatch

	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	req.Header.Set("Authorization", "DPoP "+sessionToken)
	req.Header.Set("DPoP", proof)

	ok, _, err := a.ValidateSessionWithRequest(req)
	require.Error(t, err)
	assert.False(t, ok)
}

// "expected exactly one JWS signature" — JWS JSON General Serialization with two signatures.
// jws.Parse succeeds and returns len(sigs)==2, which must be rejected.
func TestDPoP_MultipleSignatures_Rejected(t *testing.T) {
	priv, _ := dpopNewKeyPair(t)
	// Build a valid compact JWS then re-serialize it as JSON with 2 signature entries.
	compact := dpopMakeProof(t, priv, dpopValidOpts("GET", dpopTestURL, dpopTestToken))
	parts := strings.SplitN(compact, ".", 3)
	require.Len(t, parts, 3)
	// JSON General Serialization: payload is the second segment; each entry repeats the same header+sig.
	jwsJSON := fmt.Sprintf(
		`{"payload":%q,"signatures":[{"protected":%q,"signature":%q},{"protected":%q,"signature":%q}]}`,
		parts[1], parts[0], parts[2], parts[0], parts[2],
	)
	err := validateDPoPProof(jwsJSON, "GET", dpopTestURL, dpopTestToken, "any-jkt", time.Now)
	require.Error(t, err)
}

// "jwk must not contain a private key" — OKP (Ed25519) private key embedded in JWK header,
// proof signed with RS256 (an allowed algorithm) so the private-key check is reached.
func TestDPoP_OKPPrivateKeyInJWK_Rejected(t *testing.T) {
	rsaRaw, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaPrivJWK, err := jwk.FromRaw(rsaRaw)
	require.NoError(t, err)

	_, edPrivRaw, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	edPrivJWK, err := jwk.FromRaw(edPrivRaw)
	require.NoError(t, err)

	tok := jwt.New()
	require.NoError(t, tok.Set("jti", dpopRandomJTI()))
	require.NoError(t, tok.Set("htm", "GET"))
	require.NoError(t, tok.Set("htu", dpopTestURL))
	require.NoError(t, tok.Set(jwt.IssuedAtKey, time.Now()))
	require.NoError(t, tok.Set("ath", dpopAthFor(dpopTestToken)))

	hdrs := jws.NewHeaders()
	require.NoError(t, hdrs.Set(jws.TypeKey, "dpop+jwt"))
	require.NoError(t, hdrs.Set(jws.AlgorithmKey, jwa.RS256))
	require.NoError(t, hdrs.Set(jws.JWKKey, edPrivJWK)) // OKP private key in header

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, rsaPrivJWK, jws.WithProtectedHeaders(hdrs)))
	require.NoError(t, err)

	err = validateDPoPProof(string(signed), "GET", dpopTestURL, dpopTestToken, "any-jkt", time.Now)
	require.Error(t, err)
}

// "symmetric key not allowed in DPoP proof" — OctetSeq key embedded in JWK header,
// proof signed with RS256 (an allowed algorithm) so the OctetSeq check is reached.
func TestDPoP_OctetSeqKeyWithAllowedAlg_Rejected(t *testing.T) {
	rsaRaw, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaPrivJWK, err := jwk.FromRaw(rsaRaw)
	require.NoError(t, err)

	rawSecret := make([]byte, 32)
	_, err = rand.Read(rawSecret)
	require.NoError(t, err)
	symKey, err := jwk.FromRaw(rawSecret)
	require.NoError(t, err)

	tok := jwt.New()
	require.NoError(t, tok.Set("jti", dpopRandomJTI()))
	require.NoError(t, tok.Set("htm", "GET"))
	require.NoError(t, tok.Set("htu", dpopTestURL))
	require.NoError(t, tok.Set(jwt.IssuedAtKey, time.Now()))
	require.NoError(t, tok.Set("ath", dpopAthFor(dpopTestToken)))

	hdrs := jws.NewHeaders()
	require.NoError(t, hdrs.Set(jws.TypeKey, "dpop+jwt"))
	require.NoError(t, hdrs.Set(jws.AlgorithmKey, jwa.RS256))
	require.NoError(t, hdrs.Set(jws.JWKKey, symKey)) // OctetSeq key in header

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, rsaPrivJWK, jws.WithProtectedHeaders(hdrs)))
	require.NoError(t, err)

	err = validateDPoPProof(string(signed), "GET", dpopTestURL, dpopTestToken, "any-jkt", time.Now)
	require.Error(t, err)
}

// ---- dpopHtuMatches unit tests ----

func TestDPoPHtuMatches_PathOnlyHTU_Rejected(t *testing.T) {
	// htu without scheme/host must be rejected (not an absolute URI)
	assert.False(t, dpopHtuMatches("/just/a/path", "https://api.example.com/just/a/path"))
}

func TestDPoPHtuMatches_PathOnlyRequestURL_Rejected(t *testing.T) {
	// requestURL without scheme/host must be rejected
	assert.False(t, dpopHtuMatches("https://api.example.com/just/a/path", "/just/a/path"))
}

func TestDPoPHtuMatches_DifferentPaths_Rejected(t *testing.T) {
	assert.False(t, dpopHtuMatches("https://api.example.com/foo", "https://api.example.com/bar"))
}

// HTTP default port 80 stripping in dpopNormalizeHost.
func TestDPoP_HTU_HTTP_DefaultPort80Stripped_Matches(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", "http://api.example.com:80/v1/resource", dpopTestToken)
	proof := dpopMakeProof(t, priv, opts)
	require.NoError(t, validateDPoPProof(proof, "GET", "http://api.example.com/v1/resource", dpopTestToken, storedJKT, time.Now))
}

// ---- Fix 1: ValidateAndRefreshSessionWithRequest DPoP enforcement ----

func TestValidateAndRefreshSessionWithRequest_DPoPBoundToken_ValidProof_Accepted(t *testing.T) {
	sessionPriv, _ := dpopNewKeyPair(t)
	a := dpopNewAuthForKey(t, sessionPriv)
	dpopPriv, dpopPub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, dpopPub)
	sessionToken := dpopSignSessionJWT(t, sessionPriv, map[string]any{
		"cnf": map[string]any{"jkt": storedJKT},
	})
	const reqURL = "http://example.test/resource"
	proof := dpopMakeProof(t, dpopPriv, dpopValidOpts("GET", reqURL, sessionToken))

	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	req.Header.Set("Authorization", "DPoP "+sessionToken)
	req.Header.Set("DPoP", proof)

	ok, token, err := a.ValidateAndRefreshSessionWithRequest(req, nil)
	require.NoError(t, err)
	require.True(t, ok)
	require.NotNil(t, token)
}

func TestValidateAndRefreshSessionWithRequest_DPoPBoundToken_MissingProof_Rejected(t *testing.T) {
	sessionPriv, _ := dpopNewKeyPair(t)
	a := dpopNewAuthForKey(t, sessionPriv)
	_, dpopPub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, dpopPub)
	sessionToken := dpopSignSessionJWT(t, sessionPriv, map[string]any{
		"cnf": map[string]any{"jkt": storedJKT},
	})

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "DPoP "+sessionToken)

	ok, _, err := a.ValidateAndRefreshSessionWithRequest(req, nil)
	require.Error(t, err)
	assert.False(t, ok)
}

func TestValidateAndRefreshSessionWithRequest_DPoPBoundToken_WrongKey_Rejected(t *testing.T) {
	sessionPriv, _ := dpopNewKeyPair(t)
	a := dpopNewAuthForKey(t, sessionPriv)
	dpopPriv1, _ := dpopNewKeyPair(t)
	_, dpopPub2 := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, dpopPub2)
	sessionToken := dpopSignSessionJWT(t, sessionPriv, map[string]any{
		"cnf": map[string]any{"jkt": storedJKT},
	})
	const reqURL = "http://example.test/resource"
	proof := dpopMakeProof(t, dpopPriv1, dpopValidOpts("GET", reqURL, sessionToken))

	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	req.Header.Set("Authorization", "DPoP "+sessionToken)
	req.Header.Set("DPoP", proof)

	ok, _, err := a.ValidateAndRefreshSessionWithRequest(req, nil)
	require.Error(t, err)
	assert.False(t, ok)
}

func TestValidateAndRefreshSessionWithRequest_DPoPScheme_NoCnfJKT_Rejected(t *testing.T) {
	sessionPriv, _ := dpopNewKeyPair(t)
	a := dpopNewAuthForKey(t, sessionPriv)
	sessionToken := dpopSignSessionJWT(t, sessionPriv, nil)

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "DPoP "+sessionToken)

	ok, _, err := a.ValidateAndRefreshSessionWithRequest(req, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidToken)
	assert.False(t, ok)
}

// TestValidateAndRefreshSessionWithRequest_DPoPBoundToken_AfterRefresh_NoDPoPHeader_Rejected
// proves the security fix: when an expired DPoP-bound session token is presented in the
// Authorization header and a refresh is performed, the presented session token must still
// be subject to DPoP enforcement — no DPoP proof means the request is rejected.
func TestValidateAndRefreshSessionWithRequest_DPoPBoundToken_AfterRefresh_NoDPoPHeader_Rejected(t *testing.T) {
	// Create a key pair used to sign both the refresh token and the response session token.
	sessionPriv, sessionPub := dpopNewKeyPair(t)

	// DPoP client key pair: both the presented (expired) and the refreshed session token
	// are bound to this key.
	_, dpopPub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, dpopPub)

	// Build the expired DPoP-bound session JWT that will be presented in the Authorization header.
	// It is already expired, so validateSession will fail and a refresh will be triggered.
	expiredSessionJWT := dpopSignSessionJWT(t, sessionPriv, map[string]any{
		"cnf": map[string]any{"jkt": storedJKT},
		// Override expiry to put it in the past.
		jwt.ExpirationKey: time.Now().Add(-time.Hour),
	})

	// Build the DPoP-bound session JWT that the refresh endpoint will return.
	dpopBoundSessionJWT := dpopSignSessionJWT(t, sessionPriv, map[string]any{
		"cnf": map[string]any{"jkt": storedJKT},
	})

	// Build a valid refresh token signed with the same key (drn=DSR marks it as a refresh token).
	refreshToken := dpopSignSessionJWT(t, sessionPriv, map[string]any{"drn": "DSR"})

	// Serialize the public key so that newTestAuthConf can be configured with it.
	pub, err := sessionPriv.PublicKey()
	require.NoError(t, err)
	require.NoError(t, pub.Set(jwk.KeyIDKey, "dpop-test"))
	_ = sessionPub // already derived above
	pubBytes, err := json.Marshal(pub)
	require.NoError(t, err)

	// HTTP mock: simulates a successful /refresh response with a DPoP-bound session token.
	refreshBody := fmt.Sprintf(`{"sessionJwt":%q,"refreshJwt":"","cookiePath":"/","cookieDomain":""}`, dpopBoundSessionJWT)
	a, err := newTestAuthConf(
		&AuthParams{ProjectID: "a", PublicKey: string(pubBytes)},
		&api.ClientParams{ProjectID: "a"},
		mocks.Do(func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBufferString(refreshBody)),
			}, nil
		}),
	)
	require.NoError(t, err)

	// Request: carries the expired DPoP-bound session token in the Authorization header
	// and the refresh token in a cookie, but deliberately omits the DPoP proof header
	// to simulate a downgrade attack.
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "DPoP "+expiredSessionJWT)
	req.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: refreshToken})
	// No DPoP proof header — this is the attack vector.

	ok, tok, authErr := a.ValidateAndRefreshSessionWithRequest(req, nil)
	require.Error(t, authErr, "expected DPoP enforcement to reject because no proof was provided for the presented DPoP-bound session token")
	assert.False(t, ok)
	assert.Nil(t, tok)
	assert.ErrorIs(t, authErr, descope.ErrInvalidToken)
}

// ---- Fix 3: case-insensitive auth-scheme matching ----

func TestParseAuthScheme_NoDelimiter_Rejected(t *testing.T) {
	_, _, ok := parseAuthScheme("BearerTokenWithNoSeparator")
	assert.False(t, ok)
}

func TestParseAuthScheme_EmptyToken_Rejected(t *testing.T) {
	_, _, ok := parseAuthScheme("Bearer ")
	assert.False(t, ok)
}

func TestParseAuthScheme_TabDelimiter_Accepted(t *testing.T) {
	scheme, token, ok := parseAuthScheme("DPoP\tmy-token")
	require.True(t, ok)
	assert.Equal(t, "dpop", scheme)
	assert.Equal(t, "my-token", token)
}

func TestValidateSessionWithRequest_InvalidJWT_ReturnsError(t *testing.T) {
	sessionPriv, _ := dpopNewKeyPair(t)
	a := dpopNewAuthForKey(t, sessionPriv)
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "Bearer not-a-valid-jwt")
	ok, _, err := a.ValidateSessionWithRequest(req)
	require.Error(t, err)
	assert.False(t, ok)
}

func TestProvideTokens_DPoPSchemeLowercase_Extracted(t *testing.T) {
	provider := &defaultRequestTokensProvider{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "dpop my-token")
	sessionToken, _ := provider.ProvideTokens(req)
	assert.Equal(t, "my-token", sessionToken)
}

func TestProvideTokens_BearerSchemeMixedCase_Extracted(t *testing.T) {
	provider := &defaultRequestTokensProvider{}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "BEARER my-token")
	sessionToken, _ := provider.ProvideTokens(req)
	assert.Equal(t, "my-token", sessionToken)
}

func TestValidateSessionWithRequest_DPoPSchemeLowercase_NoCnfJKT_Rejected(t *testing.T) {
	sessionPriv, _ := dpopNewKeyPair(t)
	a := dpopNewAuthForKey(t, sessionPriv)
	sessionToken := dpopSignSessionJWT(t, sessionPriv, nil)

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("Authorization", "dpop "+sessionToken) // lowercase scheme

	ok, _, err := a.ValidateSessionWithRequest(req)
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidToken)
	assert.False(t, ok)
}

// ---- Fix 4: multiple DPoP headers rejected ----

func TestValidateSessionWithRequest_DPoPProofTrimmed_Accepted(t *testing.T) {
	sessionPriv, _ := dpopNewKeyPair(t)
	a := dpopNewAuthForKey(t, sessionPriv)
	dpopPriv, dpopPub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, dpopPub)
	sessionToken := dpopSignSessionJWT(t, sessionPriv, map[string]any{
		"cnf": map[string]any{"jkt": storedJKT},
	})
	const reqURL = "http://example.test/resource"
	proof := dpopMakeProof(t, dpopPriv, dpopValidOpts("GET", reqURL, sessionToken))

	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	req.Header.Set("Authorization", "DPoP "+sessionToken)
	req.Header.Set("DPoP", "  "+proof+"  ")

	ok, _, err := a.ValidateSessionWithRequest(req)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestValidateSessionWithRequest_MultipleDPoPHeaders_Rejected(t *testing.T) {
	sessionPriv, _ := dpopNewKeyPair(t)
	a := dpopNewAuthForKey(t, sessionPriv)
	dpopPriv, dpopPub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, dpopPub)
	sessionToken := dpopSignSessionJWT(t, sessionPriv, map[string]any{
		"cnf": map[string]any{"jkt": storedJKT},
	})
	const reqURL = "http://example.test/resource"
	proof := dpopMakeProof(t, dpopPriv, dpopValidOpts("GET", reqURL, sessionToken))

	req := httptest.NewRequest(http.MethodGet, reqURL, nil)
	req.Header.Set("Authorization", "DPoP "+sessionToken)
	req.Header.Add("DPoP", proof)
	req.Header.Add("DPoP", proof) // duplicate

	ok, _, err := a.ValidateSessionWithRequest(req)
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidToken)
	assert.False(t, ok)
}

func TestDPoP_EnforceDPoP_UnboundToken_Noop(t *testing.T) {
	// Token with no cnf.jkt → no DPoP check, no proof needed.
	tok := &descope.Token{Claims: map[string]any{}}
	req := httptest.NewRequest(http.MethodGet, "http://example.test/resource", nil)
	require.NoError(t, enforceDPoPIfNeeded(req, "any-token", tok))
}

// ---- Fix 5a: X-Forwarded-Proto / X-Forwarded-Host in dpopRequestURL ----

func TestDPoPRequestURL_AbsoluteURL_Untouched(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://api.example.com/resource", nil)
	req.Header.Set("X-Forwarded-Proto", "http")
	req.Header.Set("X-Forwarded-Host", "other.example.com")
	// Absolute URL should be returned as-is, ignoring forwarded headers.
	assert.Equal(t, "https://api.example.com/resource", dpopRequestURL(req))
}

func TestDPoPRequestURL_NoForwardedHeaders_FallsBackToTLS(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Host = "api.example.com"
	// No TLS, no forwarded headers → http.
	assert.Equal(t, "http://api.example.com/resource", dpopRequestURL(req))
}

func TestDPoPRequestURL_ForwardedProto_Used(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Host = "api.example.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	assert.Equal(t, "https://api.example.com/resource", dpopRequestURL(req))
}

func TestDPoPRequestURL_ForwardedProtoCommaList_FirstValueUsed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Host = "api.example.com"
	req.Header.Set("X-Forwarded-Proto", "https, http")
	assert.Equal(t, "https://api.example.com/resource", dpopRequestURL(req))
}

func TestDPoPRequestURL_ForwardedHost_Used(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Host = "internal.svc"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "api.example.com")
	assert.Equal(t, "https://api.example.com/resource", dpopRequestURL(req))
}

func TestDPoPRequestURL_ForwardedProtoAndHost_EndToEnd_Accepted(t *testing.T) {
	// Proof signed with https://api.example.com/resource; request comes in
	// over plain HTTP behind a TLS-terminating proxy that sets X-Forwarded-*.
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	const proofURL = "https://api.example.com/resource"
	const accessToken = "my-access-token"
	proof := dpopMakeProof(t, priv, dpopValidOpts("GET", proofURL, accessToken))

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Host = "api.example.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("DPoP", proof)

	err := validateDPoPProof(proof, "GET", dpopRequestURL(req), accessToken, storedJKT, time.Now)
	require.NoError(t, err)
}

// htu comparison matches backend: no dot-segment or percent-encoding normalization.

func TestDPoP_HTU_DotSegments_NotEquivalent(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", "https://api.example.com/a/./b", dpopTestToken)
	proof := dpopMakeProof(t, priv, opts)
	require.Error(t, validateDPoPProof(proof, "GET", "https://api.example.com/a/b", dpopTestToken, storedJKT, time.Now))
}

func TestDPoP_HTU_PercentEncodedUnreserved_NotEquivalent(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", "https://api.example.com/foo%2Dbar", dpopTestToken)
	proof := dpopMakeProof(t, priv, opts)
	require.Error(t, validateDPoPProof(proof, "GET", "https://api.example.com/foo-bar", dpopTestToken, storedJKT, time.Now))
}

func TestDPoP_HTU_PercentEncodedReservedPreserved(t *testing.T) {
	// %2F is '/', a reserved char — /foo%2Fbar ≠ /foo/bar.
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", "https://api.example.com/foo%2Fbar", dpopTestToken)
	proof := dpopMakeProof(t, priv, opts)
	require.Error(t, validateDPoPProof(proof, "GET", "https://api.example.com/foo/bar", dpopTestToken, storedJKT, time.Now))
}

func TestDPoP_HTU_TrailingSlashPreserved(t *testing.T) {
	// /foo/ and /foo are not equivalent — trailing slash is preserved.
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", "https://api.example.com/foo/", dpopTestToken)
	proof := dpopMakeProof(t, priv, opts)
	require.Error(t, validateDPoPProof(proof, "GET", "https://api.example.com/foo", dpopTestToken, storedJKT, time.Now))
}
