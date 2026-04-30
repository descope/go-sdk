package auth

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
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

// ---- ValidateDPoPProof tests ----

func TestDPoP_PlainBearer_EmptyJKT_Accepted(t *testing.T) {
	// storedJKT empty → plain Bearer, DPoP not required
	require.NoError(t, ValidateDPoPProof("", "GET", dpopTestURL, dpopTestToken, ""))
}

func TestDPoP_BoundToken_MissingProof_Rejected(t *testing.T) {
	// storedJKT present but no proof → downgrade attack
	err := ValidateDPoPProof("", "GET", dpopTestURL, dpopTestToken, "some-jkt")
	require.Error(t, err)
}

func TestDPoP_ValidProof_Accepted(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", dpopTestURL, dpopTestToken)
	proof := dpopMakeProof(t, priv, opts)
	require.NoError(t, ValidateDPoPProof(proof, "GET", dpopTestURL, dpopTestToken, storedJKT))
}

func TestDPoP_KeyMismatch_Rejected(t *testing.T) {
	priv1, _ := dpopNewKeyPair(t)
	_, pub2 := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub2) // token bound to key2
	opts := dpopValidOpts("GET", dpopTestURL, dpopTestToken)
	proof := dpopMakeProof(t, priv1, opts) // but proof signed by key1
	require.Error(t, ValidateDPoPProof(proof, "GET", dpopTestURL, dpopTestToken, storedJKT))
}

func TestDPoP_WrongHTM_Rejected(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("POST", dpopTestURL, dpopTestToken) // proof says POST
	proof := dpopMakeProof(t, priv, opts)
	require.Error(t, ValidateDPoPProof(proof, "GET", dpopTestURL, dpopTestToken, storedJKT)) // request is GET
}

// Fix #1: htm comparison must be case-sensitive (RFC 7230 §3.1.1)
func TestDPoP_HTM_CaseSensitive_Rejected(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("post", dpopTestURL, dpopTestToken) // lowercase htm
	proof := dpopMakeProof(t, priv, opts)
	// "post" must NOT match "POST" — HTTP methods are case-sensitive
	require.Error(t, ValidateDPoPProof(proof, "POST", dpopTestURL, dpopTestToken, storedJKT))
}

func TestDPoP_WrongHTU_Rejected(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", "https://evil.example.com/steal", dpopTestToken)
	proof := dpopMakeProof(t, priv, opts)
	require.Error(t, ValidateDPoPProof(proof, "GET", dpopTestURL, dpopTestToken, storedJKT))
}

func TestDPoP_HTU_IgnoresQueryString(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", dpopTestURL, dpopTestToken) // htu without query
	proof := dpopMakeProof(t, priv, opts)
	// request URL has query — should still match
	require.NoError(t, ValidateDPoPProof(proof, "GET", dpopTestURL+"?foo=bar", dpopTestToken, storedJKT))
}

// Fix #5: htu matching strips default ports (443/80)
func TestDPoP_HTU_DefaultPortStripped_Matches(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	// proof htu includes explicit :443, request URL omits it — must match
	opts := dpopValidOpts("GET", "https://api.example.com:443/v1/resource", dpopTestToken)
	proof := dpopMakeProof(t, priv, opts)
	require.NoError(t, ValidateDPoPProof(proof, "GET", "https://api.example.com/v1/resource", dpopTestToken, storedJKT))
}

func TestDPoP_HTU_DefaultPortOmitted_Matches(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	// proof htu omits :443, request URL includes it — must match
	opts := dpopValidOpts("GET", "https://api.example.com/v1/resource", dpopTestToken)
	proof := dpopMakeProof(t, priv, opts)
	require.NoError(t, ValidateDPoPProof(proof, "GET", "https://api.example.com:443/v1/resource", dpopTestToken, storedJKT))
}

func TestDPoP_HTU_NonDefaultPort_Rejected(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	// proof htu uses :8443, request URL uses default port — must NOT match
	opts := dpopValidOpts("GET", "https://api.example.com:8443/v1/resource", dpopTestToken)
	proof := dpopMakeProof(t, priv, opts)
	require.Error(t, ValidateDPoPProof(proof, "GET", "https://api.example.com/v1/resource", dpopTestToken, storedJKT))
}

func TestDPoP_ExpiredIAT_Rejected(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", dpopTestURL, dpopTestToken)
	opts.iat = time.Now().Add(-2 * time.Minute)
	proof := dpopMakeProof(t, priv, opts)
	require.Error(t, ValidateDPoPProof(proof, "GET", dpopTestURL, dpopTestToken, storedJKT))
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
	require.Error(t, ValidateDPoPProof(proof, "GET", dpopTestURL, dpopTestToken, storedJKT))
}

func TestDPoP_WrongAth_Rejected(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", dpopTestURL, "wrong-token") // ath for wrong token
	proof := dpopMakeProof(t, priv, opts)
	require.Error(t, ValidateDPoPProof(proof, "GET", dpopTestURL, dpopTestToken, storedJKT))
}

func TestDPoP_MalformedProof_Rejected(t *testing.T) {
	require.Error(t, ValidateDPoPProof("not-a-jwt", "GET", dpopTestURL, dpopTestToken, "some-jkt"))
}

func TestDPoP_WrongTypHeader_Rejected(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", dpopTestURL, dpopTestToken)
	opts.typ = "at+jwt"
	proof := dpopMakeProof(t, priv, opts)
	require.Error(t, ValidateDPoPProof(proof, "GET", dpopTestURL, dpopTestToken, storedJKT))
}

func TestDPoP_MissingJWKHeader_Rejected(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", dpopTestURL, dpopTestToken)
	opts.includeJWK = false
	proof := dpopMakeProof(t, priv, opts)
	require.Error(t, ValidateDPoPProof(proof, "GET", dpopTestURL, dpopTestToken, storedJKT))
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
	err = ValidateDPoPProof(string(signed), "GET", dpopTestURL, dpopTestToken, "any-jkt")
	require.Error(t, err)
}

// "rejected algorithm in DPoP proof" — end-to-end: EdDSA is not in the allow-list.
func TestDPoP_RejectedAlg_EdDSA_EndToEnd_Rejected(t *testing.T) {
	// ed25519.GenerateKey returns (PublicKey, PrivateKey, error)
	edPubRaw, edPrivRaw, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	edPrivJWK, err := jwk.FromRaw(edPrivRaw)
	require.NoError(t, err)
	edPubJWK, err := jwk.FromRaw(edPubRaw)
	require.NoError(t, err)

	tok := jwt.New()
	require.NoError(t, tok.Set("jti", dpopRandomJTI()))
	require.NoError(t, tok.Set("htm", "GET"))
	require.NoError(t, tok.Set("htu", dpopTestURL))
	require.NoError(t, tok.Set(jwt.IssuedAtKey, time.Now()))
	require.NoError(t, tok.Set("ath", dpopAthFor(dpopTestToken)))

	hdrs := jws.NewHeaders()
	require.NoError(t, hdrs.Set(jws.TypeKey, "dpop+jwt"))
	require.NoError(t, hdrs.Set(jws.JWKKey, edPubJWK))

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.EdDSA, edPrivJWK, jws.WithProtectedHeaders(hdrs)))
	require.NoError(t, err)

	err = ValidateDPoPProof(string(signed), "GET", dpopTestURL, dpopTestToken, "any-jkt")
	require.Error(t, err)
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

	err = ValidateDPoPProof(string(signed), "GET", dpopTestURL, dpopTestToken, "any-jkt")
	require.Error(t, err)
}

// "jwk must not contain a private key" — ECDSA private key embedded in JWK header.
func TestDPoP_ECDSAPrivateKeyInJWK_Rejected(t *testing.T) {
	priv, _ := dpopNewKeyPair(t)
	// Embed the private key (not the derived public key) in the JWK header.
	opts := dpopValidOpts("GET", dpopTestURL, dpopTestToken)
	opts.jwkOverride = priv
	proof := dpopMakeProof(t, priv, opts)
	err := ValidateDPoPProof(proof, "GET", dpopTestURL, dpopTestToken, "any-jkt")
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

	require.Error(t, ValidateDPoPProof(tampered, "GET", dpopTestURL, dpopTestToken, storedJKT))
}

func TestDPoP_MissingJTI_Rejected(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", dpopTestURL, dpopTestToken)
	opts.omitJTI = true
	proof := dpopMakeProof(t, priv, opts)
	require.Error(t, ValidateDPoPProof(proof, "GET", dpopTestURL, dpopTestToken, storedJKT))
}

func TestDPoP_EmptyJTI_Rejected(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", dpopTestURL, dpopTestToken)
	opts.emptyJTI = true
	proof := dpopMakeProof(t, priv, opts)
	require.Error(t, ValidateDPoPProof(proof, "GET", dpopTestURL, dpopTestToken, storedJKT))
}

func TestDPoP_MissingHTM_Rejected(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", dpopTestURL, dpopTestToken)
	opts.omitHTM = true
	proof := dpopMakeProof(t, priv, opts)
	require.Error(t, ValidateDPoPProof(proof, "GET", dpopTestURL, dpopTestToken, storedJKT))
}

func TestDPoP_EmptyHTM_Rejected(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", dpopTestURL, dpopTestToken)
	opts.emptyHTM = true
	proof := dpopMakeProof(t, priv, opts)
	require.Error(t, ValidateDPoPProof(proof, "GET", dpopTestURL, dpopTestToken, storedJKT))
}

func TestDPoP_MissingHTU_Rejected(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", dpopTestURL, dpopTestToken)
	opts.omitHTU = true
	proof := dpopMakeProof(t, priv, opts)
	require.Error(t, ValidateDPoPProof(proof, "GET", dpopTestURL, dpopTestToken, storedJKT))
}

func TestDPoP_EmptyHTU_Rejected(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", dpopTestURL, dpopTestToken)
	opts.emptyHTU = true
	proof := dpopMakeProof(t, priv, opts)
	require.Error(t, ValidateDPoPProof(proof, "GET", dpopTestURL, dpopTestToken, storedJKT))
}

func TestDPoP_MissingIAT_Rejected(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", dpopTestURL, dpopTestToken)
	opts.omitIAT = true
	proof := dpopMakeProof(t, priv, opts)
	require.Error(t, ValidateDPoPProof(proof, "GET", dpopTestURL, dpopTestToken, storedJKT))
}

func TestDPoP_EmptyATH_Rejected(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", dpopTestURL, dpopTestToken)
	opts.ath = ""               // clear the valid ath
	opts.includeEmptyATH = true // include ath="" (present but empty)
	proof := dpopMakeProof(t, priv, opts)
	require.Error(t, ValidateDPoPProof(proof, "GET", dpopTestURL, dpopTestToken, storedJKT))
}

func TestDPoP_RejectedAlgs(t *testing.T) {
	// Fix #4: allow-list — only RS*/PS*/ES* are permitted
	assert.False(t, dpopIsAllowedAlg("none"))
	assert.False(t, dpopIsAllowedAlg("HS256"))
	assert.False(t, dpopIsAllowedAlg("HS384"))
	assert.False(t, dpopIsAllowedAlg("HS512"))
	assert.False(t, dpopIsAllowedAlg("EdDSA"))   // not in allow-list
	assert.False(t, dpopIsAllowedAlg("unknown")) // unknown alg rejected by default
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
	err := ValidateDPoPProof(jwsJSON, "GET", dpopTestURL, dpopTestToken, "any-jkt")
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

	err = ValidateDPoPProof(string(signed), "GET", dpopTestURL, dpopTestToken, "any-jkt")
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

	err = ValidateDPoPProof(string(signed), "GET", dpopTestURL, dpopTestToken, "any-jkt")
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

func TestDPoPHtuMatches_InvalidHTU_Rejected(t *testing.T) {
	// Invalid percent-encoding causes url.Parse to return an error
	assert.False(t, dpopHtuMatches("https://api.example.com/%zz/path", "https://api.example.com/path"))
}

func TestDPoPHtuMatches_InvalidRequestURL_Rejected(t *testing.T) {
	// Invalid percent-encoding in requestURL causes url.Parse to return an error
	assert.False(t, dpopHtuMatches("https://api.example.com/path", "https://api.example.com/%zz/path"))
}

// HTTP default port 80 stripping in dpopNormalizeHost.
func TestDPoP_HTU_HTTP_DefaultPort80Stripped_Matches(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	opts := dpopValidOpts("GET", "http://api.example.com:80/v1/resource", dpopTestToken)
	proof := dpopMakeProof(t, priv, opts)
	require.NoError(t, ValidateDPoPProof(proof, "GET", "http://api.example.com/v1/resource", dpopTestToken, storedJKT))
}
