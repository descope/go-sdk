package auth

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/descope/go-sdk/descope"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ─── Test key/token builders ────────────────────────────────────────────────────

const jweTestSub = "jwe-test-user"

// buildSigningKey returns an ES256 signing key (jwk with kid+alg+use) and its public JWK JSON,
// suitable for AuthParams.PublicKey so the inner JWS verifies.
func buildSigningKey(t *testing.T) (priv jwk.Key, publicJWK string) {
	t.Helper()
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	priv, err = jwk.FromRaw(raw)
	require.NoError(t, err)
	require.NoError(t, priv.Set(jwk.KeyIDKey, "sigkey"))
	require.NoError(t, priv.Set(jwk.AlgorithmKey, jwa.ES256))
	require.NoError(t, priv.Set(jwk.KeyUsageKey, jwk.ForSignature))

	pub, err := priv.PublicKey()
	require.NoError(t, err)
	require.NoError(t, pub.Set(jwk.KeyIDKey, "sigkey"))
	require.NoError(t, pub.Set(jwk.AlgorithmKey, jwa.ES256))
	require.NoError(t, pub.Set(jwk.KeyUsageKey, jwk.ForSignature))
	b, err := json.Marshal(pub)
	require.NoError(t, err)
	return priv, string(b)
}

// signInnerJWS builds and signs a minimal DS-shaped session JWS with the signing key.
func signInnerJWS(t *testing.T, signing jwk.Key) string {
	t.Helper()
	tok, err := jwt.NewBuilder().
		Issuer("jwe-test").
		Subject(jweTestSub).
		Audience([]string{"test"}).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Claim("drn", "DS").
		Build()
	require.NoError(t, err)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256, signing))
	require.NoError(t, err)
	return string(signed)
}

// genEncKey generates an encryption keypair for the given key-wrap algorithm. It returns the private
// JWK JSON (for Config.PrivateKey), the public jwk.Key (for wrapping), and the key's thumbprint kid.
func genEncKey(t *testing.T, alg jwa.KeyEncryptionAlgorithm) (privJWK string, pub jwk.Key, kid string) {
	t.Helper()
	var rawPriv any
	switch alg {
	case jwa.RSA_OAEP_256:
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		rawPriv = k
	case jwa.ECDH_ES_A256KW:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		rawPriv = k
	default:
		t.Fatalf("unsupported alg %s", alg)
	}

	priv, err := jwk.FromRaw(rawPriv)
	require.NoError(t, err)
	tp, err := priv.Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	kid = base64.RawURLEncoding.EncodeToString(tp)
	require.NoError(t, priv.Set(jwk.KeyIDKey, kid))

	pub, err = priv.PublicKey()
	require.NoError(t, err)
	require.NoError(t, pub.Set(jwk.KeyIDKey, kid))
	require.NoError(t, pub.Set(jwk.KeyUsageKey, jwk.ForEncryption))

	b, err := json.Marshal(priv)
	require.NoError(t, err)
	return string(b), pub, kid
}

// wrapJWE encrypts the inner JWS to the recipient public key (sign-then-encrypt nested JWT).
func wrapJWE(t *testing.T, innerJWS string, alg jwa.KeyEncryptionAlgorithm, pub jwk.Key) string {
	t.Helper()
	hdrs := jwe.NewHeaders()
	require.NoError(t, hdrs.Set(jwe.ContentTypeKey, "JWT"))
	require.NoError(t, hdrs.Set(jwe.KeyIDKey, pub.KeyID()))
	encrypted, err := jwe.Encrypt([]byte(innerJWS),
		jwe.WithKey(alg, pub),
		jwe.WithContentEncryption(jwa.A256GCM),
		jwe.WithProtectedHeaders(hdrs),
	)
	require.NoError(t, err)
	return string(encrypted)
}

// newJWEAuth builds an auth service whose Provider verifies with publicJWK and decrypts with privateKey.
func newJWEAuth(t *testing.T, publicJWK, privateKey string, provider func(string) (any, error)) *authenticationService {
	t.Helper()
	a, err := newTestAuthConf(&AuthParams{
		ProjectID:          "a",
		PublicKey:          publicJWK,
		PrivateKey:         privateKey,
		PrivateKeyProvider: provider,
	}, nil, DoOk(nil))
	require.NoError(t, err)
	return a
}

// ─── Tests ──────────────────────────────────────────────────────────────────────

func TestValidateJWT_JWE_RSA(t *testing.T) {
	signing, pubJWK := buildSigningKey(t)
	inner := signInnerJWS(t, signing)
	encPriv, encPub, _ := genEncKey(t, jwa.RSA_OAEP_256)
	token := wrapJWE(t, inner, jwa.RSA_OAEP_256, encPub)
	require.Equal(t, 4, countDots(token), "expected a 5-part JWE")

	a := newJWEAuth(t, pubJWK, encPriv, nil)
	parsed, err := ValidateJWT(token, a.publicKeysProvider)
	require.NoError(t, err)
	assert.Equal(t, jweTestSub, parsed.ID)
	assert.Equal(t, "DS", parsed.Claims["drn"], "custom claims must survive decrypt + verify")
}

func TestValidateJWT_JWE_EC(t *testing.T) {
	signing, pubJWK := buildSigningKey(t)
	inner := signInnerJWS(t, signing)
	encPriv, encPub, _ := genEncKey(t, jwa.ECDH_ES_A256KW)
	token := wrapJWE(t, inner, jwa.ECDH_ES_A256KW, encPub)

	a := newJWEAuth(t, pubJWK, encPriv, nil)
	parsed, err := ValidateJWT(token, a.publicKeysProvider)
	require.NoError(t, err)
	assert.Equal(t, jweTestSub, parsed.ID)
}

func TestValidateJWT_JWE_KeySetRotation(t *testing.T) {
	signing, pubJWK := buildSigningKey(t)
	inner := signInnerJWS(t, signing)

	// Two encryption keys; the token is wrapped to the second. A JWK Set must select by kid.
	priv1, _, _ := genEncKey(t, jwa.RSA_OAEP_256)
	priv2, pub2, _ := genEncKey(t, jwa.RSA_OAEP_256)
	token := wrapJWE(t, inner, jwa.RSA_OAEP_256, pub2)

	set := jwk.NewSet()
	for _, raw := range []string{priv1, priv2} {
		k, err := jwk.ParseKey([]byte(raw))
		require.NoError(t, err)
		require.NoError(t, set.AddKey(k))
	}
	setJSON, err := json.Marshal(set)
	require.NoError(t, err)

	a := newJWEAuth(t, pubJWK, string(setJSON), nil)
	parsed, err := ValidateJWT(token, a.publicKeysProvider)
	require.NoError(t, err)
	assert.Equal(t, jweTestSub, parsed.ID)
}

func TestValidateJWT_JWE_PrivateKeyProvider(t *testing.T) {
	signing, pubJWK := buildSigningKey(t)
	inner := signInnerJWS(t, signing)
	encPriv, encPub, wantKid := genEncKey(t, jwa.RSA_OAEP_256)
	token := wrapJWE(t, inner, jwa.RSA_OAEP_256, encPub)

	var gotKid string
	provider := func(kid string) (any, error) {
		gotKid = kid
		k, err := jwk.ParseKey([]byte(encPriv))
		require.NoError(t, err)
		return k, nil
	}

	// No PrivateKey string — only the callback supplies the key.
	a := newJWEAuth(t, pubJWK, "", provider)
	parsed, err := ValidateJWT(token, a.publicKeysProvider)
	require.NoError(t, err)
	assert.Equal(t, jweTestSub, parsed.ID)
	assert.Equal(t, wantKid, gotKid, "provider should be called with the JWE header kid")
}

func TestValidateJWT_PlainJWS_NoRegression(t *testing.T) {
	// A plain 3-part JWS must validate exactly as before, even with a decryption key configured.
	_, encPub, _ := genEncKey(t, jwa.RSA_OAEP_256)
	_ = encPub
	a, err := newTestAuthConf(&AuthParams{ProjectID: "a", PublicKey: publicKey}, nil, DoOk(nil))
	require.NoError(t, err)
	require.Equal(t, 2, countDots(jwtTokenValid), "fixture must be a 3-part JWS")

	parsed, err := ValidateJWT(jwtTokenValid, a.publicKeysProvider)
	require.NoError(t, err)
	assert.Equal(t, "someuser", parsed.ID)
}

func TestValidateJWT_JWE_PreservesEncryptedJWT(t *testing.T) {
	// The returned Token must carry the original *encrypted* JWT, not the decrypted inner JWS —
	// otherwise a SessionJWTViaCookie project would rewrite its browser cookie to plaintext.
	signing, pubJWK := buildSigningKey(t)
	inner := signInnerJWS(t, signing)
	encPriv, encPub, _ := genEncKey(t, jwa.RSA_OAEP_256)
	token := wrapJWE(t, inner, jwa.RSA_OAEP_256, encPub)

	a := newJWEAuth(t, pubJWK, encPriv, nil)
	parsed, err := ValidateJWT(token, a.publicKeysProvider)
	require.NoError(t, err)
	assert.Equal(t, token, parsed.JWT, "returned token must keep the encrypted JWE wire format")
	assert.NotEqual(t, inner, parsed.JWT, "token.JWT must not be the decrypted inner JWS")
	assert.Equal(t, 4, countDots(parsed.JWT), "token.JWT must stay a 5-part JWE")
}

func TestValidateJWT_JWE_DisallowedAlgRejected(t *testing.T) {
	// The key-wrap alg is read from the (attacker-controllable) header; anything other than what
	// Descope issues (e.g. RSA1_5) must be refused, not attempted — otherwise it opens an algorithm
	// downgrade and a Bleichenbacher padding-oracle probe against the recipient key.
	signing, pubJWK := buildSigningKey(t)
	inner := signInnerJWS(t, signing)
	encPriv, encPub, _ := genEncKey(t, jwa.RSA_OAEP_256)
	token := wrapJWE(t, inner, jwa.RSA1_5, encPub)

	a := newJWEAuth(t, pubJWK, encPriv, nil)
	_, err := ValidateJWT(token, a.publicKeysProvider)
	require.Error(t, err)
	assert.True(t, descope.ErrJWEDecrypt.Is(err), "a disallowed key-wrap alg must be refused with ErrJWEDecrypt")
}

func TestValidateJWT_JWE_NoKeyConfigured(t *testing.T) {
	signing, pubJWK := buildSigningKey(t)
	inner := signInnerJWS(t, signing)
	_, encPub, _ := genEncKey(t, jwa.RSA_OAEP_256)
	token := wrapJWE(t, inner, jwa.RSA_OAEP_256, encPub)

	// PublicKey set but no PrivateKey / provider → must fail with ErrJWEDecrypt, not a parse error.
	a, err := newTestAuthConf(&AuthParams{ProjectID: "a", PublicKey: pubJWK}, nil, DoOk(nil))
	require.NoError(t, err)
	_, err = ValidateJWT(token, a.publicKeysProvider)
	require.ErrorIs(t, err, descope.ErrJWEDecrypt)
}

func TestValidateJWT_JWE_WrongKey(t *testing.T) {
	signing, pubJWK := buildSigningKey(t)
	inner := signInnerJWS(t, signing)
	_, encPub, _ := genEncKey(t, jwa.RSA_OAEP_256)
	token := wrapJWE(t, inner, jwa.RSA_OAEP_256, encPub)

	// Configure a *different* private key → decryption must fail.
	otherPriv, _, _ := genEncKey(t, jwa.RSA_OAEP_256)
	a := newJWEAuth(t, pubJWK, otherPriv, nil)
	_, err := ValidateJWT(token, a.publicKeysProvider)
	require.ErrorIs(t, err, descope.ErrJWEDecrypt)
}

func countDots(s string) int {
	n := 0
	for _, c := range s {
		if c == '.' {
			n++
		}
	}
	return n
}
