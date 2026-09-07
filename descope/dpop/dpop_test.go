package dpop

import (
	"crypto"
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

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parseProof verifies the proof against its own embedded key, the way a server does, and
// returns the protected headers and claims.
func parseProof(t *testing.T, proof string) (jws.Headers, jwt.Token) {
	t.Helper()
	msg, err := jws.Parse([]byte(proof))
	require.NoError(t, err)
	require.Len(t, msg.Signatures(), 1)
	headers := msg.Signatures()[0].ProtectedHeaders()

	embedded := headers.JWK()
	require.NotNil(t, embedded, "proof must embed the public key")
	_, err = jws.Verify([]byte(proof), jws.WithKey(headers.Algorithm(), embedded))
	require.NoError(t, err, "proof signature must verify against the embedded key")

	token, err := jwt.Parse([]byte(proof), jwt.WithVerify(false), jwt.WithValidate(false))
	require.NoError(t, err)
	return headers, token
}

func claim(t *testing.T, token jwt.Token, name string) string {
	t.Helper()
	raw, ok := token.Get(name)
	require.True(t, ok, "claim %s must be present", name)
	value, ok := raw.(string)
	require.True(t, ok, "claim %s must be a string", name)
	return value
}

func TestProofClaimsAndHeaders(t *testing.T) {
	key, err := NewKey()
	require.NoError(t, err)
	assert.Equal(t, "ES256", key.Algorithm())

	accessToken := "some.access.token"
	proof, err := key.Proof(http.MethodPost, "https://api.descope.com/oauth2/v1/apps/token?x=1#frag",
		WithAccessToken(accessToken), WithNonce("nonce-value"))
	require.NoError(t, err)

	headers, token := parseProof(t, proof)
	assert.Equal(t, "dpop+jwt", headers.Type())
	assert.Equal(t, "ES256", headers.Algorithm().String())

	// The embedded key must be public only, and its thumbprint is the dpop_jkt value.
	_, isPrivate := headers.JWK().(jwk.ECDSAPrivateKey)
	assert.False(t, isPrivate, "proof must not embed the private key")

	assert.Equal(t, http.MethodPost, claim(t, token, "htm"))
	assert.Equal(t, "https://api.descope.com/oauth2/v1/apps/token", claim(t, token, "htu"), "query and fragment are excluded from htu")
	assert.Equal(t, "nonce-value", claim(t, token, "nonce"))
	assert.NotEmpty(t, claim(t, token, "jti"))
	assert.False(t, token.IssuedAt().IsZero(), "iat is required")

	hash := sha256.Sum256([]byte(accessToken))
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(hash[:]), claim(t, token, "ath"))
}

func TestProofIsSingleUse(t *testing.T) {
	key, err := NewKey()
	require.NoError(t, err)

	first, err := key.Proof(http.MethodGet, "https://api.descope.com/oauth2/v1/apps/userinfo")
	require.NoError(t, err)
	second, err := key.Proof(http.MethodGet, "https://api.descope.com/oauth2/v1/apps/userinfo")
	require.NoError(t, err)

	_, firstToken := parseProof(t, first)
	_, secondToken := parseProof(t, second)
	assert.NotEqual(t, claim(t, firstToken, "jti"), claim(t, secondToken, "jti"), "each proof needs a fresh jti")
}

func TestProofOmitsAthAndNonceWhenUnset(t *testing.T) {
	key, err := NewKey()
	require.NoError(t, err)
	proof, err := key.Proof(http.MethodPost, "https://api.descope.com/oauth2/v1/apps/token")
	require.NoError(t, err)

	_, token := parseProof(t, proof)
	_, hasATH := token.Get("ath")
	assert.False(t, hasATH)
	_, hasNonce := token.Get("nonce")
	assert.False(t, hasNonce)
}

func TestProofRejectsRelativeURL(t *testing.T) {
	key, err := NewKey()
	require.NoError(t, err)
	_, err = key.Proof(http.MethodGet, "/oauth2/v1/apps/token")
	require.ErrorContains(t, err, "must be absolute")
}

func TestKeySurvivesSerialization(t *testing.T) {
	key, err := NewKey()
	require.NoError(t, err)

	serialized, err := json.Marshal(key)
	require.NoError(t, err)
	restored, err := ParseKey(serialized)
	require.NoError(t, err)

	// Same key means the same cnf.jkt, so tokens bound before a restart stay usable.
	assert.Equal(t, key.Thumbprint(), restored.Thumbprint())
	proof, err := restored.Proof(http.MethodPost, "https://api.descope.com/oauth2/v1/apps/token")
	require.NoError(t, err)
	parseProof(t, proof)
}

func TestThumbprintMatchesEmbeddedKey(t *testing.T) {
	key, err := NewKey()
	require.NoError(t, err)
	proof, err := key.Proof(http.MethodPost, "https://api.descope.com/oauth2/v1/apps/token")
	require.NoError(t, err)

	headers, _ := parseProof(t, proof)
	thumbprint, err := headers.JWK().Thumbprint(crypto.SHA256)
	require.NoError(t, err)
	assert.Equal(t, key.Thumbprint(), base64.RawURLEncoding.EncodeToString(thumbprint))
}

// TestTransportNonceHandshake exercises the handshake Descope's token endpoint always
// forces: reject the first proof with 400 use_dpop_nonce, then accept the retry.
func TestTransportNonceHandshake(t *testing.T) {
	type attempt struct {
		nonce string
		body  string
		auth  string
		ath   string
	}
	var attempts []attempt
	var issued int

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		_, token := parseProof(t, r.Header.Get(HeaderProof))
		nonce, _ := token.Get("nonce")
		ath, _ := token.Get("ath")
		assert.Equal(t, r.Method, claim(t, token, "htm"))
		attempts = append(attempts, attempt{
			nonce: fmt.Sprint(nonce),
			body:  string(body),
			auth:  r.Header.Get("Authorization"),
			ath:   fmt.Sprint(ath),
		})

		// Descope always requires a nonce, and rotates it on every response.
		issued++
		w.Header().Set(HeaderNonce, "nonce-"+fmt.Sprint(issued))
		if nonce == nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"use_dpop_nonce","error_description":"nonce required"}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"at","token_type":"DPoP"}`))
	}))
	defer server.Close()

	key, err := NewKey()
	require.NoError(t, err)
	client := &http.Client{Transport: &Transport{Key: key}}

	req, err := http.NewRequest(http.MethodPost, server.URL+"/oauth2/v1/apps/token", strings.NewReader("grant_type=client_credentials"))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer existing-token")

	res, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	assert.Equal(t, http.StatusOK, res.StatusCode, "the retry must succeed")

	require.Len(t, attempts, 2, "exactly one retry")
	assert.Equal(t, "<nil>", attempts[0].nonce, "the first proof cannot know the nonce")
	assert.Equal(t, "nonce-1", attempts[1].nonce, "the retry carries the server nonce")
	assert.Equal(t, "grant_type=client_credentials", attempts[1].body, "the body is replayed")

	// Bearer is rewritten to the DPoP scheme and bound with ath.
	assert.Equal(t, "DPoP existing-token", attempts[1].auth)
	hash := sha256.Sum256([]byte("existing-token"))
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(hash[:]), attempts[1].ath)

	// The rotated nonce is reused, so a following request needs no retry.
	attempts = nil
	res2, err := client.Get(server.URL + "/oauth2/v1/apps/userinfo")
	require.NoError(t, err)
	defer func() { _ = res2.Body.Close() }()
	require.Len(t, attempts, 1, "the cached nonce avoids a second handshake")
	assert.Equal(t, "nonce-2", attempts[0].nonce)
}

func TestTransportReturnsNonNonceErrorsUntouched(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set(HeaderNonce, "fresh-nonce")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
	}))
	defer server.Close()

	key, err := NewKey()
	require.NoError(t, err)
	client := &http.Client{Transport: &Transport{Key: key}}

	res, err := client.Post(server.URL+"/oauth2/v1/apps/token", "application/x-www-form-urlencoded", strings.NewReader("grant_type=client_credentials"))
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()

	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	assert.Equal(t, 1, calls, "a non-nonce error must not be retried")
	assert.JSONEq(t, `{"error":"invalid_client"}`, string(body), "the body stays readable")
}

func TestTransportRequiresKey(t *testing.T) {
	_, err := (&Transport{}).RoundTrip(httptest.NewRequest(http.MethodGet, "https://api.descope.com/", nil))
	require.ErrorContains(t, err, "Key is nil")
}

func TestKeyAlgorithmPerKeyType(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	_, ed25519Priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)

	// RSA gets PS256, never RS256: FAPI 2.0 rejects RSASSA-PKCS1-v1_5 proofs.
	for _, tc := range []struct {
		name string
		raw  any
		alg  string
	}{
		{"rsa", rsaKey, "PS256"},
		{"ed25519", ed25519Priv, "EdDSA"},
		{"p384", p384, "ES384"},
		{"p521", p521, "ES512"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key, err := NewKeyFromRaw(tc.raw)
			require.NoError(t, err)
			assert.Equal(t, tc.alg, key.Algorithm())

			proof, err := key.Proof(http.MethodPost, "https://api.descope.com/oauth2/v1/apps/token")
			require.NoError(t, err)
			headers, _ := parseProof(t, proof)
			assert.Equal(t, tc.alg, headers.Algorithm().String())
		})
	}
}

func TestKeyHonorsExplicitAlgorithm(t *testing.T) {
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jwkKey, err := jwk.FromRaw(raw)
	require.NoError(t, err)
	require.NoError(t, jwkKey.Set(jwk.AlgorithmKey, jwa.ES256))

	serialized, err := json.Marshal(jwkKey)
	require.NoError(t, err)
	key, err := ParseKey(serialized)
	require.NoError(t, err)
	assert.Equal(t, "ES256", key.Algorithm())
}

func TestKeyRejectsUnusableKeys(t *testing.T) {
	publicOnly, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_, err = NewKeyFromRaw(publicOnly.Public())
	require.ErrorContains(t, err, "must be a private key")

	// A symmetric key cannot prove possession: the server would need the secret to verify.
	_, err = NewKeyFromRaw([]byte("not-an-asymmetric-key"))
	require.ErrorContains(t, err, "unsupported DPoP key type")

	_, err = ParseKey([]byte("not a jwk"))
	require.ErrorContains(t, err, "parse DPoP key")
}

// TestTransportRetriesResourceServerChallenge covers the resource-server shape of the
// challenge: 401 with a WWW-Authenticate: DPoP header instead of a JSON body.
func TestTransportRetriesResourceServerChallenge(t *testing.T) {
	var nonces []any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, token := parseProof(t, r.Header.Get(HeaderProof))
		nonce, _ := token.Get("nonce")
		nonces = append(nonces, nonce)
		if len(nonces) == 1 {
			w.Header().Set(HeaderNonce, "rs-nonce")
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce", error_description="nonce required"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"sub":"U1"}`))
	}))
	defer server.Close()

	key, err := NewKey()
	require.NoError(t, err)
	client := &http.Client{Transport: &Transport{Key: key}}

	res, err := client.Get(server.URL + "/oauth2/v1/apps/userinfo")
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	assert.Equal(t, http.StatusOK, res.StatusCode)
	require.Len(t, nonces, 2)
	assert.Equal(t, "rs-nonce", nonces[1])
}

// A server that issues no nonce still gets a proof, and nothing is cached for it.
func TestTransportWithoutNonceHeader(t *testing.T) {
	var proofs int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(HeaderProof) != "" {
			proofs++
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	key, err := NewKey()
	require.NoError(t, err)
	transport := &Transport{Key: key}

	res, err := (&http.Client{Transport: transport}).Get(server.URL + "/resource")
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	assert.Equal(t, http.StatusForbidden, res.StatusCode)
	assert.Equal(t, 1, proofs, "no nonce means no retry")
	assert.Empty(t, transport.nonce(res.Request.URL.Host))
}
