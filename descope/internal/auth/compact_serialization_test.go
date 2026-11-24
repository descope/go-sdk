package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/require"
)

func compactTestProvider(t *testing.T) (*Provider, jwk.Key) {
	t.Helper()
	pk, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	k, err := jwk.FromRaw(pk)
	require.NoError(t, err)
	require.NoError(t, k.Set(jwk.KeyIDKey, "k1"))
	require.NoError(t, k.Set(jwk.AlgorithmKey, jwa.ES384))
	pub, err := k.PublicKey()
	require.NoError(t, err)
	pubJSON, err := json.Marshal(pub)
	require.NoError(t, err)
	return NewProvider(nil, &AuthParams{PublicKey: string(pubJSON), ProjectID: "P1"}), k
}

func compactTestSign(t *testing.T, k jwk.Key, exp time.Time) string {
	t.Helper()
	tok := jwt.New()
	require.NoError(t, tok.Set("iss", "https://api.descope.com/P1"))
	require.NoError(t, tok.Set("sub", "user1"))
	require.NoError(t, tok.Set("exp", exp))
	c, err := jwt.Sign(tok, jwt.WithKey(jwa.ES384, k))
	require.NoError(t, err)
	return string(c)
}

func jsonSerialized(t *testing.T, compact string, general bool, extra map[string]any) string {
	t.Helper()
	p := strings.Split(compact, ".")
	require.Len(t, p, 3)
	doc := map[string]any{"payload": p[1]}
	if general {
		doc["signatures"] = []map[string]any{{"protected": p[0], "signature": p[2]}}
	} else {
		doc["protected"] = p[0]
		doc["signature"] = p[2]
	}
	for key, v := range extra {
		doc[key] = v
	}
	b, err := json.Marshal(doc)
	require.NoError(t, err)
	return string(b)
}

func TestValidateJWTCompactSerializationOnly(t *testing.T) {
	p, k := compactTestProvider(t)

	valid := compactTestSign(t, k, time.Now().Add(time.Hour))
	tok, err := ValidateJWT(valid, p)
	require.NoError(t, err)
	require.Equal(t, "user1", tok.ID)

	expired := compactTestSign(t, k, time.Now().Add(-time.Hour))
	_, err = ValidateJWT(expired, p)
	require.ErrorContains(t, err, "expired")

	extra := map[string]any{"sub": "other", "exp": time.Now().Add(24 * time.Hour).Unix()}
	cases := map[string]string{
		"flattened":          jsonSerialized(t, valid, false, extra),
		"flattened with aud": jsonSerialized(t, valid, false, map[string]any{"aud": []string{"x"}, "sub": "other"}),
		"general":            jsonSerialized(t, valid, true, extra),
		"expired payload":    jsonSerialized(t, expired, false, extra),
		"no exp":             jsonSerialized(t, expired, false, map[string]any{"sub": "other"}),
		"leading whitespace": " \n" + jsonSerialized(t, valid, false, extra),
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			tok, err := ValidateJWT(in, p)
			require.Error(t, err)
			require.ErrorContains(t, err, "compact serialization")
			require.Nil(t, tok)
		})
	}
}

func TestValidateJWTRejectsJSONSerializationInsideJWE(t *testing.T) {
	key, keyJWK := newTestJWEKey(t, "current", jweKeyBytes)
	a := newTestJWEAuth(t, keyJWK)

	inner := jsonSerialized(t, jwtTokenValid, false, map[string]any{"sub": "other", "exp": time.Now().Add(24 * time.Hour).Unix()})
	encrypted := encryptTestToken(t, inner, key)

	tok, err := ValidateJWT(encrypted, a.publicKeysProvider)
	require.Error(t, err)
	require.ErrorContains(t, err, "Token is not in compact serialization")
	require.Nil(t, tok)

	// sanity: the same key still decrypts a compact token
	_, err = ValidateJWT(encryptTestToken(t, jwtTokenValid, key), a.publicKeysProvider)
	require.NoError(t, err)
}

func TestDPoPRejectsJSONSerializedProof(t *testing.T) {
	priv, pub := dpopNewKeyPair(t)
	storedJKT := dpopJKTOf(t, pub)
	proof := dpopMakeProof(t, priv, dpopValidOpts("POST", dpopTestURL, dpopTestToken))

	forged := map[string]string{
		"flattened, edited htm": jsonSerialized(t, proof, false, map[string]any{"htm": "GET", "htu": dpopTestURL, "ath": dpopAthFor(dpopTestToken), "jti": dpopRandomJTI(), "iat": time.Now().Unix()}),
		"general, edited htm":   jsonSerialized(t, proof, true, map[string]any{"htm": "GET", "htu": dpopTestURL, "ath": dpopAthFor(dpopTestToken), "jti": dpopRandomJTI(), "iat": time.Now().Unix()}),
	}
	for name, in := range forged {
		t.Run(name, func(t *testing.T) {
			err := validateDPoPProof(in, "GET", dpopTestURL, dpopTestToken, storedJKT, time.Now, nil)
			require.Error(t, err)
			require.ErrorContains(t, err, "compact serialization")
		})
	}

	// sanity: the compact proof is still accepted for its own method
	require.NoError(t, validateDPoPProof(proof, "POST", dpopTestURL, dpopTestToken, storedJKT, time.Now, nil))
}
