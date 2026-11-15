package auth

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestJWEKey(t *testing.T, kid string, size int) (jwk.Key, string) {
	raw := make([]byte, size)
	_, err := rand.Read(raw)
	require.NoError(t, err)
	key, err := jwk.FromRaw(raw)
	require.NoError(t, err)
	if kid != "" {
		require.NoError(t, key.Set(jwk.KeyIDKey, kid))
	}
	b, err := utils.Marshal(key)
	require.NoError(t, err)
	return key, string(b)
}

// encryptTestToken wraps a signed JWT the way Descope does: A256KW, A256GCM, cty JWT, iss and the key's kid
func encryptTestToken(t *testing.T, signed string, key jwk.Key, options ...jwe.EncryptOption) string {
	headers := jwe.NewHeaders()
	require.NoError(t, headers.Set(jwe.KeyIDKey, key.KeyID()))
	require.NoError(t, headers.Set(jwe.ContentTypeKey, "JWT"))
	require.NoError(t, headers.Set("iss", "https://api.descope.com/a"))
	options = append([]jwe.EncryptOption{jwe.WithKey(jwa.A256KW, key), jwe.WithContentEncryption(jwa.A256GCM), jwe.WithProtectedHeaders(headers)}, options...)
	encrypted, err := jwe.Encrypt([]byte(signed), options...)
	require.NoError(t, err)
	return string(encrypted)
}

func newTestJWEAuth(t *testing.T, keys ...string) *authenticationService {
	a, err := newTestAuthConf(&AuthParams{ProjectID: "a", PublicKey: publicKey, JWTEncryptionKeys: keys}, nil, DoOk(nil))
	require.NoError(t, err)
	return a
}

func TestValidateJWTDecryptsEncryptedToken(t *testing.T) {
	current, currentJWK := newTestJWEKey(t, "current", jweKeyBytes)
	previous, previousJWK := newTestJWEKey(t, "previous", jweKeyBytes)
	a := newTestJWEAuth(t, currentJWK, previousJWK)
	plain, err := ValidateJWT(jwtTokenValid, a.publicKeysProvider)
	require.NoError(t, err)

	for name, key := range map[string]jwk.Key{"current": current, "previous": previous} {
		encrypted := encryptTestToken(t, jwtTokenValid, key)
		token, err := ValidateJWT(encrypted, a.publicKeysProvider)
		require.NoError(t, err, name)
		assert.Equal(t, encrypted, token.JWT, "%s: the token keeps its encrypted form for the caller", name)
		assert.Equal(t, plain.ID, token.ID, "%s: the claims come from the signed JWT inside", name)
	}
}

func TestValidateJWTDecryptsWithKeySet(t *testing.T) {
	current, currentJWK := newTestJWEKey(t, "current", jweKeyBytes)
	previous, previousJWK := newTestJWEKey(t, "previous", jweKeyBytes)
	a := newTestJWEAuth(t, `{"keys":[`+currentJWK+`,`+previousJWK+`]}`)
	for name, key := range map[string]jwk.Key{"current": current, "previous": previous} {
		_, err := ValidateJWT(encryptTestToken(t, jwtTokenValid, key), a.publicKeysProvider)
		require.NoError(t, err, name)
	}
}

func TestValidateSessionWithEncryptedToken(t *testing.T) {
	key, keyJWK := newTestJWEKey(t, "current", jweKeyBytes)
	a := newTestJWEAuth(t, keyJWK)
	ok, token, err := a.ValidateSessionWithToken(context.Background(), encryptTestToken(t, jwtTokenValid, key))
	require.NoError(t, err)
	assert.True(t, ok)
	assert.NotNil(t, token)
}

func TestValidateJWTRejectsUndecryptableTokens(t *testing.T) {
	key, keyJWK := newTestJWEKey(t, "current", jweKeyBytes)
	unknown, _ := newTestJWEKey(t, "unknown", jweKeyBytes)
	sameKidOtherKey, _ := newTestJWEKey(t, "current", jweKeyBytes)
	encrypted := encryptTestToken(t, jwtTokenValid, key)

	tests := map[string]struct {
		keys  []string
		token string
	}{
		"no keys configured":       {token: encrypted},
		"unknown kid":              {keys: []string{keyJWK}, token: encryptTestToken(t, jwtTokenValid, unknown)},
		"wrong key for kid":        {keys: []string{keyJWK}, token: encryptTestToken(t, jwtTokenValid, sameKidOtherKey)},
		"malformed":                {keys: []string{keyJWK}, token: "a.b.c.d.e"},
		"other content encryption": {keys: []string{keyJWK}, token: encryptTestToken(t, jwtTokenValid, key, jwe.WithContentEncryption(jwa.A128CBC_HS256))},
		"compressed":               {keys: []string{keyJWK}, token: encryptTestToken(t, jwtTokenValid, key, jwe.WithCompress(jwa.Deflate))},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			a := newTestJWEAuth(t, tc.keys...)
			token, err := ValidateJWT(tc.token, a.publicKeysProvider)
			require.ErrorIs(t, err, descope.ErrInvalidToken)
			assert.Nil(t, token)
		})
	}
}

func TestJWTEncryptionKeysAreValidatedAtStartup(t *testing.T) {
	_, shortKey := newTestJWEKey(t, "short", 16)
	_, noKid := newTestJWEKey(t, "", jweKeyBytes)
	_, dup := newTestJWEKey(t, "dup", jweKeyBytes)
	_, sameKidOtherKey := newTestJWEKey(t, "dup", jweKeyBytes)
	for name, key := range map[string]string{
		"not a JWK":      "not-a-jwk",
		"not symmetric":  publicKey,
		"not 256 bits":   shortKey,
		"no kid":         noKid,
		"empty key set":  `{"keys":[]}`,
		"bad key in set": `{"keys":[` + noKid + `]}`,
		"duplicate kid":  `{"keys":[` + dup + `,` + sameKidOtherKey + `]}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := newTestAuthConf(&AuthParams{ProjectID: "a", PublicKey: publicKey, JWTEncryptionKeys: []string{key}}, nil, DoOk(nil))
			require.ErrorIs(t, err, descope.ErrInvalidArguments)
		})
	}
	t.Run("duplicate kid across entries", func(t *testing.T) {
		_, err := newTestAuthConf(&AuthParams{ProjectID: "a", PublicKey: publicKey, JWTEncryptionKeys: []string{dup, sameKidOtherKey}}, nil, DoOk(nil))
		require.ErrorIs(t, err, descope.ErrInvalidArguments)
	})
}
