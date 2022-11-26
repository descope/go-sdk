package auth

import (
	"fmt"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
)

func TestIsStepup(t *testing.T) {
	lo := &LoginOptions{Stepup: true}
	assert.True(t, lo.IsJWTRequired())
	lo = &LoginOptions{Stepup: false}
	assert.False(t, lo.IsJWTRequired())
	lo = nil
	assert.False(t, lo.IsJWTRequired())
}

func TestAuthFactors(t *testing.T) {
	to := &Token{}
	assert.False(t, to.IsMFA())
	to = &Token{Claims: map[string]interface{}{}}
	assert.False(t, to.IsMFA())
	to = &Token{Claims: map[string]interface{}{"amr": []interface{}{string(AuthFactorEmail)}}}
	assert.False(t, to.IsMFA())
	to = &Token{Claims: map[string]interface{}{"amr": []interface{}{string(AuthFactorEmail), string(AuthFactorWebauthn), string(AuthFactorMFA)}}}
	assert.True(t, to.IsMFA())
}

func TestCustomClaims(t *testing.T) {
	to := &Token{Claims: map[string]interface{}{}}
	assert.Nil(t, to.CustomClaim("a"))
	to = &Token{Claims: map[string]interface{}{"a": "b"}}
	assert.EqualValues(t, "b", to.CustomClaim("a"))
	to = &Token{}
	assert.Nil(t, to.CustomClaim("a"))
}

func TestNewToken(t *testing.T) {
	jwtStr := "jwtttt"
	token := jwt.New()

	projectID := "123456"
	issuer := fmt.Sprintf("https://jame.com/%s", projectID)
	subject := "subj"
	expiration := time.Now()

	token.Set(jwt.IssuerKey, issuer)
	token.Set(jwt.SubjectKey, subject)
	token.Set(jwt.ExpirationKey, expiration)

	resToken := NewToken(jwtStr, token)

	assert.EqualValues(t, jwtStr, resToken.JWT)
	assert.EqualValues(t, subject, resToken.ID)
	assert.EqualValues(t, projectID, resToken.ProjectID)
	assert.EqualValues(t, 0, resToken.RefreshExpiration)
	assert.EqualValues(t, expiration.Unix(), resToken.Expiration)
}

func TestNewTokenWithProjectID(t *testing.T) {
	jwtStr := "jwtttt"
	token := jwt.New()

	projectID := "123456"
	issuer := projectID
	subject := "subj"
	expiration := time.Now()

	token.Set(jwt.IssuerKey, issuer)
	token.Set(jwt.SubjectKey, subject)
	token.Set(jwt.ExpirationKey, expiration)

	resToken := NewToken(jwtStr, token)

	assert.EqualValues(t, jwtStr, resToken.JWT)
	assert.EqualValues(t, subject, resToken.ID)
	assert.EqualValues(t, projectID, resToken.ProjectID)
	assert.EqualValues(t, 0, resToken.RefreshExpiration)
	assert.EqualValues(t, expiration.Unix(), resToken.Expiration)
}
