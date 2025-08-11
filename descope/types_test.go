package descope

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

	_ = token.Set(jwt.IssuerKey, issuer)
	_ = token.Set(jwt.SubjectKey, subject)
	_ = token.Set(jwt.ExpirationKey, expiration)

	resToken := NewToken(jwtStr, token)

	assert.EqualValues(t, jwtStr, resToken.JWT)
	assert.EqualValues(t, subject, resToken.ID)
	assert.EqualValues(t, projectID, resToken.ProjectID)
	assert.EqualValues(t, 0, resToken.RefreshExpiration)
	assert.EqualValues(t, expiration.Unix(), resToken.Expiration)
}

func TestNewTokenCustomSubject(t *testing.T) {
	jwtStr := "jwtttt"
	token := jwt.New()

	projectID := "123456"
	issuer := fmt.Sprintf("https://jame.com/%s", projectID)
	subject := "subj"
	expiration := time.Now()

	_ = token.Set(jwt.IssuerKey, issuer)
	_ = token.Set(jwt.SubjectKey, subject+"none")
	_ = token.Set(jwt.ExpirationKey, expiration)
	_ = token.Set("dsub", subject)

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

	_ = token.Set(jwt.IssuerKey, issuer)
	_ = token.Set(jwt.SubjectKey, subject)
	_ = token.Set(jwt.ExpirationKey, expiration)

	resToken := NewToken(jwtStr, token)

	assert.EqualValues(t, jwtStr, resToken.JWT)
	assert.EqualValues(t, subject, resToken.ID)
	assert.EqualValues(t, projectID, resToken.ProjectID)
	assert.EqualValues(t, 0, resToken.RefreshExpiration)
	assert.EqualValues(t, expiration.Unix(), resToken.Expiration)
}

func TestGetCreatedTime(t *testing.T) {
	now := time.Now()
	ct := now.Unix()
	now = time.Unix(ct, 0)
	u := UserResponse{CreatedTime: int32(ct)} // nolint:gosec
	assert.True(t, u.GetCreatedTime().Equal(now))
	r := Role{CreatedTime: int32(ct)} // nolint:gosec
	assert.True(t, r.GetCreatedTime().Equal(now))

	c := ThirdPartyApplicationConsent{CreatedTime: int32(ct)} // nolint:gosec
	assert.True(t, c.GetCreatedTime().Equal(now))
}

func TestIsPermittedPerTenantFromTenantsClaim(t *testing.T) {
	tenantID := "somestring"
	dt := &Token{
		Claims: map[string]any{
			ClaimAuthorizedTenants: map[string]any{
				tenantID: map[string]any{
					ClaimAuthorizedGlobalPermissions: []any{"a", "b", "c"},
				},
			},
		},
	}
	p := dt.IsPermittedPerTenant(tenantID, "a")
	assert.True(t, p)
	p = dt.IsPermittedPerTenant(tenantID+"a", "a")
	assert.False(t, p)
	p = dt.IsPermittedPerTenant(tenantID, "d")
	assert.False(t, p)
}

func TestIsPermittedPerTenantWithCurrentTenant(t *testing.T) {
	tenantID := "t1"
	dt := &Token{
		Claims: map[string]any{
			ClaimDescopeCurrentTenant:        tenantID,
			ClaimAuthorizedGlobalPermissions: []any{"a", "b", "c"},
		},
	}
	p := dt.IsPermittedPerTenant(tenantID, "a")
	assert.True(t, p)
	p = dt.IsPermittedPerTenant(tenantID, "d")
	assert.False(t, p)
}

func TestIsPermitted(t *testing.T) {
	dt := &Token{
		Claims: map[string]any{
			ClaimAuthorizedGlobalPermissions: []any{"a", "b", "c"},
		},
	}
	p := dt.IsPermitted("a")
	assert.True(t, p)
	p = dt.IsPermitted("d")
	assert.False(t, p)
}
