package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/sdk"
	"github.com/descope/go-sdk/descope/tests/helpers"
	"github.com/descope/go-sdk/descope/tests/mocks"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	jwtTokenValid    = `eyJhbGciOiJFUzM4NCIsImtpZCI6InRlc3RrZXkiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOlsidGVzdCJdLCJkcm4iOiJEUyIsImV4cCI6MzY1OTU2MTQzMCwiaWF0IjoxNjU5NTYxNDMwLCJpc3MiOiJ0ZXN0Iiwic3ViIjoic29tZXVzZXIiLCJ0ZXN0IjoidGVzdCJ9.tE6hXIuH74drymm6DSAs4FkaQSzf3MQ0D7pjC-9SaBRnqHoRuDOIJd3mIRsxzfb2nS6NX_tk6H1na6kFEKsJdMsUG-LbCqqib98z9tHtq-Jh6Axl5Qe9RITfIOwzOssw`                                                                                                                                                                                                                                                                                                                                      // nolint:gosec
	jwtRTokenValid   = `eyJhbGciOiJFUzM4NCIsImtpZCI6InRlc3RrZXkiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOlsidGVzdCJdLCJkcm4iOiJEU1IiLCJleHAiOjM2NTk1NjE0MzAsImlhdCI6MTY1OTU2MTQzMCwiaXNzIjoidGVzdCIsInN1YiI6InNvbWV1c2VyIiwidGVzdCI6InRlc3QifQ.zKbJKuGo9Q9NsvI_SdrH1pDH8uuTRnTcT4eMJe237Lr6ZrtRGbw2a0U0aEwgNrox2RXupkmD3vfQtZiD3AiU9xHY8X3xwTGsDwA497eT6RrA13zNufrhSMNjF6V5-xVl`                                                                                                                                                                                                                                                                                                                                    // nolint:gosec
	jwtTokenExpired  = `eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCIsImtpZCI6ImU0YTU3Y2M5ZGZiNDAyYTNlNTNjNDJhNjQyMmY3M2FmIn0.eyJjb29raWVOYW1lIjoiRFMiLCJleHAiOjEyNTYyNTg2OTF9.AvU50pkQt8F000JqpVy7vCbcV-pwGqyi_GENqmmqrRMVswk5Y5VfSjP7axBnZ55xJ85sP6ozawbs_g1FdGtzvgrHEIJVRJSe73EwWTV9yZwiUD8kU-QAtUqP_Vk-rf-3zzE1lmI3DubXZYGTE4tMUsIQ-2NI3-Q9R89yzjLMv9z7_0TaDB28LMCJPlmjTA-7x_FoWqxmCs0z00dZ6sthtppbo25DiO3EW7D35gE1CPOgITjktWSRt035TR0iV91YoPyPAkmEo3mxI4XXu-1fLcZdFFTZOOU4TmA-_wbXevf0kIaQ9Kl4jPEK9lSUHEhLG59nu_0aPVxUXqE-Y8Qo7Ed-Gri5fPhZarDtMRRpVc1pc7D8zYMyKEHvCqkdjV9MDfIK3eCVuCGUxytgEe4Px-sgPSS_7Ne8hZ1T7K3TbcoMlRl--fI6rbmcOj-2srCcofr9NX2pxeUdWU8g6ZfFFxADSfJNb0MbZz55QGN8yz-54jZR3nT7i7kXX0ylrDQw` // nolint:gosec
	jwtTokenNotYet   = `eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCIsImtpZCI6ImU0YTU3Y2M5ZGZiNDAyYTNlNTNjNDJhNjQyMmY3M2FmIn0.eyJjb29raWVOYW1lIjoiRFMiLCJuYmYiOjI2NTYyNTg2OTF9.dvkNfmyUgbhlwv2eW_qC8VfcKYaMKaS8aDM2XdgYxnLuOhQUNnlY87H8bQGw7RChvqyJtciFo74KFhTZkAWqKDpdisIPDnydJ7SzY-NOv6Mtg0DAl99nDuItsYDoSIHVV_3h6feZC353ziQIEoktPf9dnyYpN0IumGMg-g5ww7foDglpwbIP9c6SxxDIOIMh5fGlT7tG79-i_QJ3zsDuYo0v8aNFd7QcP5tA8Kj9Tthp2pHTacu0WDSq39p6XEvDaKiLRhhVOfyd_jTTC2xzmkXRzt2KOy1ObRvhOiItQCoISn66QO4dm8febSagA2_GtDd1VYxwT0zW7usK4CwKfoSej_UMp-BZZ8Q1fDqMWfG9qWjeinfty7ePQwV2Y_kiNCjyTvKlbPnTINL_VXemb0pIaAITfROlzWtXGGnP3soFczgWe4WXC_Q7wx3uCkyN5BIKLajxCF3EAfPzDi7YbYnQXEk-imGoqWpYXw0SXMkYo2wkd9Qul4uXH_mGh50l` // nolint:gosec
	unknownPublicKey = `{
		"crv": "P-384",
		"key_ops": [
		  "verify"
		],
		"kty": "EC",
		"x": "Zd7Unk3ijm3MKXt9vbHR02Y1zX-cpXu6H1_wXRtMl3e39TqeOJ3XnJCxSfE5vjMX",
		"y": "Cv8AgXWpMkMFWvLGhJ_Gsb8LmapAtEurnBsFI4CAG42yUGDfkZ_xjFXPbYssJl7U",
		"alg": "ES384",
		"use": "sig",
		"kid": "32b3da5277b142c7e24fdf0ef09e0919"
	  }`
	publicKey = `{"alg":"ES384","crv":"P-384","kid":"testkey","kty":"EC","use":"sig","x":"fcK-QcFhZooWoMPU2qIfkwBXfLIKkGm2plbS35jEQ53JqgnCaHDzLpyGaWWaIKfg","y":"IJS9pIQl3ZHh3GXi166DZgDieWGEypG9zaE3mEQrjgU-9F4qJWYDo4Fk0XS-ZJXr"}`

	jwtTokenWithTenants  = "eyJhbGciOiJFUzM4NCIsImtpZCI6InRlc3RrZXkiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOlsidGVzdCJdLCJkcm4iOiJEUyIsImV4cCI6MzY2MDIyMzc1OSwiaWF0IjoxNjYwMjIzNzU5LCJpc3MiOiJ0ZXN0Iiwic3ViIjoic29tZXVzZXIiLCJ0ZW5hbnRzIjp7InQxIjp7fSwidDIiOnt9fX0.sIa7U18_h772xYpyFCjOXtsBtMtwWBoFNmDA-Bc-hmWciQC_5-sndtwLdaJD77t2wkoq3wAbjp6jcL1-qBSNZ6pueMdO02IbGK-mkmC439UhdQ7xs7jQXziHstMBaHT5" // nolint:gosec
	publicKeyWithTenants = `{"alg":"ES384","crv":"P-384","kid":"testkey","kty":"EC","use":"sig","x":"Ov545bC4GMh_YPMF_rHzpi2iuLk4wmQsSN_HiCS_-e1TOp2zrPPOVzjIaGWk-S4u","y":"uzQM6ROnewL6UhYkV7FNH-0sXRj3QqoaKsQmclzJSad8oYw9Q7czRDfGa0dWo7r6"}`
)

var (
	mockAuthSessionCookie        = &http.Cookie{Value: jwtTokenValid, Name: descope.SessionCookieName}
	mockAuthRefreshCookie        = &http.Cookie{Value: jwtTokenValid, Name: descope.RefreshCookieName}
	mockAuthInvalidSessionCookie = &http.Cookie{Value: jwtTokenExpired, Name: descope.SessionCookieName}
	mockAuthInvalidRefreshCookie = &http.Cookie{Value: jwtTokenExpired, Name: descope.RefreshCookieName}

	mockAuthSessionBody             = fmt.Sprintf(`{"sessionJwt": "%s", "refreshJwt": "%s", "cookiePath": "%s", "cookieDomain": "%s" }`, jwtTokenValid, jwtRTokenValid, "/my-path", "my-domain")
	mockAuthSessionBodyNoRefreshJwt = fmt.Sprintf(`{"sessionJwt": "%s", "cookiePath": "%s", "cookieDomain": "%s" }`, jwtTokenValid, "/my-path", "my-domain")

	mockUserResponseBody        = fmt.Sprintf(`{"name": "%s", "email": "%s", "userId": "%s", "picture": "%s"}`, "kuku name", "kuku@test.com", "kuku", "@(^_^)@")
	mockUserHistoryResponseBody = fmt.Sprintf(`[
		{"city": "%s", "country": "%s", "userId": "%s", "ip": "%s", "loginTime": %d},
		{"city": "%s", "country": "%s", "userId": "%s", "ip": "%s", "loginTime": %d}
	]`,
		"kefar saba", "Israel", "kuku", "1.1.1.1", 32,
		"eilat", "Israele", "nunu", "1.1.1.2", 23)

	permissions            = []any{"foo", "bar"}
	roles                  = []any{"abc", "xyz"}
	mockAuthorizationToken = &descope.Token{
		Claims: map[string]any{
			claimPermissions: permissions,
			claimRoles:       roles,
		},
	}
	mockAuthorizationTenantToken = &descope.Token{
		Claims: map[string]any{
			descope.ClaimAuthorizedTenants: map[string]any{
				"kuku": mockAuthorizationToken.Claims,
				"t1":   map[string]any{},
			},
		},
	}
	mockAuthorizationCurrentTenantTokenNoTenants = &descope.Token{
		Claims: map[string]any{
			claimPermissions:                  permissions,
			claimRoles:                        roles,
			descope.ClaimDescopeCurrentTenant: "t1",
		},
	}
	mockAuthorizationCurrentTenantTokenWithTenants = &descope.Token{
		Claims: map[string]any{
			claimPermissions: permissions,
			claimRoles:       roles,
			descope.ClaimAuthorizedTenants: map[string]any{
				"t1": map[string]any{
					claimPermissions: []any{"t1-perm1", "t1-perm2"},
					claimRoles:       []any{"t1-role1", "t1-role2"},
				},
				"t2": map[string]any{},
			},
		},
	}
)

func readBodyMap(r *http.Request) (m map[string]any, err error) {
	m = map[string]any{}
	err = readBody(r, &m)
	return m, err
}

func readBody(r *http.Request, m any) (err error) {
	reader, err := r.GetBody()
	if err != nil {
		return err
	}
	res, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	err = json.Unmarshal(res, &m)
	return
}

func DoOk(checks func(*http.Request)) mocks.Do {
	return func(r *http.Request) (*http.Response, error) {
		if checks != nil {
			checks(r)
		}
		res := &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(mockAuthSessionBody))}
		return res, nil
	}
}

func DoBadRequest(checks func(*http.Request)) mocks.Do {
	return func(r *http.Request) (*http.Response, error) {
		if checks != nil {
			checks(r)
		}
		b, err := utils.Marshal(map[string]any{"errorCode": "E011001", "errorDescription": "Request is malformed"})
		if err != nil {
			return nil, err
		}
		res := &http.Response{StatusCode: http.StatusBadRequest, Body: io.NopCloser(bytes.NewBuffer(b))}
		return res, nil
	}
}

func DoWithBody(statusCode int, checks func(*http.Request), body any) mocks.Do {
	return func(r *http.Request) (*http.Response, error) {
		if checks != nil {
			checks(r)
		}

		b, err := utils.Marshal(body)
		if err != nil {
			return nil, err
		}
		res := &http.Response{StatusCode: statusCode, Body: io.NopCloser(bytes.NewBuffer(b))}
		return res, nil
	}
}

func DoOkWithBody(checks func(*http.Request), body any) mocks.Do {
	return DoWithBody(http.StatusOK, checks, body)
}

func DoRedirect(url string, checks func(*http.Request)) mocks.Do {
	return DoOkWithBody(checks, map[string]any{"url": url})
}

func newTestAuth(clientParams *api.ClientParams, callback mocks.Do) (*authenticationService, error) {
	return newTestAuthConf(nil, clientParams, callback)
}

func newTestAuthConf(authParams *AuthParams, clientParams *api.ClientParams, callback mocks.Do) (*authenticationService, error) {
	if clientParams == nil {
		clientParams = &api.ClientParams{ProjectID: "a"}
	}
	if authParams == nil {
		authParams = &AuthParams{ProjectID: "a", PublicKey: publicKey}
	}
	clientParams.DefaultClient = mocks.NewTestClient(callback)
	return NewAuth(*authParams, api.NewClient(*clientParams), nil)
}

func TestVerifyDeliveryMethod(t *testing.T) {
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	err = a.verifyDeliveryMethod(descope.MethodEmail, "", &descope.User{})
	assert.ErrorIs(t, err, descope.ErrInvalidArguments)
	err = a.verifyDeliveryMethod(descope.MethodSMS, "abc@notaphone.com", &descope.User{})
	assert.ErrorIs(t, err, descope.ErrInvalidArguments)
	err = a.verifyDeliveryMethod(descope.MethodVoice, "abc@notaphone.com", &descope.User{})
	assert.ErrorIs(t, err, descope.ErrInvalidArguments)
	err = a.verifyDeliveryMethod(descope.MethodWhatsApp, "abc@notaphone.com", &descope.User{})
	assert.ErrorIs(t, err, descope.ErrInvalidArguments)

	u := &descope.User{}
	err = a.verifyDeliveryMethod(descope.MethodEmail, "abc@notaphone.com", u)
	assert.Nil(t, err)
	assert.NotEmpty(t, u.Email)

	u = &descope.User{Email: "abc@notaphone.com"}
	err = a.verifyDeliveryMethod(descope.MethodEmail, "my username", u)
	assert.Nil(t, err)

	u = &descope.User{}
	err = a.verifyDeliveryMethod(descope.MethodSMS, "+19999999999", u)
	assert.Nil(t, err)
	assert.NotEmpty(t, u.Phone)
	err = a.verifyDeliveryMethod(descope.MethodVoice, "+19999999999", u)
	assert.Nil(t, err)
	assert.NotEmpty(t, u.Phone)
	err = a.verifyDeliveryMethod(descope.MethodWhatsApp, "+19999999999", u)
	assert.Nil(t, err)
	assert.NotEmpty(t, u.Phone)

	u = &descope.User{Phone: "+19999999999"}
	err = a.verifyDeliveryMethod(descope.MethodSMS, "my username", u)
	assert.Nil(t, err)
	err = a.verifyDeliveryMethod(descope.MethodVoice, "my username", u)
	assert.Nil(t, err)
	err = a.verifyDeliveryMethod(descope.MethodWhatsApp, "my username", u)
	assert.Nil(t, err)
}

func TestAuthDefaultURL(t *testing.T) {
	url := "http://test.com"
	a, err := newTestAuthConf(nil, &api.ClientParams{BaseURL: url}, DoOk(func(r *http.Request) {
		assert.Contains(t, r.URL.String(), url)
	}))
	require.NoError(t, err)
	_, err = a.OTP().VerifyCode(context.Background(), descope.MethodWhatsApp, "4444", "444", nil)
	require.NoError(t, err)
}

func TestEmptyPublicKey(t *testing.T) {
	a, err := newTestAuthConf(&AuthParams{ProjectID: "a"}, nil, mocks.Do(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("[]"))}, nil
	}))
	require.NoError(t, err)
	ok, _, err := a.ValidateSessionWithToken(context.Background(), jwtTokenExpired)
	require.False(t, ok)
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrPublicKey)
	assert.Contains(t, err.Error(), descope.ErrInvalidResponse.Description)
}

func TestErrorFetchPublicKey(t *testing.T) {
	a, err := newTestAuthConf(&AuthParams{ProjectID: "a"}, nil, mocks.Do(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusInternalServerError, Body: io.NopCloser(strings.NewReader("what"))}, nil
	}))
	require.NoError(t, err)
	ok, _, err := a.ValidateSessionWithToken(context.Background(), jwtTokenExpired)
	require.False(t, ok)
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrPublicKey)
	assert.Contains(t, err.Error(), descope.ErrInvalidResponse.Description)
}

// Validate Session

func TestValidateSessionWithRequest(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: descope.SessionCookieName, Value: jwtTokenValid})
	ok, _, err := a.ValidateSessionWithRequest(request)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestValidateSessionWithRequestInvalidInput(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	ok, _, err := a.ValidateSessionWithRequest(nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	require.False(t, ok)
	ok, _, err = a.ValidateSessionWithRequest(&http.Request{Header: http.Header{}})
	require.ErrorIs(t, err, descope.ErrMissingArguments)
	require.False(t, ok)
}

func TestValidateSessionWithToken(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	ok, _, err := a.ValidateSessionWithToken(context.Background(), jwtTokenValid)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestValidateSessionWithTokenInvalidInput(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	ok, _, err := a.ValidateSessionWithToken(context.Background(), "")
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	require.False(t, ok)
}

func TestValidateSessionWithTokenNoPublicKey(t *testing.T) {
	a, err := newTestAuthConf(&AuthParams{ProjectID: "a"}, nil, DoOk(nil))
	require.NoError(t, err)
	ok, _, err := a.ValidateSessionWithToken(context.Background(), jwtTokenValid)
	assert.ErrorIs(t, err, descope.ErrPublicKey)
	require.False(t, ok)
}

func TestValidateSessionWithTokenExpired(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	ok, _, err := a.ValidateSessionWithToken(context.Background(), jwtTokenExpired)
	require.Error(t, err)
	require.False(t, ok)
}

func TestJWTLeewayDefault(t *testing.T) {
	// Test that default leeway (5 seconds) is used when JWTLeeway is not set
	authParams := &AuthParams{ProjectID: "a", PublicKey: publicKey}
	a, err := newTestAuthConf(authParams, nil, DoOk(nil))
	require.NoError(t, err)

	// Create a token that expires 3 seconds ago (within default 5 second leeway)
	now := time.Now()
	token, err := jwt.NewBuilder().
		Issuer("test").
		Subject("someuser").
		Audience([]string{"test"}).
		IssuedAt(now.Add(-10 * time.Second)).
		Expiration(now.Add(-3 * time.Second)).
		Build()
	require.NoError(t, err)

	// Sign the token
	key, err := helpers.LoadPrivateKey()
	require.NoError(t, err)
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES384, key))
	require.NoError(t, err)

	// Should validate successfully with default 5 second leeway
	ok, _, err := a.ValidateSessionWithToken(context.Background(), string(signed))
	require.NoError(t, err)
	require.True(t, ok)
}

func TestJWTLeewayCustom(t *testing.T) {
	// Test that custom leeway is used when JWTLeeway is set
	customLeeway := 30 * time.Second
	authParams := &AuthParams{ProjectID: "a", PublicKey: publicKey, JWTLeeway: customLeeway}
	a, err := newTestAuthConf(authParams, nil, DoOk(nil))
	require.NoError(t, err)

	// Create a token that expires 15 seconds ago (within custom 30 second leeway, but outside default 5 second leeway)
	now := time.Now()
	token, err := jwt.NewBuilder().
		Issuer("test").
		Subject("someuser").
		Audience([]string{"test"}).
		IssuedAt(now.Add(-20 * time.Second)).
		Expiration(now.Add(-15 * time.Second)).
		Build()
	require.NoError(t, err)

	// Sign the token
	key, err := helpers.LoadPrivateKey()
	require.NoError(t, err)
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES384, key))
	require.NoError(t, err)

	// Should validate successfully with custom 30 second leeway
	ok, _, err := a.ValidateSessionWithToken(context.Background(), string(signed))
	require.NoError(t, err)
	require.True(t, ok)
}

func TestJWTLeewayCustomTooSmall(t *testing.T) {
	// Test that a token outside the custom leeway fails validation
	customLeeway := 5 * time.Second
	authParams := &AuthParams{ProjectID: "a", PublicKey: publicKey, JWTLeeway: customLeeway}
	a, err := newTestAuthConf(authParams, nil, DoOk(nil))
	require.NoError(t, err)

	// Create a token that expires 10 seconds ago (outside custom 5 second leeway)
	now := time.Now()
	token, err := jwt.NewBuilder().
		Issuer("test").
		Subject("someuser").
		Audience([]string{"test"}).
		IssuedAt(now.Add(-20 * time.Second)).
		Expiration(now.Add(-10 * time.Second)).
		Build()
	require.NoError(t, err)

	// Sign the token
	key, err := helpers.LoadPrivateKey()
	require.NoError(t, err)
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES384, key))
	require.NoError(t, err)

	// Should fail validation as token is outside the 5 second leeway
	ok, _, err := a.ValidateSessionWithToken(context.Background(), string(signed))
	require.Error(t, err)
	require.False(t, ok)
}

// Refresh Session

func TestRefreshSessionWithRequest(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtRTokenValid})
	ok, _, err := a.RefreshSessionWithRequest(request, nil)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestRefreshSessionWithRequestInvalidInput(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	ok, _, err := a.RefreshSessionWithRequest(nil, nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	require.False(t, ok)
	ok, _, err = a.RefreshSessionWithRequest(&http.Request{Header: http.Header{}}, nil)
	require.ErrorIs(t, err, descope.ErrMissingArguments)
	require.False(t, ok)
}

func TestRefreshSessionWithToken(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	ok, _, err := a.RefreshSessionWithToken(context.Background(), jwtRTokenValid)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestRefreshSessionWithTokenInvalidInput(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	ok, _, err := a.RefreshSessionWithToken(context.Background(), "")
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	require.False(t, ok)
}

func TestRefreshSessionWithTokenNoPublicKey(t *testing.T) {
	a, err := newTestAuthConf(&AuthParams{ProjectID: "a"}, nil, DoOk(nil))
	require.NoError(t, err)
	ok, _, err := a.RefreshSessionWithToken(context.Background(), jwtRTokenValid)
	assert.ErrorIs(t, err, descope.ErrPublicKey)
	require.False(t, ok)
}

func TestRefreshSessionWithTokenExpired(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	ok, _, err := a.RefreshSessionWithToken(context.Background(), jwtTokenExpired)
	require.Error(t, err)
	require.False(t, ok)
}

func TestRefreshSessionWithTokenViaCookie(t *testing.T) {
	// Test that refresh session works when tokens are returned via cookies instead of response body
	// This tests the fix for a panic that occurred when sToken was nil due to empty body
	sessionCookie := &http.Cookie{Name: descope.SessionCookieName, Value: jwtTokenValid}
	refreshCookie := &http.Cookie{Name: descope.RefreshCookieName, Value: jwtRTokenValid}
	a, err := newTestAuth(nil, func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(`{"cookiePath": "/", "cookieDomain": "test.com"}`)),
			Header:     http.Header{"Set-Cookie": []string{sessionCookie.String(), refreshCookie.String()}},
		}, nil
	})
	require.NoError(t, err)
	ok, token, err := a.RefreshSessionWithToken(context.Background(), jwtRTokenValid)
	require.NoError(t, err)
	require.True(t, ok)
	require.NotNil(t, token)
	require.NotEmpty(t, token.JWT)
	require.NotZero(t, token.RefreshExpiration)
}

// Tenant Selection

func TestSelectTenantWithRequest(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		b, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, "tid", b["tenant"])
	}))
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtRTokenValid})
	authInfo, err := a.SelectTenantWithRequest(context.Background(), "tid", request, nil)
	require.NoError(t, err)
	require.NotNil(t, authInfo)
}

func TestSelectTenantWithRequestInvalidInput(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	info, err := a.SelectTenantWithRequest(context.Background(), "tid", nil, nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	require.Nil(t, info)
	info, err = a.SelectTenantWithRequest(context.Background(), "tid", &http.Request{Header: http.Header{}}, nil)
	require.ErrorIs(t, err, descope.ErrMissingArguments)
	require.Nil(t, info)
}

func TestSelectTenantWithToken(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		b, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, "tid", b["tenant"])
	}))
	require.NoError(t, err)
	info, err := a.SelectTenantWithToken(context.Background(), "tid", jwtRTokenValid)
	require.NoError(t, err)
	require.NotNil(t, info)
}

func TestSelectTenantWithTokenInvalidInput(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	info, err := a.SelectTenantWithToken(context.Background(), "tid", "")
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	require.Nil(t, info)
}

// Validate and Refresh Session
func strictCookies(t *testing.T, response *httptest.ResponseRecorder) {
	for _, cookie := range response.Result().Cookies() {
		require.Equal(t, cookie.SameSite, http.SameSiteStrictMode)
	}
}

func laxCookies(t *testing.T, response *httptest.ResponseRecorder) {
	for _, cookie := range response.Result().Cookies() {
		require.Equal(t, cookie.SameSite, http.SameSiteLaxMode)
	}
}

func TestValidateAndRefreshSessionWithRequest(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	// Both tokens ok
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: descope.SessionCookieName, Value: jwtTokenValid})
	request.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtRTokenValid})
	response := httptest.NewRecorder()
	ok, _, err := a.ValidateAndRefreshSessionWithRequest(request, response)
	strictCookies(t, response)
	require.NoError(t, err)
	require.True(t, ok)

	// Session expired
	request = &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: descope.SessionCookieName, Value: jwtTokenExpired})
	request.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtRTokenValid})
	response = httptest.NewRecorder()
	ok, _, err = a.ValidateAndRefreshSessionWithRequest(request, response)
	strictCookies(t, response)
	require.NoError(t, err)
	require.True(t, ok)

	// Session missing
	request = &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtRTokenValid})
	response = httptest.NewRecorder()
	ok, _, err = a.ValidateAndRefreshSessionWithRequest(request, response)
	strictCookies(t, response)
	require.NoError(t, err)
	require.True(t, ok)

	// Refresh missing
	request = &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: descope.SessionCookieName, Value: jwtTokenValid})
	response = httptest.NewRecorder()
	ok, _, err = a.ValidateAndRefreshSessionWithRequest(request, response)
	strictCookies(t, response)
	require.NoError(t, err)
	require.True(t, ok)

	a, err = newTestAuthConf(&AuthParams{CookieSameSite: http.SameSiteLaxMode, ProjectID: "a", PublicKey: publicKey}, nil, DoOk(nil))
	require.NoError(t, err)
	request = &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: descope.SessionCookieName, Value: jwtTokenExpired})
	request.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtRTokenValid})
	response = httptest.NewRecorder()
	ok, _, err = a.ValidateAndRefreshSessionWithRequest(request, response)
	laxCookies(t, response)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestValidateAndRefreshSessionWithRequestInvalidInput(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	ok, _, err := a.ValidateAndRefreshSessionWithRequest(nil, nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	require.False(t, ok)
	ok, _, err = a.ValidateAndRefreshSessionWithRequest(&http.Request{Header: http.Header{}}, nil)
	require.ErrorIs(t, err, descope.ErrMissingArguments)
	require.False(t, ok)
}

func TestValidateAndRefreshSessionWithToken(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	ok, _, err := a.ValidateAndRefreshSessionWithTokens(context.Background(), jwtTokenValid, jwtRTokenValid)
	require.NoError(t, err)
	require.True(t, ok)
	ok, _, err = a.ValidateAndRefreshSessionWithTokens(context.Background(), jwtTokenExpired, jwtRTokenValid)
	require.NoError(t, err)
	require.True(t, ok)
	ok, _, err = a.ValidateAndRefreshSessionWithTokens(context.Background(), "", jwtRTokenValid)
	require.NoError(t, err)
	require.True(t, ok)
	ok, _, err = a.ValidateAndRefreshSessionWithTokens(context.Background(), jwtTokenValid, "")
	require.NoError(t, err)
	require.True(t, ok)
}

func TestValidateAndRefreshSessionWithTokenInvalidInput(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	ok, _, err := a.ValidateAndRefreshSessionWithTokens(context.Background(), "", "")
	require.ErrorIs(t, err, descope.ErrMissingArguments)
	require.False(t, ok)
}

func TestValidateAndRefreshSessionWithTokenNoPublicKey(t *testing.T) {
	a, err := newTestAuthConf(&AuthParams{ProjectID: "a"}, nil, DoOk(nil))
	require.NoError(t, err)
	ok, _, err := a.ValidateAndRefreshSessionWithTokens(context.Background(), jwtTokenValid, jwtRTokenValid)
	assert.ErrorIs(t, err, descope.ErrPublicKey)
	require.False(t, ok)
}

func TestValidateAndRefreshSessionWithTokenExpired(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	ok, _, err := a.ValidateAndRefreshSessionWithTokens(context.Background(), jwtTokenExpired, jwtTokenExpired)
	require.Error(t, err)
	require.False(t, ok)
}

func TestValidateSessionFetchKeyCalledOnce(t *testing.T) {
	count := 0
	a, err := newTestAuthConf(&AuthParams{ProjectID: "a"}, nil, mocks.Do(func(_ *http.Request) (*http.Response, error) {
		count++
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{"keys":[%s]}`, publicKey)))}, nil
	}))
	require.NoError(t, err)
	ok, _, err := a.ValidateSessionWithToken(context.Background(), jwtTokenValid)
	require.NoError(t, err)
	require.True(t, ok)
	require.EqualValues(t, 1, count)
	ok, _, err = a.ValidateSessionWithToken(context.Background(), jwtTokenValid)
	require.NoError(t, err)
	require.True(t, ok)
	require.EqualValues(t, 1, count)
}

func TestValidateSessionFetchKeyMalformed(t *testing.T) {
	a, err := newTestAuthConf(&AuthParams{ProjectID: "a"}, nil, mocks.Do(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{"keys":[%s]}`, unknownPublicKey)))}, nil
	}))
	require.NoError(t, err)
	ok, _, err := a.validateAndRefreshSessionWithTokens(context.Background(), jwtTokenValid, jwtTokenValid, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrPublicKey)
	assert.Contains(t, err.Error(), "does not exist")
	require.False(t, ok)
}

func TestValidateSessionFailWithInvalidKey(t *testing.T) {
	count := 0
	a, err := newTestAuthConf(&AuthParams{PublicKey: unknownPublicKey}, nil, mocks.Do(func(_ *http.Request) (*http.Response, error) {
		count++
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(fmt.Sprintf("[%s]", publicKey)))}, nil
	}))
	require.NoError(t, err)
	ok, _, err := a.ValidateSessionWithToken(context.Background(), jwtTokenValid)
	require.Error(t, err)
	require.False(t, ok)
	require.Zero(t, count)
}

func TestValidateSessionFailWithInvalidAlgorithm(t *testing.T) {
	a, err := newTestAuthConf(&AuthParams{ProjectID: "a"}, nil, mocks.Do(func(_ *http.Request) (*http.Response, error) {
		badKey := strings.ReplaceAll(publicKey, "ES384", "ES123")
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{"keys":[%s]}`, badKey)))}, nil
	}))
	require.NoError(t, err)
	ok, _, err := a.validateAndRefreshSessionWithTokens(context.Background(), jwtTokenValid, jwtTokenValid, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrPublicKey)
	assert.Contains(t, err.Error(), "Invalid signature algorithm")
	require.False(t, ok)
}

func TestValidateSessionRequest(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: descope.SessionCookieName, Value: jwtTokenValid})
	ok, token, err := a.ValidateSessionWithRequest(request)
	require.NoError(t, err)
	require.True(t, ok)
	require.EqualValues(t, jwtTokenValid, token.JWT)
}

func TestValidateSessionRequestHeader(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.Header.Add(api.AuthorizationHeaderName, api.BearerAuthorizationPrefix+jwtTokenValid)
	ok, token, err := a.ValidateSessionWithRequest(request)
	require.NoError(t, err)
	require.True(t, ok)
	require.EqualValues(t, jwtTokenValid, token.JWT)
}

func TestValidateSessionRequestRefreshSession(t *testing.T) {
	a, err := newTestAuthConf(&AuthParams{ProjectID: "a", PublicKey: publicKey, CookieDomain: "cookiedomain.com"}, nil, func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(mockAuthSessionBody))}, nil
	})
	a.conf.SessionJWTViaCookie = true
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtRTokenValid})
	request.AddCookie(&http.Cookie{Name: descope.SessionCookieName, Value: jwtTokenExpired})

	b := httptest.NewRecorder()
	ok, userToken, err := a.ValidateAndRefreshSessionWithRequest(request, b)
	strictCookies(t, b)
	require.NoError(t, err)
	require.True(t, ok)
	assert.EqualValues(t, mockAuthSessionCookie.Value, userToken.JWT)
	require.Len(t, b.Result().Cookies(), 2)
	sessionCookie := b.Result().Cookies()[0]
	require.NoError(t, err)
	assert.Equal(t, "cookiedomain.com", sessionCookie.Domain)
	// Change domain so we can easily compare the rest of the values
	sessionCookie.Domain = mockAuthSessionCookie.Domain
	assert.EqualValues(t, mockAuthSessionCookie.Value, sessionCookie.Value)
}

func TestValidateSessionNotYet(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	ok, _, err := a.ValidateAndRefreshSessionWithTokens(context.Background(), jwtTokenNotYet, jwtTokenNotYet)
	require.Error(t, err)
	require.False(t, ok)
}

func TestConvertError(t *testing.T) {
	err := convertTokenError(jwt.ErrTokenExpired())
	require.ErrorIs(t, err, descope.ErrInvalidToken)
	require.NotEmpty(t, err.(*descope.Error).Message)
	err = convertTokenError(jwt.ErrTokenNotYetValid())
	require.ErrorIs(t, err, descope.ErrInvalidToken)
	require.NotEmpty(t, err.(*descope.Error).Message)
	err = convertTokenError(jwt.ErrInvalidIssuedAt())
	require.ErrorIs(t, err, descope.ErrInvalidToken)
	require.Empty(t, err.(*descope.Error).Message)
	err = convertTokenError(nil)
	require.Nil(t, err)
}

func TestLogout(t *testing.T) {
	a, err := newTestAuth(nil, func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(mockAuthSessionBody))}, nil
	})
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtRTokenValid})

	w := httptest.NewRecorder()
	err = a.Logout(request, w)
	strictCookies(t, w)
	require.NoError(t, err)
	require.Len(t, w.Result().Cookies(), 2)
	c1 := w.Result().Cookies()[0]
	assert.Empty(t, c1.Value)
	assert.EqualValues(t, descope.SessionCookieName, c1.Name)
	assert.EqualValues(t, "/my-path", c1.Path)
	assert.EqualValues(t, "my-domain", c1.Domain)
	c2 := w.Result().Cookies()[1]
	assert.Empty(t, c2.Value)
	assert.EqualValues(t, descope.RefreshCookieName, c2.Name)
	assert.EqualValues(t, "/my-path", c2.Path)
	assert.EqualValues(t, "my-domain", c2.Domain)

	err = a.Logout(request, nil)
	require.NoError(t, err)
}

func TestLogoutWithToken(t *testing.T) {
	a, err := newTestAuth(nil, func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(mockAuthSessionBody))}, nil
	})
	require.NoError(t, err)

	w := httptest.NewRecorder()
	err = a.LogoutWithToken(jwtRTokenValid, w)
	strictCookies(t, w)
	require.NoError(t, err)
	require.Len(t, w.Result().Cookies(), 2)
	c1 := w.Result().Cookies()[0]
	assert.Empty(t, c1.Value)
	assert.EqualValues(t, descope.SessionCookieName, c1.Name)
	assert.EqualValues(t, "/my-path", c1.Path)
	assert.EqualValues(t, "my-domain", c1.Domain)
	c2 := w.Result().Cookies()[1]
	assert.Empty(t, c2.Value)
	assert.EqualValues(t, descope.RefreshCookieName, c2.Name)
	assert.EqualValues(t, "/my-path", c2.Path)
	assert.EqualValues(t, "my-domain", c2.Domain)

	err = a.LogoutWithToken(jwtRTokenValid, nil)
	require.NoError(t, err)
}

func TestLogoutAll(t *testing.T) {
	a, err := newTestAuth(nil, func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(mockAuthSessionBody))}, nil
	})
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtRTokenValid})

	w := httptest.NewRecorder()
	err = a.LogoutAll(request, w)
	strictCookies(t, w)
	require.NoError(t, err)
	require.Len(t, w.Result().Cookies(), 2)
	c1 := w.Result().Cookies()[0]
	assert.Empty(t, c1.Value)
	assert.EqualValues(t, descope.SessionCookieName, c1.Name)
	assert.EqualValues(t, "/my-path", c1.Path)
	assert.EqualValues(t, "my-domain", c1.Domain)
	c2 := w.Result().Cookies()[1]
	assert.Empty(t, c2.Value)
	assert.EqualValues(t, descope.RefreshCookieName, c2.Name)
	assert.EqualValues(t, "/my-path", c2.Path)
	assert.EqualValues(t, "my-domain", c2.Domain)

	err = a.LogoutAll(request, nil)
	require.NoError(t, err)
}

func TestLogoutAllWithToken(t *testing.T) {
	a, err := newTestAuth(nil, func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(mockAuthSessionBody))}, nil
	})
	require.NoError(t, err)

	w := httptest.NewRecorder()
	err = a.LogoutAllWithToken(jwtRTokenValid, w)
	strictCookies(t, w)
	require.NoError(t, err)
	require.Len(t, w.Result().Cookies(), 2)
	c1 := w.Result().Cookies()[0]
	assert.Empty(t, c1.Value)
	assert.EqualValues(t, descope.SessionCookieName, c1.Name)
	assert.EqualValues(t, "/my-path", c1.Path)
	assert.EqualValues(t, "my-domain", c1.Domain)
	c2 := w.Result().Cookies()[1]
	assert.Empty(t, c2.Value)
	assert.EqualValues(t, descope.RefreshCookieName, c2.Name)
	assert.EqualValues(t, "/my-path", c2.Path)
	assert.EqualValues(t, "my-domain", c2.Domain)

	err = a.LogoutAllWithToken(jwtRTokenValid, nil)
	require.NoError(t, err)
}

func TestLogoutNoClaims(t *testing.T) {
	a, err := newTestAuth(nil, func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK}, nil
	})
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtRTokenValid})

	w := httptest.NewRecorder()
	err = a.Logout(request, w)
	strictCookies(t, w)
	require.NoError(t, err)
	require.Len(t, w.Result().Cookies(), 2)
	c1 := w.Result().Cookies()[0]
	assert.Empty(t, c1.Value)
	assert.EqualValues(t, descope.SessionCookieName, c1.Name)
	assert.EqualValues(t, "/", c1.Path)
	assert.EqualValues(t, "", c1.Domain)
	c2 := w.Result().Cookies()[1]
	assert.Empty(t, c2.Value)
	assert.EqualValues(t, descope.RefreshCookieName, c2.Name)
	assert.EqualValues(t, "/", c2.Path)
	assert.EqualValues(t, "", c2.Domain)
}

func TestLogoutAllNoClaims(t *testing.T) {
	a, err := newTestAuth(nil, func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK}, nil
	})
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtRTokenValid})

	w := httptest.NewRecorder()
	err = a.LogoutAll(request, w)
	strictCookies(t, w)
	require.NoError(t, err)
	require.Len(t, w.Result().Cookies(), 2)
	c1 := w.Result().Cookies()[0]
	assert.Empty(t, c1.Value)
	assert.EqualValues(t, descope.SessionCookieName, c1.Name)
	assert.EqualValues(t, "/", c1.Path)
	assert.EqualValues(t, "", c1.Domain)
	c2 := w.Result().Cookies()[1]
	assert.Empty(t, c2.Value)
	assert.EqualValues(t, descope.RefreshCookieName, c2.Name)
	assert.EqualValues(t, "/", c2.Path)
	assert.EqualValues(t, "", c2.Domain)
}

func TestLogoutFailure(t *testing.T) {
	a, err := newTestAuth(nil, func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadGateway}, nil
	})
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtRTokenValid})

	err = a.Logout(request, nil)
	require.Error(t, err)
}

func TestLogoutAllFailure(t *testing.T) {
	a, err := newTestAuth(nil, func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadGateway}, nil
	})
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtRTokenValid})

	err = a.LogoutAll(request, nil)
	require.Error(t, err)
}

func TestLogoutInvalidRefreshToken(t *testing.T) {
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtTokenExpired})

	err = a.Logout(request, nil)
	require.Error(t, err)
}

func TestLogoutAllInvalidRefreshToken(t *testing.T) {
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtTokenExpired})

	err = a.LogoutAll(request, nil)
	require.Error(t, err)
}

func TestLogoutEmptyRequest(t *testing.T) {
	a, err := newTestAuth(nil, func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadGateway}, nil
	})
	require.NoError(t, err)

	err = a.Logout(nil, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidArguments)
}

func TestLogoutAllEmptyRequest(t *testing.T) {
	a, err := newTestAuth(nil, func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadGateway}, nil
	})
	require.NoError(t, err)

	err = a.LogoutAll(nil, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidArguments)
}

func TestLogoutMissingToken(t *testing.T) {
	a, err := newTestAuth(nil, func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadGateway}, nil
	})
	require.NoError(t, err)

	request := &http.Request{Header: http.Header{}}
	err = a.Logout(request, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrRefreshToken)
}

func TestLogoutAllMissingToken(t *testing.T) {
	a, err := newTestAuth(nil, func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadGateway}, nil
	})
	require.NoError(t, err)

	request := &http.Request{Header: http.Header{}}
	err = a.LogoutAll(request, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrRefreshToken)
}

func TestExtractTokensEmpty(t *testing.T) {
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	tokens, err := a.extractTokens(&descope.JWTResponse{})
	require.NoError(t, err)
	require.Len(t, tokens, 0)
}

func TestExtractTokensInvalid(t *testing.T) {
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	tokens, err := a.extractTokens(&descope.JWTResponse{SessionJwt: "aaaaa"})
	require.ErrorIs(t, err, descope.ErrPublicKey)
	require.Empty(t, tokens)
	tokens, err = a.extractTokens(&descope.JWTResponse{RefreshJwt: "aaaaa"})
	require.ErrorIs(t, err, descope.ErrPublicKey)
	require.Empty(t, tokens)
}

func TestExtractJwtWithTenants(t *testing.T) {
	a, err := newTestAuthConf(&AuthParams{PublicKey: publicKeyWithTenants}, nil, nil)
	require.NoError(t, err)
	tokens, err := a.extractTokens(&descope.JWTResponse{SessionJwt: jwtTokenWithTenants})
	require.NoError(t, err)
	require.True(t, len(tokens) > 0)
	tenants := tokens[0].GetTenants()
	assert.Len(t, tenants, 2)
	m := map[string]any{"t1": true, "t2": true}
	for _, k := range tenants {
		delete(m, k)
	}
	assert.Len(t, m, 0)
}

func BenchmarkValidateSession(b *testing.B) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(b, err)

	for n := 0; n < b.N; n++ {
		_, _, _ = a.ValidateSessionWithToken(context.Background(), jwtTokenValid)
	}
}

func TestExchangeAccessKey(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)

	ok, token, err := a.ExchangeAccessKey(context.Background(), "foo", nil)
	require.NoError(t, err)
	require.True(t, ok)
	require.NotNil(t, token)
}

func TestExchangeAccessKeyWithLoginOptions(t *testing.T) {
	response := map[string]any{}
	err := utils.Unmarshal([]byte(mockAuthSessionBody), &response)
	require.NoError(t, err)
	a, err := newTestAuth(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		rlo, found := req["loginOptions"]
		require.True(t, found)
		cc, found := rlo.(map[string]any)["customClaims"]
		require.True(t, found)
		customClaims, ok := cc.(map[string]any)
		require.True(t, ok)
		d, found := customClaims["k1"]
		require.True(t, found)
		require.EqualValues(t, "v1", d)
	}, response))
	require.NoError(t, err)
	loginOptions := &descope.AccessKeyLoginOptions{
		CustomClaims: map[string]any{"k1": "v1"},
	}

	ok, token, err := a.ExchangeAccessKey(context.Background(), "foo", loginOptions)
	require.NoError(t, err)
	require.True(t, ok)
	require.NotNil(t, token)
}

func TestExchangeAccessKeyBadRequest(t *testing.T) {
	a, err := newTestAuth(nil, DoBadRequest(nil))
	require.NoError(t, err)

	ok, token, err := a.ExchangeAccessKey(context.Background(), "foo", nil)
	require.ErrorIs(t, err, descope.ErrBadRequest)
	require.False(t, ok)
	require.Nil(t, token)
}

func TestExchangeAccessKeyEmptyResponse(t *testing.T) {
	a, err := newTestAuth(nil, DoOkWithBody(nil, ""))
	require.NoError(t, err)

	ok, token, err := a.ExchangeAccessKey(context.Background(), "foo", nil)
	require.ErrorIs(t, err, descope.ErrUnexpectedResponse)
	require.False(t, ok)
	require.Nil(t, token)
}

func TestExchangeAccessKeyInvalidResponse(t *testing.T) {
	expectedResponse := descope.JWTResponse{}
	a, err := newTestAuth(nil, DoOkWithBody(nil, expectedResponse))
	require.NoError(t, err)

	ok, token, err := a.ExchangeAccessKey(context.Background(), "foo", nil)
	require.ErrorIs(t, err, descope.ErrUnexpectedResponse)
	require.False(t, ok)
	require.Nil(t, token)
}

func TestValidatePermissions(t *testing.T) {
	a, err := newTestAuth(nil, DoOkWithBody(nil, ""))
	require.NoError(t, err)

	require.True(t, a.ValidatePermissions(context.Background(), nil, []string{}))
	require.False(t, a.ValidatePermissions(context.Background(), nil, []string{"foo"}))

	require.True(t, a.ValidatePermissions(context.Background(), mockAuthorizationToken, []string{}))
	require.True(t, a.ValidatePermissions(context.Background(), mockAuthorizationToken, []string{"foo"}))
	require.True(t, a.ValidatePermissions(context.Background(), mockAuthorizationToken, []string{"foo", "bar"}))
	require.False(t, a.ValidatePermissions(context.Background(), mockAuthorizationToken, []string{"foo", "bar", "qux"}))

	require.True(t, a.ValidatePermissions(context.Background(), mockAuthorizationTenantToken, []string{}))
	require.False(t, a.ValidatePermissions(context.Background(), mockAuthorizationTenantToken, []string{"foo"}))
	require.False(t, a.ValidatePermissions(context.Background(), mockAuthorizationTenantToken, []string{"foo", "bar"}))
	require.False(t, a.ValidatePermissions(context.Background(), mockAuthorizationTenantToken, []string{"foo", "bar", "qux"}))

	require.False(t, a.ValidateTenantPermissions(context.Background(), mockAuthorizationToken, "kuku", []string{}))
	require.False(t, a.ValidateTenantPermissions(context.Background(), mockAuthorizationToken, "kuku", []string{"foo"}))
	require.False(t, a.ValidateTenantPermissions(context.Background(), mockAuthorizationToken, "kuku", []string{"foo", "bar"}))
	require.False(t, a.ValidateTenantPermissions(context.Background(), mockAuthorizationToken, "kuku", []string{"foo", "bar", "qux"}))

	require.True(t, a.ValidateTenantPermissions(context.Background(), mockAuthorizationTenantToken, "kuku", []string{}))
	require.True(t, a.ValidateTenantPermissions(context.Background(), mockAuthorizationTenantToken, "kuku", []string{"foo"}))
	require.True(t, a.ValidateTenantPermissions(context.Background(), mockAuthorizationTenantToken, "kuku", []string{"foo", "bar"}))
	require.False(t, a.ValidateTenantPermissions(context.Background(), mockAuthorizationTenantToken, "kuku", []string{"foo", "bar", "qux"}))

	require.True(t, a.ValidateTenantPermissions(context.Background(), mockAuthorizationTenantToken, "t1", []string{}))
	require.False(t, a.ValidateTenantPermissions(context.Background(), mockAuthorizationTenantToken, "t2", []string{}))

	require.True(t, a.ValidateTenantPermissions(context.Background(), mockAuthorizationCurrentTenantTokenNoTenants, "t1", []string{"foo"}))
	require.False(t, a.ValidateTenantPermissions(context.Background(), mockAuthorizationCurrentTenantTokenNoTenants, "t1", []string{"qux"}))
	require.False(t, a.ValidateTenantPermissions(context.Background(), mockAuthorizationCurrentTenantTokenNoTenants, "t2", []string{"foo"}))

	require.True(t, a.ValidateTenantPermissions(context.Background(), mockAuthorizationCurrentTenantTokenWithTenants, "t1", []string{"t1-perm1"}))
	require.False(t, a.ValidateTenantPermissions(context.Background(), mockAuthorizationCurrentTenantTokenWithTenants, "t1", []string{"foo"}))

	// check when the value of the claim is not a map
	require.False(t, a.ValidateTenantPermissions(
		context.Background(),
		&descope.Token{Claims: map[string]any{
			descope.ClaimAuthorizedTenants: map[string]any{"t1": true},
		}},
		"t1",
		[]string{"foo"},
	))
}

func TestGetMatchedPermissions(t *testing.T) {
	a, err := newTestAuth(nil, DoOkWithBody(nil, ""))
	require.NoError(t, err)

	require.Equal(t, []string{}, a.GetMatchedPermissions(context.Background(), nil, []string{}))
	require.Equal(t, []string{}, a.GetMatchedPermissions(context.Background(), nil, []string{"abc"}))

	require.Equal(t, []string{}, a.GetMatchedPermissions(context.Background(), mockAuthorizationToken, []string{}))
	require.Equal(t, []string{"foo"}, a.GetMatchedPermissions(context.Background(), mockAuthorizationToken, []string{"foo"}))
	require.Equal(t, []string{"foo", "bar"}, a.GetMatchedPermissions(context.Background(), mockAuthorizationToken, []string{"foo", "bar"}))
	require.Equal(t, []string{"foo", "bar"}, a.GetMatchedPermissions(context.Background(), mockAuthorizationToken, []string{"foo", "bar", "qux"}))

	require.Equal(t, []string{}, a.GetMatchedTenantPermissions(context.Background(), mockAuthorizationTenantToken, "kuku", []string{}))
	require.Equal(t, []string{"foo"}, a.GetMatchedTenantPermissions(context.Background(), mockAuthorizationTenantToken, "kuku", []string{"foo"}))
	require.Equal(t, []string{"foo", "bar"}, a.GetMatchedTenantPermissions(context.Background(), mockAuthorizationTenantToken, "kuku", []string{"foo", "bar"}))
	require.Equal(t, []string{"foo", "bar"}, a.GetMatchedTenantPermissions(context.Background(), mockAuthorizationTenantToken, "kuku", []string{"foo", "bar", "qux"}))

	require.Equal(t, []string{"foo", "bar"}, a.GetMatchedTenantPermissions(context.Background(), mockAuthorizationCurrentTenantTokenNoTenants, "t1", []string{"foo", "bar", "qux"}))
	require.Equal(t, []string{}, a.GetMatchedTenantPermissions(context.Background(), mockAuthorizationCurrentTenantTokenNoTenants, "t2", []string{"foo", "bar", "qux"}))

	require.Equal(t, []string{"t1-perm1"}, a.GetMatchedTenantPermissions(context.Background(), mockAuthorizationCurrentTenantTokenWithTenants, "t1", []string{"t1-perm1"}))
	require.Equal(t, []string{}, a.GetMatchedTenantPermissions(context.Background(), mockAuthorizationCurrentTenantTokenWithTenants, "t1", []string{"foo"}))
}

func TestValidateRoles(t *testing.T) {
	a, err := newTestAuth(nil, DoOkWithBody(nil, ""))
	require.NoError(t, err)

	require.True(t, a.ValidateRoles(context.Background(), nil, []string{}))
	require.False(t, a.ValidateRoles(context.Background(), nil, []string{"foo"}))

	require.True(t, a.ValidateRoles(context.Background(), mockAuthorizationToken, []string{}))
	require.True(t, a.ValidateRoles(context.Background(), mockAuthorizationToken, []string{"abc"}))
	require.True(t, a.ValidateRoles(context.Background(), mockAuthorizationToken, []string{"abc", "xyz"}))
	require.False(t, a.ValidateRoles(context.Background(), mockAuthorizationToken, []string{"abc", "xyz", "tuv"}))

	require.True(t, a.ValidateRoles(context.Background(), mockAuthorizationTenantToken, []string{}))
	require.False(t, a.ValidateRoles(context.Background(), mockAuthorizationTenantToken, []string{"abc"}))
	require.False(t, a.ValidateRoles(context.Background(), mockAuthorizationTenantToken, []string{"abc", "xyz"}))
	require.False(t, a.ValidateRoles(context.Background(), mockAuthorizationTenantToken, []string{"abc", "xyz", "tuv"}))

	require.False(t, a.ValidateTenantRoles(context.Background(), mockAuthorizationToken, "kuku", []string{}))
	require.False(t, a.ValidateTenantRoles(context.Background(), mockAuthorizationToken, "kuku", []string{"abc"}))
	require.False(t, a.ValidateTenantRoles(context.Background(), mockAuthorizationToken, "kuku", []string{"abc", "xyz"}))
	require.False(t, a.ValidateTenantRoles(context.Background(), mockAuthorizationToken, "kuku", []string{"abc", "xyz", "tuv"}))

	require.True(t, a.ValidateTenantRoles(context.Background(), mockAuthorizationTenantToken, "kuku", []string{}))
	require.True(t, a.ValidateTenantRoles(context.Background(), mockAuthorizationTenantToken, "kuku", []string{"abc"}))
	require.True(t, a.ValidateTenantRoles(context.Background(), mockAuthorizationTenantToken, "kuku", []string{"abc", "xyz"}))
	require.False(t, a.ValidateTenantRoles(context.Background(), mockAuthorizationTenantToken, "kuku", []string{"abc", "xyz", "tuv"}))

	require.True(t, a.ValidateTenantRoles(context.Background(), mockAuthorizationTenantToken, "t1", []string{}))
	require.False(t, a.ValidateTenantRoles(context.Background(), mockAuthorizationTenantToken, "t2", []string{}))

	require.True(t, a.ValidateTenantRoles(context.Background(), mockAuthorizationCurrentTenantTokenNoTenants, "t1", []string{"abc"}))
	require.False(t, a.ValidateTenantRoles(context.Background(), mockAuthorizationCurrentTenantTokenNoTenants, "t1", []string{"tuv"}))
	require.False(t, a.ValidateTenantRoles(context.Background(), mockAuthorizationCurrentTenantTokenNoTenants, "t2", []string{"abc"}))

	require.True(t, a.ValidateTenantRoles(context.Background(), mockAuthorizationCurrentTenantTokenWithTenants, "t1", []string{"t1-role1"}))
	require.False(t, a.ValidateTenantRoles(context.Background(), mockAuthorizationCurrentTenantTokenWithTenants, "t1", []string{"abc"}))
}

func TestGetMatchedRoles(t *testing.T) {
	a, err := newTestAuth(nil, DoOkWithBody(nil, ""))
	require.NoError(t, err)

	require.Equal(t, []string{}, a.GetMatchedRoles(context.Background(), nil, []string{}))
	require.Equal(t, []string{}, a.GetMatchedRoles(context.Background(), nil, []string{"foo"}))

	require.Equal(t, []string{}, a.GetMatchedRoles(context.Background(), mockAuthorizationToken, []string{}))
	require.Equal(t, []string{"abc"}, a.GetMatchedRoles(context.Background(), mockAuthorizationToken, []string{"abc"}))
	require.Equal(t, []string{"abc", "xyz"}, a.GetMatchedRoles(context.Background(), mockAuthorizationToken, []string{"abc", "xyz"}))
	require.Equal(t, []string{"abc", "xyz"}, a.GetMatchedRoles(context.Background(), mockAuthorizationToken, []string{"abc", "xyz", "tuv"}))

	require.Equal(t, []string{}, a.GetMatchedTenantRoles(context.Background(), mockAuthorizationTenantToken, "kuku", []string{}))
	require.Equal(t, []string{"abc"}, a.GetMatchedTenantRoles(context.Background(), mockAuthorizationTenantToken, "kuku", []string{"abc"}))
	require.Equal(t, []string{"abc", "xyz"}, a.GetMatchedTenantRoles(context.Background(), mockAuthorizationTenantToken, "kuku", []string{"abc", "xyz"}))
	require.Equal(t, []string{"abc", "xyz"}, a.GetMatchedTenantRoles(context.Background(), mockAuthorizationTenantToken, "kuku", []string{"abc", "xyz", "tuv"}))

	require.Equal(t, []string{"abc", "xyz"}, a.GetMatchedTenantRoles(context.Background(), mockAuthorizationCurrentTenantTokenNoTenants, "t1", []string{"abc", "xyz", "tuv"}))
	require.Equal(t, []string{}, a.GetMatchedTenantRoles(context.Background(), mockAuthorizationCurrentTenantTokenNoTenants, "t2", []string{"abc", "xyz", "tuv"}))

	require.Equal(t, []string{"t1-role1"}, a.GetMatchedTenantRoles(context.Background(), mockAuthorizationCurrentTenantTokenWithTenants, "t1", []string{"t1-role1"}))
	require.Equal(t, []string{}, a.GetMatchedTenantRoles(context.Background(), mockAuthorizationCurrentTenantTokenWithTenants, "t1", []string{"abc"}))
}

func TestGetTenants(t *testing.T) {
	require.Equal(t, []string{}, mockAuthorizationToken.GetTenants())
	require.Equal(t, []string{"t1"}, mockAuthorizationCurrentTenantTokenNoTenants.GetTenants())
	require.ElementsMatch(t, []string{"kuku", "t1"}, mockAuthorizationTenantToken.GetTenants())
	require.ElementsMatch(t, []string{"t1", "t2"}, mockAuthorizationCurrentTenantTokenWithTenants.GetTenants())
}

func TestMe(t *testing.T) {
	a, err := newTestAuth(nil, func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(mockUserResponseBody))}, nil
	})
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtRTokenValid})

	user, err := a.Me(request)
	require.NoError(t, err)
	assert.Equal(t, "kuku", user.UserID)
	assert.Equal(t, "kuku@test.com", user.Email)
	assert.Equal(t, "kuku name", user.Name)
	assert.Equal(t, "@(^_^)@", user.Picture)
}

func TestMeNoRequest(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	user, err := a.Me(nil)
	assert.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.Nil(t, user)
}

func TestMeNoToken(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	user, err := a.Me(request)
	assert.ErrorIs(t, err, descope.ErrRefreshToken)
	assert.ErrorContains(t, err, "Unable to find tokens")
	assert.Nil(t, user)
}

func TestMeInvalidToken(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtTokenExpired})

	user, err := a.Me(request)
	assert.ErrorIs(t, err, descope.ErrRefreshToken)
	assert.ErrorContains(t, err, "Invalid refresh token")
	assert.Nil(t, user)
}

func TestMeEmptyResponse(t *testing.T) {
	a, err := newTestAuth(nil, func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(""))}, nil
	})
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtRTokenValid})

	user, err := a.Me(request)
	assert.ErrorContains(t, err, "JSON input")
	assert.Nil(t, user)
}

func TestTenants(t *testing.T) {
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		m := &map[string]any{}
		_ = readBody(r, m)
		assert.EqualValues(t, map[string]any{"dct": true, "ids": nil}, *m)
		res := descope.TenantsResponse{Tenants: []descope.MeTenant{{ID: "a"}}}
		bs, err := utils.Marshal(res)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(string(bs)))}, nil
	})
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtRTokenValid})

	tnts, err := a.MyTenants(context.Background(), request, true, nil)
	require.NoError(t, err)
	assert.Len(t, tnts.Tenants, 1)
}

func TestTenantsInvalidArgs(t *testing.T) {
	a, err := newTestAuth(nil, func(_ *http.Request) (*http.Response, error) {
		res := descope.TenantsResponse{Tenants: []descope.MeTenant{{ID: "a"}}}
		bs, err := utils.Marshal(res)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(string(bs)))}, nil
	})
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtRTokenValid})

	_, err = a.MyTenants(context.Background(), request, true, []string{"a"})
	require.Error(t, err)
}

func TestTenantsNoRequest(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	user, err := a.MyTenants(context.Background(), nil, true, nil)
	assert.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.Nil(t, user)
}

func TestTenantsNoToken(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	user, err := a.MyTenants(context.Background(), request, true, nil)
	assert.ErrorIs(t, err, descope.ErrRefreshToken)
	assert.ErrorContains(t, err, "Unable to find tokens")
	assert.Nil(t, user)
}

func TestTenantsInvalidToken(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtTokenExpired})

	user, err := a.MyTenants(context.Background(), request, true, nil)
	assert.ErrorIs(t, err, descope.ErrRefreshToken)
	assert.ErrorContains(t, err, "Invalid refresh token")
	assert.Nil(t, user)
}

func TestHistory(t *testing.T) {
	a, err := newTestAuth(nil, func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(mockUserHistoryResponseBody))}, nil
	})
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtRTokenValid})

	userHistory, err := a.History(request)
	require.NoError(t, err)
	require.Len(t, userHistory, 2)

	assert.Equal(t, "kuku", userHistory[0].UserID)
	assert.Equal(t, "kefar saba", userHistory[0].City)
	assert.Equal(t, "Israel", userHistory[0].Country)
	assert.Equal(t, "1.1.1.1", userHistory[0].IP)
	assert.Equal(t, int32(32), userHistory[0].LoginTime)

	assert.Equal(t, "nunu", userHistory[1].UserID)
	assert.Equal(t, "eilat", userHistory[1].City)
	assert.Equal(t, "Israele", userHistory[1].Country)
	assert.Equal(t, "1.1.1.2", userHistory[1].IP)
	assert.Equal(t, int32(23), userHistory[1].LoginTime)
}

func TestHistoryNoRequest(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	user, err := a.History(nil)
	assert.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.Nil(t, user)
}

func TestHistoryNoToken(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	user, err := a.History(request)
	assert.ErrorIs(t, err, descope.ErrRefreshToken)
	assert.ErrorContains(t, err, "Unable to find tokens")
	assert.Nil(t, user)
}

func TestHistoryInvalidToken(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtTokenExpired})

	user, err := a.History(request)
	assert.ErrorIs(t, err, descope.ErrRefreshToken)
	assert.ErrorContains(t, err, "Invalid refresh token")
	assert.Nil(t, user)
}

func TestHistoryEmptyResponse(t *testing.T) {
	a, err := newTestAuth(nil, func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(""))}, nil
	})
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtRTokenValid})

	user, err := a.History(request)
	assert.ErrorContains(t, err, "JSON input")
	assert.Nil(t, user)
}

// RequestTokensProvider tests

type mockRequestTokensProvider struct {
	sessionToken string
	refreshToken string
}

func (m *mockRequestTokensProvider) ProvideTokens(_ *http.Request) (string, string) {
	return m.sessionToken, m.refreshToken
}

func newTestAuthWithTokenProvider(clientParams *api.ClientParams, callback mocks.Do, tokenProvider sdk.RequestTokensProvider) (*authenticationService, error) {
	if clientParams == nil {
		clientParams = &api.ClientParams{ProjectID: "a"}
	}
	authParams := &AuthParams{ProjectID: "a", PublicKey: publicKey}
	clientParams.DefaultClient = mocks.NewTestClient(callback)
	return NewAuth(*authParams, api.NewClient(*clientParams), tokenProvider)
}

func TestDefaultRequestTokensProviderNilRequest(t *testing.T) {
	provider := &defaultRequestTokensProvider{
		sessionCookieName: descope.SessionCookieName,
		refreshCookieName: descope.RefreshCookieName,
	}
	sessionToken, refreshToken := provider.ProvideTokens(nil)
	assert.Empty(t, sessionToken)
	assert.Empty(t, refreshToken)
}

func TestDefaultRequestTokensProviderFromCookie(t *testing.T) {
	provider := &defaultRequestTokensProvider{
		sessionCookieName: descope.SessionCookieName,
		refreshCookieName: descope.RefreshCookieName,
	}
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: descope.SessionCookieName, Value: "session-token-value"})
	request.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: "refresh-token-value"})

	sessionToken, refreshToken := provider.ProvideTokens(request)
	assert.Equal(t, "session-token-value", sessionToken)
	assert.Equal(t, "refresh-token-value", refreshToken)
}

func TestDefaultRequestTokensProviderFromHeader(t *testing.T) {
	provider := &defaultRequestTokensProvider{
		sessionCookieName: descope.SessionCookieName,
		refreshCookieName: descope.RefreshCookieName,
	}
	request := &http.Request{Header: http.Header{}}
	request.Header.Add(api.AuthorizationHeaderName, api.BearerAuthorizationPrefix+"header-session-token")
	request.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: "refresh-token-value"})

	sessionToken, refreshToken := provider.ProvideTokens(request)
	assert.Equal(t, "header-session-token", sessionToken)
	assert.Equal(t, "refresh-token-value", refreshToken)
}

func TestDefaultRequestTokensProviderHeaderTakesPrecedence(t *testing.T) {
	provider := &defaultRequestTokensProvider{
		sessionCookieName: descope.SessionCookieName,
		refreshCookieName: descope.RefreshCookieName,
	}
	request := &http.Request{Header: http.Header{}}
	request.Header.Add(api.AuthorizationHeaderName, api.BearerAuthorizationPrefix+"header-session-token")
	request.AddCookie(&http.Cookie{Name: descope.SessionCookieName, Value: "cookie-session-token"})
	request.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: "refresh-token-value"})

	sessionToken, refreshToken := provider.ProvideTokens(request)
	assert.Equal(t, "header-session-token", sessionToken)
	assert.Equal(t, "refresh-token-value", refreshToken)
}

func TestDefaultRequestTokensProviderNoRefreshCookie(t *testing.T) {
	provider := &defaultRequestTokensProvider{
		sessionCookieName: descope.SessionCookieName,
		refreshCookieName: descope.RefreshCookieName,
	}
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: descope.SessionCookieName, Value: "session-token-value"})

	sessionToken, refreshToken := provider.ProvideTokens(request)
	assert.Equal(t, "session-token-value", sessionToken)
	assert.Empty(t, refreshToken)
}

func TestDefaultRequestTokensProviderCustomCookieNames(t *testing.T) {
	provider := &defaultRequestTokensProvider{
		sessionCookieName: "CustomSession",
		refreshCookieName: "CustomRefresh",
	}
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: "CustomSession", Value: "custom-session-token"})
	request.AddCookie(&http.Cookie{Name: "CustomRefresh", Value: "custom-refresh-token"})

	sessionToken, refreshToken := provider.ProvideTokens(request)
	assert.Equal(t, "custom-session-token", sessionToken)
	assert.Equal(t, "custom-refresh-token", refreshToken)
}

func TestCustomRequestTokensProviderValidateSession(t *testing.T) {
	customProvider := &mockRequestTokensProvider{
		sessionToken: jwtTokenValid,
		refreshToken: jwtRTokenValid,
	}
	a, err := newTestAuthWithTokenProvider(nil, DoOk(nil), customProvider)
	require.NoError(t, err)

	// Even with an empty request, the custom provider should provide the tokens
	request := &http.Request{Header: http.Header{}}
	ok, token, err := a.ValidateSessionWithRequest(request)
	require.NoError(t, err)
	require.True(t, ok)
	require.NotNil(t, token)
}

func TestCustomRequestTokensProviderValidateAndRefreshSession(t *testing.T) {
	customProvider := &mockRequestTokensProvider{
		sessionToken: jwtTokenValid,
		refreshToken: jwtRTokenValid,
	}
	a, err := newTestAuthWithTokenProvider(nil, DoOk(nil), customProvider)
	require.NoError(t, err)

	// Even with an empty request, the custom provider should provide the tokens
	request := &http.Request{Header: http.Header{}}
	ok, token, err := a.ValidateAndRefreshSessionWithRequest(request, nil)
	require.NoError(t, err)
	require.True(t, ok)
	require.NotNil(t, token)
}

func TestCustomRequestTokensProviderRefreshSession(t *testing.T) {
	customProvider := &mockRequestTokensProvider{
		sessionToken: "",
		refreshToken: jwtRTokenValid,
	}
	a, err := newTestAuthWithTokenProvider(nil, DoOk(nil), customProvider)
	require.NoError(t, err)

	// Even with an empty request, the custom provider should provide the refresh token
	request := &http.Request{Header: http.Header{}}
	ok, token, err := a.RefreshSessionWithRequest(request, nil)
	require.NoError(t, err)
	require.True(t, ok)
	require.NotNil(t, token)
}

func TestCustomRequestTokensProviderEmptyTokens(t *testing.T) {
	customProvider := &mockRequestTokensProvider{
		sessionToken: "",
		refreshToken: "",
	}
	a, err := newTestAuthWithTokenProvider(nil, DoOk(nil), customProvider)
	require.NoError(t, err)

	request := &http.Request{Header: http.Header{}}
	ok, _, err := a.ValidateSessionWithRequest(request)
	require.ErrorIs(t, err, descope.ErrMissingArguments)
	require.False(t, ok)
}

func TestCustomRequestTokensProviderOverridesDefaultBehavior(t *testing.T) {
	// Create a custom provider that returns specific tokens
	customProvider := &mockRequestTokensProvider{
		sessionToken: jwtTokenValid,
		refreshToken: jwtRTokenValid,
	}
	a, err := newTestAuthWithTokenProvider(nil, DoOk(nil), customProvider)
	require.NoError(t, err)

	// Create a request with different tokens in cookies - these should be ignored
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: descope.SessionCookieName, Value: jwtTokenExpired})
	request.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtTokenExpired})

	// The custom provider's valid tokens should be used, not the expired ones from cookies
	ok, token, err := a.ValidateSessionWithRequest(request)
	require.NoError(t, err)
	require.True(t, ok)
	require.NotNil(t, token)
}
