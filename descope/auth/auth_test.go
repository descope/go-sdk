package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/errors"
	"github.com/descope/go-sdk/descope/tests/mocks"
	"github.com/descope/go-sdk/descope/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	jwtTokenValid    = `eyJhbGciOiJFUzM4NCIsImtpZCI6InRlc3RrZXkiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOlsidGVzdCJdLCJkcm4iOiJEUyIsImV4cCI6MzY1OTU2MTQzMCwiaWF0IjoxNjU5NTYxNDMwLCJpc3MiOiJ0ZXN0Iiwic3ViIjoic29tZXVzZXIiLCJ0ZXN0IjoidGVzdCJ9.tE6hXIuH74drymm6DSAs4FkaQSzf3MQ0D7pjC-9SaBRnqHoRuDOIJd3mIRsxzfb2nS6NX_tk6H1na6kFEKsJdMsUG-LbCqqib98z9tHtq-Jh6Axl5Qe9RITfIOwzOssw`
	jwtRTokenValid   = `eyJhbGciOiJFUzM4NCIsImtpZCI6InRlc3RrZXkiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOlsidGVzdCJdLCJkcm4iOiJEU1IiLCJleHAiOjM2NTk1NjE0MzAsImlhdCI6MTY1OTU2MTQzMCwiaXNzIjoidGVzdCIsInN1YiI6InNvbWV1c2VyIiwidGVzdCI6InRlc3QifQ.zKbJKuGo9Q9NsvI_SdrH1pDH8uuTRnTcT4eMJe237Lr6ZrtRGbw2a0U0aEwgNrox2RXupkmD3vfQtZiD3AiU9xHY8X3xwTGsDwA497eT6RrA13zNufrhSMNjF6V5-xVl`
	jwtTokenExpired  = `eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCIsImtpZCI6ImU0YTU3Y2M5ZGZiNDAyYTNlNTNjNDJhNjQyMmY3M2FmIn0.eyJjb29raWVOYW1lIjoiRFMiLCJleHAiOjEyNTYyNTg2OTF9.AvU50pkQt8F000JqpVy7vCbcV-pwGqyi_GENqmmqrRMVswk5Y5VfSjP7axBnZ55xJ85sP6ozawbs_g1FdGtzvgrHEIJVRJSe73EwWTV9yZwiUD8kU-QAtUqP_Vk-rf-3zzE1lmI3DubXZYGTE4tMUsIQ-2NI3-Q9R89yzjLMv9z7_0TaDB28LMCJPlmjTA-7x_FoWqxmCs0z00dZ6sthtppbo25DiO3EW7D35gE1CPOgITjktWSRt035TR0iV91YoPyPAkmEo3mxI4XXu-1fLcZdFFTZOOU4TmA-_wbXevf0kIaQ9Kl4jPEK9lSUHEhLG59nu_0aPVxUXqE-Y8Qo7Ed-Gri5fPhZarDtMRRpVc1pc7D8zYMyKEHvCqkdjV9MDfIK3eCVuCGUxytgEe4Px-sgPSS_7Ne8hZ1T7K3TbcoMlRl--fI6rbmcOj-2srCcofr9NX2pxeUdWU8g6ZfFFxADSfJNb0MbZz55QGN8yz-54jZR3nT7i7kXX0ylrDQw`
	jwtTokenNotYet   = `eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCIsImtpZCI6ImU0YTU3Y2M5ZGZiNDAyYTNlNTNjNDJhNjQyMmY3M2FmIn0.eyJjb29raWVOYW1lIjoiRFMiLCJuYmYiOjI2NTYyNTg2OTF9.dvkNfmyUgbhlwv2eW_qC8VfcKYaMKaS8aDM2XdgYxnLuOhQUNnlY87H8bQGw7RChvqyJtciFo74KFhTZkAWqKDpdisIPDnydJ7SzY-NOv6Mtg0DAl99nDuItsYDoSIHVV_3h6feZC353ziQIEoktPf9dnyYpN0IumGMg-g5ww7foDglpwbIP9c6SxxDIOIMh5fGlT7tG79-i_QJ3zsDuYo0v8aNFd7QcP5tA8Kj9Tthp2pHTacu0WDSq39p6XEvDaKiLRhhVOfyd_jTTC2xzmkXRzt2KOy1ObRvhOiItQCoISn66QO4dm8febSagA2_GtDd1VYxwT0zW7usK4CwKfoSej_UMp-BZZ8Q1fDqMWfG9qWjeinfty7ePQwV2Y_kiNCjyTvKlbPnTINL_VXemb0pIaAITfROlzWtXGGnP3soFczgWe4WXC_Q7wx3uCkyN5BIKLajxCF3EAfPzDi7YbYnQXEk-imGoqWpYXw0SXMkYo2wkd9Qul4uXH_mGh50l`
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

	jwtTokenWithTenants  = "eyJhbGciOiJFUzM4NCIsImtpZCI6InRlc3RrZXkiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOlsidGVzdCJdLCJkcm4iOiJEUyIsImV4cCI6MzY2MDIyMzc1OSwiaWF0IjoxNjYwMjIzNzU5LCJpc3MiOiJ0ZXN0Iiwic3ViIjoic29tZXVzZXIiLCJ0ZW5hbnRzIjp7InQxIjp7fSwidDIiOnt9fX0.sIa7U18_h772xYpyFCjOXtsBtMtwWBoFNmDA-Bc-hmWciQC_5-sndtwLdaJD77t2wkoq3wAbjp6jcL1-qBSNZ6pueMdO02IbGK-mkmC439UhdQ7xs7jQXziHstMBaHT5"
	publicKeyWithTenants = `{"alg":"ES384","crv":"P-384","kid":"testkey","kty":"EC","use":"sig","x":"Ov545bC4GMh_YPMF_rHzpi2iuLk4wmQsSN_HiCS_-e1TOp2zrPPOVzjIaGWk-S4u","y":"uzQM6ROnewL6UhYkV7FNH-0sXRj3QqoaKsQmclzJSad8oYw9Q7czRDfGa0dWo7r6"}`
)

var (
	mockAuthSessionCookie        = &http.Cookie{Value: jwtTokenValid, Name: SessionCookieName}
	mockAuthRefreshCookie        = &http.Cookie{Value: jwtTokenValid, Name: RefreshCookieName}
	mockAuthInvalidSessionCookie = &http.Cookie{Value: jwtTokenExpired, Name: SessionCookieName}
	mockAuthInvalidRefreshCookie = &http.Cookie{Value: jwtTokenExpired, Name: RefreshCookieName}

	mockAuthSessionBody = fmt.Sprintf(`{"sessionJwt": "%s", "refreshJwt": "%s", "cookiePath": "%s", "cookieDomain": "%s" }`, jwtTokenValid, jwtRTokenValid, "/my-path", "my-domain")

	mockUserResponseBody = fmt.Sprintf(`{"name": "%s", "email": "%s", "userId": "%s", "picture": "%s"}`, "kuku name", "kuku@test.com", "kuku", "@(^_^)@")

	permissions                  = []interface{}{"foo", "bar"}
	roles                        = []interface{}{"abc", "xyz"}
	mockAuthorizationToken       = &Token{Claims: map[string]any{claimPermissions: permissions, claimRoles: roles}}
	mockAuthorizationTenantToken = &Token{Claims: map[string]any{ClaimAuthorizedTenants: map[string]any{"kuku": mockAuthorizationToken.Claims}}}
)

func readBodyMap(r *http.Request) (m map[string]interface{}, err error) {
	m = map[string]interface{}{}
	err = readBody(r, &m)
	return m, err
}

func readBody(r *http.Request, m interface{}) (err error) {
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
		b, err := utils.Marshal(map[string]interface{}{"error": errors.NewInvalidArgumentError("test")})
		if err != nil {
			return nil, err
		}
		res := &http.Response{StatusCode: http.StatusBadRequest, Body: io.NopCloser(bytes.NewBuffer(b))}
		return res, nil
	}
}

func DoOkWithBody(checks func(*http.Request), body interface{}) mocks.Do {
	return func(r *http.Request) (*http.Response, error) {
		if checks != nil {
			checks(r)
		}

		b, err := utils.Marshal(body)
		if err != nil {
			return nil, err
		}
		res := &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(b))}
		return res, nil
	}
}

func DoRedirect(url string, checks func(*http.Request)) mocks.Do {
	return DoOkWithBody(checks, map[string]interface{}{"url": url})
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
	return NewAuth(*authParams, api.NewClient(*clientParams))
}

func TestVerifyDeliveryMethod(t *testing.T) {
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	err = a.verifyDeliveryMethod(MethodEmail, "", &User{})
	assert.EqualValues(t, errors.BadRequestErrorCode, err.(*errors.WebError).Code)

	err = a.verifyDeliveryMethod(MethodSMS, "abc@notaphone.com", &User{})
	assert.EqualValues(t, errors.BadRequestErrorCode, err.(*errors.WebError).Code)

	u := &User{}
	err = a.verifyDeliveryMethod(MethodEmail, "abc@notaphone.com", u)
	assert.Nil(t, err)
	assert.NotEmpty(t, u.Email)

	u = &User{Email: "abc@notaphone.com"}
	err = a.verifyDeliveryMethod(MethodEmail, "my username", u)
	assert.Nil(t, err)

	u = &User{}
	err = a.verifyDeliveryMethod(MethodSMS, "+19999999999", u)
	assert.Nil(t, err)
	assert.NotEmpty(t, u.Phone)

	u = &User{Phone: "+19999999999"}
	err = a.verifyDeliveryMethod(MethodSMS, "my username", u)
	assert.Nil(t, err)
}

func TestAuthDefaultURL(t *testing.T) {
	url := "http://test.com"
	a, err := newTestAuthConf(nil, &api.ClientParams{BaseURL: url}, DoOk(func(r *http.Request) {
		assert.Contains(t, r.URL.String(), url)
	}))
	require.NoError(t, err)
	_, err = a.OTP().VerifyCode(MethodWhatsApp, "4444", "444", nil)
	require.NoError(t, err)
}

func TestEmptyPublicKey(t *testing.T) {
	a, err := newTestAuthConf(&AuthParams{ProjectID: "a"}, nil, mocks.Do(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("[]"))}, nil
	}))
	require.NoError(t, err)
	ok, _, err := a.validateSession(jwtTokenExpired, "", false, nil)
	require.False(t, ok)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no public key was found")
}

func TestErrorFetchPublicKey(t *testing.T) {
	a, err := newTestAuthConf(&AuthParams{ProjectID: "a"}, nil, mocks.Do(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusInternalServerError, Body: io.NopCloser(strings.NewReader("what"))}, nil
	}))
	require.NoError(t, err)
	ok, _, err := a.validateSession(jwtTokenExpired, "", false, nil)
	require.False(t, ok)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no public key was found")
}

func TestValidateSession(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	ok, _, err := a.validateSession(jwtTokenValid, "", false, nil)
	require.NoError(t, err)
	require.True(t, ok)
	ok, _, err = a.validateSession(jwtTokenValid, "", false, nil)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestValidateSessionTokens(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	ok, _, err := a.ValidateSessionTokens(jwtTokenValid, "")
	require.NoError(t, err)
	require.True(t, ok)
	ok, _, _ = a.ValidateSessionTokens(jwtTokenExpired, "")
	require.False(t, ok)
}

func TestValidateSessionFetchKeyCalledOnce(t *testing.T) {
	count := 0
	a, err := newTestAuthConf(&AuthParams{ProjectID: "a"}, nil, mocks.Do(func(r *http.Request) (*http.Response, error) {
		count++
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{"keys":[%s]}`, publicKey)))}, nil
	}))
	require.NoError(t, err)
	ok, _, err := a.validateSession(jwtTokenValid, "", false, nil)
	require.NoError(t, err)
	require.True(t, ok)
	require.EqualValues(t, 1, count)
	ok, _, err = a.validateSession(jwtTokenValid, "", false, nil)
	require.NoError(t, err)
	require.True(t, ok)
	require.EqualValues(t, 1, count)
}

func TestValidateSessionFetchKeyMalformed(t *testing.T) {
	a, err := newTestAuthConf(&AuthParams{ProjectID: "a"}, nil, mocks.Do(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{"keys":[%s]}`, unknownPublicKey)))}, nil
	}))
	require.NoError(t, err)
	ok, _, err := a.validateSession(jwtTokenValid, jwtTokenValid, false, nil)
	require.Error(t, err)
	assert.EqualValues(t, errors.BadRequestErrorCode, err.(*errors.WebError).Code)
	require.False(t, ok)
}

func TestValidateSessionFailWithInvalidKey(t *testing.T) {
	count := 0
	a, err := newTestAuthConf(&AuthParams{PublicKey: unknownPublicKey}, nil, mocks.Do(func(r *http.Request) (*http.Response, error) {
		count++
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(fmt.Sprintf("[%s]", publicKey)))}, nil
	}))
	require.NoError(t, err)
	ok, _, err := a.validateSession(jwtTokenValid, "", false, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "key provider 0 failed")
	require.False(t, ok)
	require.Zero(t, count)
}

func TestValidateSessionRequest(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: jwtTokenValid})
	ok, token, err := a.ValidateSession(request, nil)
	require.NoError(t, err)
	require.True(t, ok)
	require.EqualValues(t, jwtTokenValid, token.JWT)
}

func TestValidateSessionRequestHeader(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.Header.Add(api.AuthorizationHeaderName, api.BearerAuthorizationPrefix+jwtTokenValid)
	ok, token, err := a.ValidateSession(request, nil)
	require.NoError(t, err)
	require.True(t, ok)
	require.EqualValues(t, jwtTokenValid, token.JWT)
}

func TestValidateSessionRequestMissingCookie(t *testing.T) {
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(mockAuthSessionBody))}, nil
	})
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtRTokenValid})
	ok, token, err := a.ValidateSession(request, nil)
	require.NoError(t, err)
	require.True(t, ok)
	require.NotEmpty(t, token)
}

func TestValidateSessionRequestMissingBothCookies(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	ok, token, err := a.ValidateSession(request, nil)
	require.NoError(t, err)
	require.False(t, ok)
	require.Empty(t, token)
}

func TestValidateSessionRequestRefreshSession(t *testing.T) {
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(mockAuthSessionBody))}, nil
	})
	a.conf.SessionJWTViaCookie = true
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtRTokenValid})
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: jwtTokenExpired})

	b := httptest.NewRecorder()
	ok, userToken, err := a.ValidateSession(request, b)
	require.NoError(t, err)
	require.True(t, ok)
	assert.EqualValues(t, mockAuthSessionCookie.Value, userToken.JWT)
	require.Len(t, b.Result().Cookies(), 2)
	sessionCookie := b.Result().Cookies()[0]
	require.NoError(t, err)
	assert.EqualValues(t, mockAuthSessionCookie.Value, sessionCookie.Value)
}

func TestValidateSessionRequestMissingSessionToken(t *testing.T) {
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(mockAuthSessionBody))}, nil
	})
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtRTokenValid})

	b := httptest.NewRecorder()
	ok, userToken, err := a.ValidateSession(request, b)
	require.NoError(t, err)
	require.True(t, ok)
	assert.EqualValues(t, mockAuthSessionCookie.Value, userToken.JWT)
	require.Len(t, b.Result().Cookies(), 1) // Only the refresh token
}

func TestValidateSessionRequestFailRefreshSession(t *testing.T) {
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusInternalServerError}, nil
	})
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtRTokenValid})
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: jwtTokenExpired})
	ok, cookies, err := a.ValidateSession(request, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, errors.FailedToRefreshTokenError)
	require.False(t, ok)
	require.Empty(t, cookies)
}

func TestValidateSessionRequestNoCookie(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	ok, cookies, err := a.ValidateSession(request, nil)
	require.NoError(t, err)
	require.False(t, ok)
	require.Empty(t, cookies)
}

func TestValidateSessionExpired(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	ok, _, err := a.validateSession(jwtTokenExpired, jwtTokenExpired, false, nil)
	require.Error(t, err)
	require.False(t, ok)
	assert.EqualValues(t, errors.BadRequestErrorCode, err.(*errors.WebError).Code)
}

func TestValidateSessionNoProvider(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	ok, _, err := a.ValidateSession(nil, nil)
	require.Error(t, err)
	require.ErrorIs(t, err, errors.MissingProviderError)
	require.False(t, ok)
}

func TestValidateSessionNotYet(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	ok, _, err := a.validateSession(jwtTokenNotYet, jwtTokenNotYet, false, nil)
	require.Error(t, err)
	require.False(t, ok)
	assert.EqualValues(t, errors.BadRequestErrorCode, err.(*errors.WebError).Code)
}

func TestRefreshSessionRequestRefreshSession(t *testing.T) {
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(mockAuthSessionBody))}, nil
	})
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtRTokenValid})
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: jwtTokenExpired})

	b := httptest.NewRecorder()
	ok, userToken, err := a.RefreshSession(request, b)
	require.NoError(t, err)
	require.True(t, ok)
	assert.EqualValues(t, mockAuthSessionCookie.Value, userToken.JWT)
	require.Len(t, b.Result().Cookies(), 1) // Just the refresh token
}

func TestRefreshSessionNoRequest(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	ok, token, err := a.RefreshSession(nil, nil)
	assert.Error(t, err)
	assert.False(t, ok)
	assert.Nil(t, token)
}

func TestRefreshSessionNoToken(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	ok, token, err := a.RefreshSession(request, nil)
	assert.NoError(t, err)
	assert.False(t, ok)
	assert.Nil(t, token)
}

func TestLogout(t *testing.T) {
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(mockAuthSessionBody))}, nil
	})
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtRTokenValid})

	w := httptest.NewRecorder()
	err = a.Logout(request, w)
	require.NoError(t, err)
	require.Len(t, w.Result().Cookies(), 2)
	c1 := w.Result().Cookies()[0]
	assert.Empty(t, c1.Value)
	assert.EqualValues(t, SessionCookieName, c1.Name)
	assert.EqualValues(t, "/my-path", c1.Path)
	assert.EqualValues(t, "my-domain", c1.Domain)
	c2 := w.Result().Cookies()[1]
	assert.Empty(t, c2.Value)
	assert.EqualValues(t, RefreshCookieName, c2.Name)
	assert.EqualValues(t, "/my-path", c2.Path)
	assert.EqualValues(t, "my-domain", c2.Domain)
}

func TestLogoutAll(t *testing.T) {
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(mockAuthSessionBody))}, nil
	})
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtRTokenValid})

	w := httptest.NewRecorder()
	err = a.LogoutAll(request, w)
	require.NoError(t, err)
	require.Len(t, w.Result().Cookies(), 2)
	c1 := w.Result().Cookies()[0]
	assert.Empty(t, c1.Value)
	assert.EqualValues(t, SessionCookieName, c1.Name)
	assert.EqualValues(t, "/my-path", c1.Path)
	assert.EqualValues(t, "my-domain", c1.Domain)
	c2 := w.Result().Cookies()[1]
	assert.Empty(t, c2.Value)
	assert.EqualValues(t, RefreshCookieName, c2.Name)
	assert.EqualValues(t, "/my-path", c2.Path)
	assert.EqualValues(t, "my-domain", c2.Domain)
}

func TestLogoutNoClaims(t *testing.T) {
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK}, nil
	})
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtRTokenValid})

	w := httptest.NewRecorder()
	err = a.Logout(request, w)
	require.NoError(t, err)
	require.Len(t, w.Result().Cookies(), 2)
	c1 := w.Result().Cookies()[0]
	assert.Empty(t, c1.Value)
	assert.EqualValues(t, SessionCookieName, c1.Name)
	assert.EqualValues(t, "/", c1.Path)
	assert.EqualValues(t, "", c1.Domain)
	c2 := w.Result().Cookies()[1]
	assert.Empty(t, c2.Value)
	assert.EqualValues(t, RefreshCookieName, c2.Name)
	assert.EqualValues(t, "/", c2.Path)
	assert.EqualValues(t, "", c2.Domain)
}

func TestLogoutAllNoClaims(t *testing.T) {
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK}, nil
	})
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtRTokenValid})

	w := httptest.NewRecorder()
	err = a.LogoutAll(request, w)
	require.NoError(t, err)
	require.Len(t, w.Result().Cookies(), 2)
	c1 := w.Result().Cookies()[0]
	assert.Empty(t, c1.Value)
	assert.EqualValues(t, SessionCookieName, c1.Name)
	assert.EqualValues(t, "/", c1.Path)
	assert.EqualValues(t, "", c1.Domain)
	c2 := w.Result().Cookies()[1]
	assert.Empty(t, c2.Value)
	assert.EqualValues(t, RefreshCookieName, c2.Name)
	assert.EqualValues(t, "/", c2.Path)
	assert.EqualValues(t, "", c2.Domain)
}

func TestLogoutFailure(t *testing.T) {
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadGateway}, nil
	})
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtRTokenValid})

	err = a.Logout(request, nil)
	require.Error(t, err)
}

func TestLogoutAllFailure(t *testing.T) {
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadGateway}, nil
	})
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtRTokenValid})

	err = a.LogoutAll(request, nil)
	require.Error(t, err)
}

func TestLogoutInvalidRefreshToken(t *testing.T) {
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtTokenExpired})

	err = a.Logout(request, nil)
	require.Error(t, err)
}

func TestLogoutAllInvalidRefreshToken(t *testing.T) {
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtTokenExpired})

	err = a.LogoutAll(request, nil)
	require.Error(t, err)
}

func TestLogoutEmptyRequest(t *testing.T) {
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadGateway}, nil
	})
	require.NoError(t, err)

	err = a.Logout(nil, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, errors.MissingRequestError)
}

func TestLogoutAllEmptyRequest(t *testing.T) {
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadGateway}, nil
	})
	require.NoError(t, err)

	err = a.LogoutAll(nil, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, errors.MissingRequestError)
}

func TestLogoutMissingToken(t *testing.T) {
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadGateway}, nil
	})
	require.NoError(t, err)

	request := &http.Request{Header: http.Header{}}
	err = a.Logout(request, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, errors.RefreshTokenError)
}

func TestLogoutAllMissingToken(t *testing.T) {
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadGateway}, nil
	})
	require.NoError(t, err)

	request := &http.Request{Header: http.Header{}}
	err = a.LogoutAll(request, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, errors.RefreshTokenError)
}

func TestAuthenticationMiddlewareFailure(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	handlerToTest := AuthenticationMiddleware(a, func(w http.ResponseWriter, r *http.Request, err error) {
		assert.EqualValues(t, errors.BadRequestErrorCode, err.(*errors.WebError).Code)
		w.WriteHeader(http.StatusBadGateway)
	}, nil)(nil)

	req := httptest.NewRequest("GET", "http://testing", nil)
	req.AddCookie(mockAuthInvalidSessionCookie)
	req.AddCookie(mockAuthInvalidRefreshCookie)

	res := httptest.NewRecorder()
	handlerToTest.ServeHTTP(res, req)
	assert.EqualValues(t, http.StatusBadGateway, res.Result().StatusCode)
}

func TestAuthenticationMiddlewareFailureDefault(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	handlerToTest := AuthenticationMiddleware(a, nil, nil)(nil)

	req := httptest.NewRequest("GET", "http://testing", nil)

	res := httptest.NewRecorder()
	handlerToTest.ServeHTTP(res, req)

	assert.EqualValues(t, http.StatusUnauthorized, res.Result().StatusCode)
}

func TestAuthenticationMiddlewareSuccessDefault(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	handlerToTest := AuthenticationMiddleware(a, nil, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, ok := r.Context().Value(ContextUserIDPropertyKey).(string)
		require.True(t, ok)
		assert.EqualValues(t, "someuser", s)
		w.WriteHeader(http.StatusTeapot)
	}))

	req := httptest.NewRequest("GET", "http://testing", nil)
	req.AddCookie(mockAuthSessionCookie)
	req.AddCookie(mockAuthRefreshCookie)

	res := httptest.NewRecorder()
	handlerToTest.ServeHTTP(res, req)
	assert.EqualValues(t, http.StatusTeapot, res.Result().StatusCode)
}

func TestAuthenticationMiddlewareSuccess(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	handlerToTest := AuthenticationMiddleware(a, nil, func(w http.ResponseWriter, r *http.Request, next http.Handler, token *Token) {
		assert.EqualValues(t, "someuser", token.ID)
		next.ServeHTTP(w, r)
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))

	req := httptest.NewRequest("GET", "http://testing", nil)
	req.AddCookie(mockAuthSessionCookie)
	req.AddCookie(mockAuthRefreshCookie)

	res := httptest.NewRecorder()
	handlerToTest.ServeHTTP(res, req)
	assert.EqualValues(t, http.StatusTeapot, res.Result().StatusCode)
}

func TestExtractTokensEmpty(t *testing.T) {
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	tokens, err := a.extractTokens(&JWTResponse{})
	require.NoError(t, err)
	require.Len(t, tokens, 0)
}

func TestExtractTokensInvalid(t *testing.T) {
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	tokens, err := a.extractTokens(&JWTResponse{RefreshJwt: "aaaaa"})
	require.Error(t, err)
	require.Empty(t, tokens)
}

func TestExtractJwtWithTenants(t *testing.T) {
	a, err := newTestAuthConf(&AuthParams{PublicKey: publicKeyWithTenants}, nil, nil)
	require.NoError(t, err)
	tokens, err := a.extractTokens(&JWTResponse{SessionJwt: jwtTokenWithTenants})
	require.NoError(t, err)
	require.True(t, len(tokens) > 0)
	tenants := tokens[0].GetTenants()
	assert.Len(t, tenants, 2)
	m := map[string]interface{}{"t1": true, "t2": true}
	for _, k := range tenants {
		delete(m, k)
	}
	assert.Len(t, m, 0)
}

func BenchmarkValidateSession(b *testing.B) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(b, err)

	for n := 0; n < b.N; n++ {
		_, _, _ = a.validateSession(jwtTokenValid, "", false, nil)
	}
}

func TestExchangeAccessKey(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)

	ok, token, err := a.ExchangeAccessKey("foo")
	require.NoError(t, err)
	require.True(t, ok)
	require.NotNil(t, token)
}

func TestExchangeAccessKeyBadRequest(t *testing.T) {
	a, err := newTestAuth(nil, DoBadRequest(nil))
	require.NoError(t, err)

	ok, token, err := a.ExchangeAccessKey("foo")
	require.ErrorIs(t, err, errors.UnauthorizedError)
	require.False(t, ok)
	require.Nil(t, token)
}

func TestExchangeAccessKeyEmptyResponse(t *testing.T) {
	a, err := newTestAuth(nil, DoOkWithBody(nil, ""))
	require.NoError(t, err)

	ok, token, err := a.ExchangeAccessKey("foo")
	require.ErrorIs(t, err, errors.InvalidAccessKeyResponse)
	require.False(t, ok)
	require.Nil(t, token)
}

func TestExchangeAccessKeyInvalidResponse(t *testing.T) {
	expectedResponse := JWTResponse{}
	a, err := newTestAuth(nil, DoOkWithBody(nil, expectedResponse))
	require.NoError(t, err)

	ok, token, err := a.ExchangeAccessKey("foo")
	require.ErrorIs(t, err, errors.InvalidAccessKeyResponse)
	require.False(t, ok)
	require.Nil(t, token)
}

func TestValidatePermissions(t *testing.T) {
	a, err := newTestAuth(nil, DoOkWithBody(nil, ""))
	require.NoError(t, err)

	require.True(t, a.ValidatePermissions(mockAuthorizationToken, []string{}))
	require.True(t, a.ValidatePermissions(mockAuthorizationToken, []string{"foo"}))
	require.True(t, a.ValidatePermissions(mockAuthorizationToken, []string{"foo", "bar"}))
	require.False(t, a.ValidatePermissions(mockAuthorizationToken, []string{"foo", "bar", "qux"}))

	require.True(t, a.ValidatePermissions(mockAuthorizationTenantToken, []string{}))
	require.False(t, a.ValidatePermissions(mockAuthorizationTenantToken, []string{"foo"}))
	require.False(t, a.ValidatePermissions(mockAuthorizationTenantToken, []string{"foo", "bar"}))
	require.False(t, a.ValidatePermissions(mockAuthorizationTenantToken, []string{"foo", "bar", "qux"}))

	require.True(t, a.ValidateTenantPermissions(mockAuthorizationToken, "kuku", []string{}))
	require.False(t, a.ValidateTenantPermissions(mockAuthorizationToken, "kuku", []string{"foo"}))
	require.False(t, a.ValidateTenantPermissions(mockAuthorizationToken, "kuku", []string{"foo", "bar"}))
	require.False(t, a.ValidateTenantPermissions(mockAuthorizationToken, "kuku", []string{"foo", "bar", "qux"}))

	require.True(t, a.ValidateTenantPermissions(mockAuthorizationTenantToken, "kuku", []string{}))
	require.True(t, a.ValidateTenantPermissions(mockAuthorizationTenantToken, "kuku", []string{"foo"}))
	require.True(t, a.ValidateTenantPermissions(mockAuthorizationTenantToken, "kuku", []string{"foo", "bar"}))
	require.False(t, a.ValidateTenantPermissions(mockAuthorizationTenantToken, "kuku", []string{"foo", "bar", "qux"}))
}

func TestValidateRoles(t *testing.T) {
	a, err := newTestAuth(nil, DoOkWithBody(nil, ""))
	require.NoError(t, err)

	require.True(t, a.ValidateRoles(mockAuthorizationToken, []string{}))
	require.True(t, a.ValidateRoles(mockAuthorizationToken, []string{"abc"}))
	require.True(t, a.ValidateRoles(mockAuthorizationToken, []string{"abc", "xyz"}))
	require.False(t, a.ValidateRoles(mockAuthorizationToken, []string{"abc", "xyz", "tuv"}))

	require.True(t, a.ValidateRoles(mockAuthorizationTenantToken, []string{}))
	require.False(t, a.ValidateRoles(mockAuthorizationTenantToken, []string{"abc"}))
	require.False(t, a.ValidateRoles(mockAuthorizationTenantToken, []string{"abc", "xyz"}))
	require.False(t, a.ValidateRoles(mockAuthorizationTenantToken, []string{"abc", "xyz", "tuv"}))

	require.True(t, a.ValidateTenantRoles(mockAuthorizationToken, "kuku", []string{}))
	require.False(t, a.ValidateTenantRoles(mockAuthorizationToken, "kuku", []string{"abc"}))
	require.False(t, a.ValidateTenantRoles(mockAuthorizationToken, "kuku", []string{"abc", "xyz"}))
	require.False(t, a.ValidateTenantRoles(mockAuthorizationToken, "kuku", []string{"abc", "xyz", "tuv"}))

	require.True(t, a.ValidateTenantRoles(mockAuthorizationTenantToken, "kuku", []string{}))
	require.True(t, a.ValidateTenantRoles(mockAuthorizationTenantToken, "kuku", []string{"abc"}))
	require.True(t, a.ValidateTenantRoles(mockAuthorizationTenantToken, "kuku", []string{"abc", "xyz"}))
	require.False(t, a.ValidateTenantRoles(mockAuthorizationTenantToken, "kuku", []string{"abc", "xyz", "tuv"}))
}

func TestMe(t *testing.T) {
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(mockUserResponseBody))}, nil
	})
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtRTokenValid})

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
	assert.Error(t, err)
	assert.Nil(t, user)
}

func TestMeNoToken(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	user, err := a.Me(request)
	assert.Error(t, err)
	assert.Nil(t, user)
}
