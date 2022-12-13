package auth

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/errors"
	"github.com/descope/go-sdk/descope/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getProjectAndJwt(r *http.Request) (string, string) {
	var projectID, jwt string
	reqToken := r.Header.Get(api.AuthorizationHeaderName)
	if splitToken := strings.Split(reqToken, api.BearerAuthorizationPrefix); len(splitToken) == 2 {
		bearer := splitToken[1]
		bearers := strings.Split(bearer, ":")
		projectID = bearers[0]
		if len(bearers) > 1 {
			jwt = bearers[1]
		}
	}
	return projectID, jwt
}

func TestSignInMagicLinkEmptyExternalID(t *testing.T) {
	email := ""
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	err = a.MagicLink().SignIn(MethodEmail, email, "", nil, nil)
	require.Error(t, err)
	assert.EqualValues(t, errors.BadRequestErrorCode, err.(*errors.WebError).Code)

	err = a.MagicLink().SignIn(MethodEmail, email, "http://test.me", nil, nil)
	require.Error(t, err)
	assert.EqualValues(t, errors.BadRequestErrorCode, err.(*errors.WebError).Code)
}

func TestSignInMagicLinkStepupNoJWT(t *testing.T) {
	email := "e@e.com"
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	err = a.MagicLink().SignIn(MethodEmail, email, "", nil, &LoginOptions{Stepup: true})
	require.Error(t, err)
	assert.ErrorIs(t, err, errors.InvalidStepupJwtError)
}

func TestSignInMagicLinkEmail(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"

	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeMagicLinkSignInURL(MethodEmail), r.URL.RequestURI())
		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, body["externalId"])
		assert.EqualValues(t, uri, body["URI"])
	}))
	require.NoError(t, err)
	err = a.MagicLink().SignIn(MethodEmail, email, uri, nil, nil)
	require.NoError(t, err)
}

func TestSignInMagicLinkEmailLoginOptions(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"

	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeMagicLinkSignInURL(MethodEmail), r.URL.RequestURI())
		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, body["externalId"])
		assert.EqualValues(t, uri, body["URI"])
		assert.EqualValues(t, map[string]interface{}{"stepup": true, "customClaims": map[string]interface{}{"k1": "v1"}}, body["loginOptions"])
		reqToken := r.Header.Get(api.AuthorizationHeaderName)
		splitToken := strings.Split(reqToken, api.BearerAuthorizationPrefix)
		require.Len(t, splitToken, 2)
		bearer := splitToken[1]
		bearers := strings.Split(bearer, ":")
		require.Len(t, bearers, 2)
		assert.EqualValues(t, "test", bearers[1])
	}))
	require.NoError(t, err)
	err = a.MagicLink().SignIn(MethodEmail, email, uri, &http.Request{Header: http.Header{"Cookie": []string{"DSR=test"}}}, &LoginOptions{Stepup: true, CustomClaims: map[string]interface{}{"k1": "v1"}})
	require.NoError(t, err)
}

func TestSignInMagicLinkEmailLoginOptionsMFA(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"

	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeMagicLinkSignInURL(MethodEmail), r.URL.RequestURI())
		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, body["externalId"])
		assert.EqualValues(t, uri, body["URI"])
		assert.EqualValues(t, map[string]interface{}{"mfa": true, "customClaims": map[string]interface{}{"k1": "v1"}}, body["loginOptions"])
		reqToken := r.Header.Get(api.AuthorizationHeaderName)
		splitToken := strings.Split(reqToken, api.BearerAuthorizationPrefix)
		require.Len(t, splitToken, 2)
		bearer := splitToken[1]
		bearers := strings.Split(bearer, ":")
		require.Len(t, bearers, 2)
		assert.EqualValues(t, "test", bearers[1])
	}))
	require.NoError(t, err)
	err = a.MagicLink().SignIn(MethodEmail, email, uri, &http.Request{Header: http.Header{"Cookie": []string{"DSR=test"}}}, &LoginOptions{MFA: true, CustomClaims: map[string]interface{}{"k1": "v1"}})
	require.NoError(t, err)
}

func TestInvalidPhoneSignUpSMS(t *testing.T) {
	phone := "thisisemail@af.com"
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	err = a.MagicLink().SignUp(MethodSMS, phone, "", &User{Name: "test"})
	require.Error(t, err)
	assert.EqualValues(t, errors.BadRequestErrorCode, err.(*errors.WebError).Code)

	err = a.MagicLink().SignUp(MethodSMS, phone, "http://test.me", &User{Name: "test"})
	require.Error(t, err)
	assert.EqualValues(t, errors.BadRequestErrorCode, err.(*errors.WebError).Code)
}

func TestInvalidPhoneSignUpWhatsApp(t *testing.T) {
	phone := "thisisemail@af.com"
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	err = a.MagicLink().SignUp(MethodSMS, phone, "", &User{Name: "test"})
	require.Error(t, err)
	assert.EqualValues(t, errors.BadRequestErrorCode, err.(*errors.WebError).Code)

	err = a.MagicLink().SignUp(MethodSMS, phone, "http://test.me", &User{Name: "test"})
	require.Error(t, err)
	assert.EqualValues(t, errors.BadRequestErrorCode, err.(*errors.WebError).Code)
}

func TestInvalidEmailSignUpEmail(t *testing.T) {
	email := "943248329844"
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	err = a.MagicLink().SignUp(MethodEmail, email, "", &User{Name: "test"})
	require.Error(t, err)
	assert.EqualValues(t, errors.BadRequestErrorCode, err.(*errors.WebError).Code)

	err = a.MagicLink().SignUp(MethodEmail, email, "http://test.me", &User{Name: "test"})
	require.Error(t, err)
	assert.EqualValues(t, errors.BadRequestErrorCode, err.(*errors.WebError).Code)
}

func TestSignUpMagicLinkEmail(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeMagicLinkSignUpURL(MethodEmail), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["email"])
		assert.EqualValues(t, uri, m["URI"])
		assert.EqualValues(t, email, m["externalId"])
		assert.EqualValues(t, "test", m["user"].(map[string]interface{})["name"])
	}))
	require.NoError(t, err)
	err = a.MagicLink().SignUp(MethodEmail, email, uri, &User{Name: "test"})
	require.NoError(t, err)
}

func TestSignUpMagicLinkEmailNoUser(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeMagicLinkSignUpURL(MethodEmail), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["email"])
		assert.EqualValues(t, uri, m["URI"])
		assert.EqualValues(t, email, m["externalId"])
		assert.EqualValues(t, email, m["user"].(map[string]interface{})["email"])
	}))
	require.NoError(t, err)
	err = a.MagicLink().SignUp(MethodEmail, email, uri, nil)
	require.NoError(t, err)
}

func TestSignUpOrInMagicLinkEmail(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeMagicLinkSignUpOrInURL(MethodEmail), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["externalId"])
		assert.EqualValues(t, uri, m["URI"])
		assert.Nil(t, m["user"])
	}))
	require.NoError(t, err)
	err = a.MagicLink().SignUpOrIn(MethodEmail, email, uri)
	require.NoError(t, err)
}

func TestSignUpOrInMagicLinkNoIdentifier(t *testing.T) {
	uri := "http://test.me"
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	err = a.MagicLink().SignUpOrIn(MethodSMS, "", uri)
	require.Error(t, err)
}

func TestSignUpOrInMagicLinkSMS(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeMagicLinkSignUpOrInURL(MethodSMS), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["externalId"])
		assert.EqualValues(t, uri, m["URI"])
		assert.Nil(t, m["user"])
	}))
	require.NoError(t, err)
	err = a.MagicLink().SignUpOrIn(MethodSMS, email, uri)
	require.NoError(t, err)
}

func TestSignUpOrInMagicLinkWhatsapp(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeMagicLinkSignUpOrInURL(MethodWhatsApp), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["externalId"])
		assert.EqualValues(t, uri, m["URI"])
		assert.Nil(t, m["user"])
	}))
	require.NoError(t, err)
	err = a.MagicLink().SignUpOrIn(MethodWhatsApp, email, uri)
	require.NoError(t, err)
}

func TestSignUpMagicLinkSMS(t *testing.T) {
	phone := "943248329844"
	uri := "http://test.me"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeMagicLinkSignUpURL(MethodSMS), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, body["phone"])
		assert.EqualValues(t, uri, body["URI"])
		assert.EqualValues(t, phone, body["externalId"])
		assert.EqualValues(t, "test", body["user"].(map[string]interface{})["name"])
	}))
	require.NoError(t, err)
	err = a.MagicLink().SignUp(MethodSMS, phone, uri, &User{Name: "test"})
	require.NoError(t, err)
}

func TestSignUpMagicLinkWhatsApp(t *testing.T) {
	phone := "943248329844"
	uri := "http://test.me"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeMagicLinkSignUpURL(MethodWhatsApp), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, body["whatsapp"])
		assert.EqualValues(t, uri, body["URI"])
		assert.EqualValues(t, phone, body["externalId"])
		assert.EqualValues(t, "test", body["user"].(map[string]interface{})["name"])
	}))
	require.NoError(t, err)
	err = a.MagicLink().SignUp(MethodWhatsApp, phone, uri, &User{Name: "test"})
	require.NoError(t, err)
}

func TestVerifyMagicLinkCodeWithSession(t *testing.T) {
	token := "4444"
	firstSeen := true
	name := "name"
	phone := "+11111111111"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeVerifyMagicLinkURL(), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, token, body["token"])
		resp := &JWTResponse{
			RefreshJwt: jwtTokenValid,
			User: &UserResponse{
				User: User{
					Name:  name,
					Phone: phone,
				},
			},
			FirstSeen: firstSeen,
		}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	w := httptest.NewRecorder()
	info, err := a.MagicLink().Verify(token, w)
	require.NoError(t, err)
	assert.NotEmpty(t, info.SessionToken.JWT)
	require.Len(t, w.Result().Cookies(), 0)
	authHeader := w.Header().Get(api.AuthorizationHeaderName)
	require.NotEmpty(t, authHeader)
	tokens := strings.Split(authHeader, api.BearerAuthorizationPrefix)
	require.EqualValues(t, 2, len(tokens))
	sessionJWT := tokens[1]
	assert.EqualValues(t, mockAuthSessionCookie.Value, sessionJWT)
	assert.True(t, info.FirstSeen)
	assert.EqualValues(t, name, info.User.Name)
	assert.EqualValues(t, phone, info.User.Phone)
}

func TestVerifyMagicLinkCodeNoSession(t *testing.T) {
	token := "4444"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeVerifyMagicLinkURL(), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, token, body["token"])
		return &http.Response{StatusCode: http.StatusOK}, nil
	})
	require.NoError(t, err)
	w := httptest.NewRecorder()
	info, err := a.MagicLink().Verify(token, w)
	require.NoError(t, err)
	assert.Empty(t, info)
}

func TestUpdateUserEmail(t *testing.T) {
	externalID := "943248329844"
	email := "test@test.com"
	uri := "https://some.url.com"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeUpdateUserEmailMagicLink(), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, externalID, body["externalId"])
		assert.EqualValues(t, email, body["email"])
		assert.EqualValues(t, uri, body["URI"])
		assert.Nil(t, body["crossDevice"])
		u, p := getProjectAndJwt(r)
		assert.NotEmpty(t, u)
		assert.NotEmpty(t, p)
	}))
	require.NoError(t, err)
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtTokenValid})
	err = a.MagicLink().UpdateUserEmail(externalID, email, uri, r)
	require.NoError(t, err)
}

func TestUpdateEmailMagicLinkFailures(t *testing.T) {
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtTokenValid})
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	err = a.MagicLink().UpdateUserEmail("", "email@email.com", "", r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "identifier"))
	err = a.MagicLink().UpdateUserEmail("id", "", "", r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "email"))
	err = a.MagicLink().UpdateUserEmail("id", "email", "", r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "email"))
}

func TestUpdateUserPhone(t *testing.T) {
	externalID := "943248329844"
	phone := "+111111111111"
	uri := "https://some.url.com"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeUpdateUserPhoneMagiclink(MethodSMS), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, externalID, body["externalId"])
		assert.EqualValues(t, phone, body["phone"])
		assert.EqualValues(t, uri, body["URI"])
		assert.Nil(t, body["crossDevice"])
		u, p := getProjectAndJwt(r)
		assert.NotEmpty(t, u)
		assert.NotEmpty(t, p)
	}))
	require.NoError(t, err)
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtTokenValid})
	err = a.MagicLink().UpdateUserPhone(MethodSMS, externalID, phone, uri, r)
	require.NoError(t, err)
}

func TestUpdatePhoneMagicLinkFailures(t *testing.T) {
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtTokenValid})
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	err = a.MagicLink().UpdateUserPhone(MethodSMS, "", "+1111111111", "", r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "identifier"))
	err = a.MagicLink().UpdateUserPhone(MethodSMS, "id", "", "", r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "phone"))
	err = a.MagicLink().UpdateUserPhone(MethodSMS, "id", "phone", "", r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "phone"))
	err = a.MagicLink().UpdateUserPhone(MethodEmail, "id", "+1111111111", "", r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "method"))
	r = &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: "somename", Value: jwtTokenValid})
	err = a.MagicLink().UpdateUserPhone(MethodSMS, "id", "+111111111111", "", r)
	assert.Error(t, err)
	assert.ErrorIs(t, err, errors.RefreshTokenError)
}
