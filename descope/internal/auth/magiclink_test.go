package auth

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
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

func TestSignInMagicLinkEmptyLoginID(t *testing.T) {
	email := ""
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	err = a.MagicLink().SignIn(descope.MethodEmail, email, "", nil, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidArgument)

	err = a.MagicLink().SignIn(descope.MethodEmail, email, "http://test.me", nil, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidArgument)
}

func TestSignInMagicLinkStepupNoJWT(t *testing.T) {
	email := "e@e.com"
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	err = a.MagicLink().SignIn(descope.MethodEmail, email, "", nil, &descope.LoginOptions{Stepup: true})
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidStepUpJWT)
}

func TestSignInMagicLinkEmail(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"

	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeMagicLinkSignInURL(descope.MethodEmail), r.URL.RequestURI())
		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, body["loginId"])
		assert.EqualValues(t, uri, body["URI"])
	}))
	require.NoError(t, err)
	err = a.MagicLink().SignIn(descope.MethodEmail, email, uri, nil, nil)
	require.NoError(t, err)
}

func TestSignInMagicLinkEmailLoginOptions(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"

	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeMagicLinkSignInURL(descope.MethodEmail), r.URL.RequestURI())
		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, body["loginId"])
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
	err = a.MagicLink().SignIn(descope.MethodEmail, email, uri, &http.Request{Header: http.Header{"Cookie": []string{"DSR=test"}}}, &descope.LoginOptions{Stepup: true, CustomClaims: map[string]interface{}{"k1": "v1"}})
	require.NoError(t, err)
}

func TestSignInMagicLinkEmailLoginOptionsMFA(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"

	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeMagicLinkSignInURL(descope.MethodEmail), r.URL.RequestURI())
		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, body["loginId"])
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
	err = a.MagicLink().SignIn(descope.MethodEmail, email, uri, &http.Request{Header: http.Header{"Cookie": []string{"DSR=test"}}}, &descope.LoginOptions{MFA: true, CustomClaims: map[string]interface{}{"k1": "v1"}})
	require.NoError(t, err)
}

func TestInvalidPhoneSignUpSMS(t *testing.T) {
	phone := "thisisemail@af.com"
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	err = a.MagicLink().SignUp(descope.MethodSMS, phone, "", &descope.User{Name: "test"})
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidArgument)

	err = a.MagicLink().SignUp(descope.MethodSMS, phone, "http://test.me", &descope.User{Name: "test"})
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidArgument)
}

func TestInvalidPhoneSignUpWhatsApp(t *testing.T) {
	phone := "thisisemail@af.com"
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	err = a.MagicLink().SignUp(descope.MethodSMS, phone, "", &descope.User{Name: "test"})
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidArgument)

	err = a.MagicLink().SignUp(descope.MethodSMS, phone, "http://test.me", &descope.User{Name: "test"})
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidArgument)
}

func TestInvalidEmailSignUpEmail(t *testing.T) {
	email := "943248329844"
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	err = a.MagicLink().SignUp(descope.MethodEmail, email, "", &descope.User{Name: "test"})
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidArgument)

	err = a.MagicLink().SignUp(descope.MethodEmail, email, "http://test.me", &descope.User{Name: "test"})
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidArgument)
}

func TestSignUpMagicLinkEmail(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeMagicLinkSignUpURL(descope.MethodEmail), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["email"])
		assert.EqualValues(t, uri, m["URI"])
		assert.EqualValues(t, email, m["loginId"])
		assert.EqualValues(t, "test", m["user"].(map[string]interface{})["name"])
	}))
	require.NoError(t, err)
	err = a.MagicLink().SignUp(descope.MethodEmail, email, uri, &descope.User{Name: "test"})
	require.NoError(t, err)
}

func TestSignUpMagicLinkEmailNoUser(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeMagicLinkSignUpURL(descope.MethodEmail), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["email"])
		assert.EqualValues(t, uri, m["URI"])
		assert.EqualValues(t, email, m["loginId"])
		assert.EqualValues(t, email, m["user"].(map[string]interface{})["email"])
	}))
	require.NoError(t, err)
	err = a.MagicLink().SignUp(descope.MethodEmail, email, uri, nil)
	require.NoError(t, err)
}

func TestSignUpOrInMagicLinkEmail(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeMagicLinkSignUpOrInURL(descope.MethodEmail), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["loginId"])
		assert.EqualValues(t, uri, m["URI"])
		assert.Nil(t, m["user"])
	}))
	require.NoError(t, err)
	err = a.MagicLink().SignUpOrIn(descope.MethodEmail, email, uri)
	require.NoError(t, err)
}

func TestSignUpOrInMagicLinkNoLoginID(t *testing.T) {
	uri := "http://test.me"
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	err = a.MagicLink().SignUpOrIn(descope.MethodSMS, "", uri)
	require.Error(t, err)
}

func TestSignUpOrInMagicLinkSMS(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeMagicLinkSignUpOrInURL(descope.MethodSMS), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["loginId"])
		assert.EqualValues(t, uri, m["URI"])
		assert.Nil(t, m["user"])
	}))
	require.NoError(t, err)
	err = a.MagicLink().SignUpOrIn(descope.MethodSMS, email, uri)
	require.NoError(t, err)
}

func TestSignUpOrInMagicLinkWhatsapp(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeMagicLinkSignUpOrInURL(descope.MethodWhatsApp), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["loginId"])
		assert.EqualValues(t, uri, m["URI"])
		assert.Nil(t, m["user"])
	}))
	require.NoError(t, err)
	err = a.MagicLink().SignUpOrIn(descope.MethodWhatsApp, email, uri)
	require.NoError(t, err)
}

func TestSignUpMagicLinkSMS(t *testing.T) {
	phone := "943248329844"
	uri := "http://test.me"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeMagicLinkSignUpURL(descope.MethodSMS), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, body["phone"])
		assert.EqualValues(t, uri, body["URI"])
		assert.EqualValues(t, phone, body["loginId"])
		assert.EqualValues(t, "test", body["user"].(map[string]interface{})["name"])
	}))
	require.NoError(t, err)
	err = a.MagicLink().SignUp(descope.MethodSMS, phone, uri, &descope.User{Name: "test"})
	require.NoError(t, err)
}

func TestSignUpMagicLinkWhatsApp(t *testing.T) {
	phone := "943248329844"
	uri := "http://test.me"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeMagicLinkSignUpURL(descope.MethodWhatsApp), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, body["whatsapp"])
		assert.EqualValues(t, uri, body["URI"])
		assert.EqualValues(t, phone, body["loginId"])
		assert.EqualValues(t, "test", body["user"].(map[string]interface{})["name"])
	}))
	require.NoError(t, err)
	err = a.MagicLink().SignUp(descope.MethodWhatsApp, phone, uri, &descope.User{Name: "test"})
	require.NoError(t, err)
}

func TestVerifyMagicLinkCodeWithSession(t *testing.T) {
	token := "4444"
	firstSeen := true
	name := "name"
	phone := "+11111111111"
	picture := "@(^_^)@"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeVerifyMagicLinkURL(), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, token, body["token"])
		resp := &descope.JWTResponse{
			RefreshJwt: jwtTokenValid,
			User: &descope.UserResponse{
				User: descope.User{
					Name:  name,
					Phone: phone,
				},
				Picture: picture,
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
	assert.Equal(t, firstSeen, info.FirstSeen)
	assert.Equal(t, name, info.User.Name)
	assert.Equal(t, phone, info.User.Phone)
	assert.Equal(t, picture, info.User.Picture)
	require.Len(t, w.Result().Cookies(), 0)
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
	loginID := "943248329844"
	email := "test@test.com"
	uri := "https://some.url.com"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeUpdateUserEmailMagicLink(), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, loginID, body["loginId"])
		assert.EqualValues(t, email, body["email"])
		assert.EqualValues(t, uri, body["URI"])
		assert.Nil(t, body["crossDevice"])
		u, p := getProjectAndJwt(r)
		assert.NotEmpty(t, u)
		assert.NotEmpty(t, p)
	}))
	require.NoError(t, err)
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtTokenValid})
	err = a.MagicLink().UpdateUserEmail(loginID, email, uri, r)
	require.NoError(t, err)
}

func TestUpdateEmailMagicLinkFailures(t *testing.T) {
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtTokenValid})
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	err = a.MagicLink().UpdateUserEmail("", "email@email.com", "", r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "loginID"))
	err = a.MagicLink().UpdateUserEmail("id", "", "", r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "email"))
	err = a.MagicLink().UpdateUserEmail("id", "email", "", r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "email"))
}

func TestUpdateUserPhone(t *testing.T) {
	loginID := "943248329844"
	phone := "+111111111111"
	uri := "https://some.url.com"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeUpdateUserPhoneMagiclink(descope.MethodSMS), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, loginID, body["loginId"])
		assert.EqualValues(t, phone, body["phone"])
		assert.EqualValues(t, uri, body["URI"])
		assert.Nil(t, body["crossDevice"])
		u, p := getProjectAndJwt(r)
		assert.NotEmpty(t, u)
		assert.NotEmpty(t, p)
	}))
	require.NoError(t, err)
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtTokenValid})
	err = a.MagicLink().UpdateUserPhone(descope.MethodSMS, loginID, phone, uri, r)
	require.NoError(t, err)
}

func TestUpdatePhoneMagicLinkFailures(t *testing.T) {
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtTokenValid})
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	err = a.MagicLink().UpdateUserPhone(descope.MethodSMS, "", "+1111111111", "", r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "loginID"))
	err = a.MagicLink().UpdateUserPhone(descope.MethodSMS, "id", "", "", r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "phone"))
	err = a.MagicLink().UpdateUserPhone(descope.MethodSMS, "id", "phone", "", r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "phone"))
	err = a.MagicLink().UpdateUserPhone(descope.MethodEmail, "id", "+1111111111", "", r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "method"))
	r = &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: "somename", Value: jwtTokenValid})
	err = a.MagicLink().UpdateUserPhone(descope.MethodSMS, "id", "+111111111111", "", r)
	assert.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrRefreshToken)
}
