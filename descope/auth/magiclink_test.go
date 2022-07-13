package auth

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/descope/go-sdk/descope/errors"
	"github.com/descope/go-sdk/descope/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignInMagicLinkEmptyExternalID(t *testing.T) {
	email := ""
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	err = a.SignInOTP(MethodEmail, email)
	require.Error(t, err)
	assert.EqualValues(t, errors.BadRequestErrorCode, err.(*errors.WebError).Code)

	err = a.SignInMagicLink(MethodEmail, email, "http://test.me")
	require.Error(t, err)
	assert.EqualValues(t, errors.BadRequestErrorCode, err.(*errors.WebError).Code)
}

func TestSignInMagicLinkCrossDeviceEmptyExternalID(t *testing.T) {
	email := ""
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	err = a.SignInOTP(MethodEmail, email)
	require.Error(t, err)
	assert.EqualValues(t, errors.BadRequestErrorCode, err.(*errors.WebError).Code)

	info, err := a.SignInMagicLinkCrossDevice(MethodEmail, email, "http://test.me")
	require.Error(t, err)
	assert.EqualValues(t, errors.BadRequestErrorCode, err.(*errors.WebError).Code)
	require.Empty(t, info)
}

func TestSignInMagicLinkEmail(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"

	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeMagicLinkSignInURL(MethodEmail), r.URL.RequestURI())
		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, body["externalID"])
		assert.EqualValues(t, uri, body["URI"])
	}))
	require.NoError(t, err)
	err = a.SignInMagicLink(MethodEmail, email, uri)
	require.NoError(t, err)
}

func TestSignInMagicLinkEmailCrossDevice(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	pendingRefResponse := "pending_ref"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeMagicLinkSignInURL(MethodEmail), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["externalID"])
		assert.EqualValues(t, uri, m["URI"])
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(fmt.Sprintf(`{"pendingRef": "%s"}`, pendingRefResponse))),
		}, nil
	})
	require.NoError(t, err)
	response, err := a.SignInMagicLinkCrossDevice(MethodEmail, email, uri)
	require.NoError(t, err)
	require.Equal(t, pendingRefResponse, response.PendingRef)
}

func TestSignInMagicLinkEmailCrossDeviceInvalidResponse(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(`{"pendingRef"`)),
		}, nil
	})
	require.NoError(t, err)
	res, err := a.SignInMagicLinkCrossDevice(MethodEmail, email, uri)
	require.Error(t, err)
	require.Empty(t, res)
}

func TestInvalidPhoneSignUpSMS(t *testing.T) {
	phone := "thisisemail@af.com"
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	err = a.SignUpOTP(MethodSMS, phone, &User{Name: "test"})
	require.Error(t, err)
	assert.EqualValues(t, errors.BadRequestErrorCode, err.(*errors.WebError).Code)

	err = a.SignUpMagicLink(MethodSMS, phone, "http://test.me", &User{Name: "test"})
	require.Error(t, err)
	assert.EqualValues(t, errors.BadRequestErrorCode, err.(*errors.WebError).Code)
}

func TestInvalidPhoneSignUpWhatsApp(t *testing.T) {
	phone := "thisisemail@af.com"
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	err = a.SignUpOTP(MethodSMS, phone, &User{Name: "test"})
	require.Error(t, err)
	assert.EqualValues(t, errors.BadRequestErrorCode, err.(*errors.WebError).Code)

	err = a.SignUpMagicLink(MethodSMS, phone, "http://test.me", &User{Name: "test"})
	require.Error(t, err)
	assert.EqualValues(t, errors.BadRequestErrorCode, err.(*errors.WebError).Code)
}

func TestInvalidEmailSignUpEmail(t *testing.T) {
	email := "943248329844"
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	err = a.SignUpOTP(MethodEmail, email, &User{Name: "test"})
	require.Error(t, err)
	assert.EqualValues(t, errors.BadRequestErrorCode, err.(*errors.WebError).Code)

	err = a.SignUpMagicLink(MethodEmail, email, "http://test.me", &User{Name: "test"})
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
		assert.EqualValues(t, email, m["externalID"])
		assert.EqualValues(t, "test", m["user"].(map[string]interface{})["name"])
	}))
	require.NoError(t, err)
	err = a.SignUpMagicLink(MethodEmail, email, uri, &User{Name: "test"})
	require.NoError(t, err)
}

func TestSignUpOrInMagicLinkEmail(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeMagicLinkSignUpOrInURL(MethodEmail), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["externalID"])
		assert.EqualValues(t, uri, m["URI"])
		assert.Nil(t, m["user"])
	}))
	require.NoError(t, err)
	err = a.SignUpOrInMagicLink(MethodEmail, email, uri)
	require.NoError(t, err)
}

func TestSignUpOrInMagicLinkSMS(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeMagicLinkSignUpOrInURL(MethodSMS), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["externalID"])
		assert.EqualValues(t, uri, m["URI"])
		assert.Nil(t, m["user"])
	}))
	require.NoError(t, err)
	err = a.SignUpOrInMagicLink(MethodSMS, email, uri)
	require.NoError(t, err)
}

func TestSignUpOrInMagicLinkWhatsapp(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeMagicLinkSignUpOrInURL(MethodWhatsApp), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["externalID"])
		assert.EqualValues(t, uri, m["URI"])
		assert.Nil(t, m["user"])
	}))
	require.NoError(t, err)
	err = a.SignUpOrInMagicLink(MethodWhatsApp, email, uri)
	require.NoError(t, err)
}

func TestSignUpMagicLinkEmailCrossDevice(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	pendingRefResponse := "pending_ref"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeMagicLinkSignUpURL(MethodEmail), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["email"])
		assert.EqualValues(t, uri, m["URI"])
		assert.EqualValues(t, email, m["externalID"])
		assert.EqualValues(t, "test", m["user"].(map[string]interface{})["name"])
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(fmt.Sprintf(`{"pendingRef": "%s"}`, pendingRefResponse))),
		}, nil
	})
	require.NoError(t, err)
	response, err := a.SignUpMagicLinkCrossDevice(MethodEmail, email, uri, &User{Name: "test"})
	require.NoError(t, err)
	require.Equal(t, pendingRefResponse, response.PendingRef)
}

func TestSignUpOrInMagicLinkEmailCrossDevice(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	pendingRefResponse := "pending_ref"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeMagicLinkSignUpOrInURL(MethodEmail), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["externalID"])
		assert.EqualValues(t, uri, m["URI"])
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(fmt.Sprintf(`{"pendingRef": "%s"}`, pendingRefResponse))),
		}, nil
	})
	require.NoError(t, err)
	response, err := a.SignUpOrInMagicLinkCrossDevice(MethodEmail, email, uri)
	require.NoError(t, err)
	require.Equal(t, pendingRefResponse, response.PendingRef)
}

func TestSignUpMagicLinkEmailCrossDeviceEmptyIdentifier(t *testing.T) {
	uri := "http://test.me"
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	response, err := a.SignUpMagicLinkCrossDevice(MethodEmail, "", uri, &User{Name: "test"})
	require.Error(t, err)
	require.Empty(t, response)
}

func TestGetMagicLinkSession(t *testing.T) {
	pendingRef := "pending_ref"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeGetMagicLinkSession(), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, pendingRef, body["pendingRef"])
	}))
	require.NoError(t, err)
	w := httptest.NewRecorder()
	info, err := a.GetMagicLinkSession(pendingRef, w)
	require.NoError(t, err)
	assert.NotEmpty(t, info.SessionToken.JWT)
	require.Len(t, w.Result().Cookies(), 1)
	sessionCookie := w.Result().Cookies()[0]
	require.NoError(t, err)
	assert.EqualValues(t, mockAuthSessionCookie.Value, sessionCookie.Value)
}

func TestGetMagicLinkSessionError(t *testing.T) {
	pendingRef := "pending_ref"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadGateway}, nil
	})
	require.NoError(t, err)
	w := httptest.NewRecorder()
	_, err = a.GetMagicLinkSession(pendingRef, w)
	require.Error(t, err)
}

func TestGetMagicLinkSessionStillPending(t *testing.T) {
	pendingRef := "pending_ref"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusUnauthorized}, nil
	})
	require.NoError(t, err)
	w := httptest.NewRecorder()
	_, err = a.GetMagicLinkSession(pendingRef, w)
	require.Error(t, err)
	require.ErrorIs(t, err, errors.MagicLinkUnauthorized)
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
		assert.EqualValues(t, phone, body["externalID"])
		assert.EqualValues(t, "test", body["user"].(map[string]interface{})["name"])
	}))
	require.NoError(t, err)
	err = a.SignUpMagicLink(MethodSMS, phone, uri, &User{Name: "test"})
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
		assert.EqualValues(t, phone, body["externalID"])
		assert.EqualValues(t, "test", body["user"].(map[string]interface{})["name"])
	}))
	require.NoError(t, err)
	err = a.SignUpMagicLink(MethodWhatsApp, phone, uri, &User{Name: "test"})
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
			JWTS: []string{jwtTokenValid},
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
	info, err := a.VerifyMagicLink(token, w)
	require.NoError(t, err)
	assert.NotEmpty(t, info.SessionToken.JWT)
	require.Len(t, w.Result().Cookies(), 1)
	sessionCookie := w.Result().Cookies()[0]
	require.NoError(t, err)
	assert.EqualValues(t, mockAuthSessionCookie.Value, sessionCookie.Value)
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
	info, err := a.VerifyMagicLink(token, w)
	require.NoError(t, err)
	assert.Empty(t, info)
}

func TestUpdateUserEmailMagicLink(t *testing.T) {
	externalID := "943248329844"
	email := "test@test.com"
	uri := "https://some.url.com"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeUpdateUserEmailMagicLink(), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, externalID, body["externalID"])
		assert.EqualValues(t, email, body["email"])
		assert.EqualValues(t, uri, body["URI"])
		assert.Nil(t, body["crossDevice"])
		u, p, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.NotEmpty(t, u)
		assert.NotEmpty(t, p)
	}))
	require.NoError(t, err)
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtTokenValid})
	err = a.UpdateUserEmailMagicLink(externalID, email, uri, r)
	require.NoError(t, err)
}

func TestUpdateUserEmailMagicLinkCrossDevice(t *testing.T) {
	externalID := "943248329844"
	email := "test@test.com"
	uri := "https://some.url.com"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeUpdateUserEmailMagicLink(), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, externalID, body["externalID"])
		assert.EqualValues(t, email, body["email"])
		assert.EqualValues(t, uri, body["URI"])
		assert.True(t, body["crossDevice"].(bool))
		u, p, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.NotEmpty(t, u)
		assert.NotEmpty(t, p)
	}))
	require.NoError(t, err)
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtTokenValid})
	_, err = a.UpdateUserEmailMagicLinkCrossDevice(externalID, email, uri, r)
	require.NoError(t, err)
}

func TestUpdateEmailMagicLinkFailures(t *testing.T) {
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtTokenValid})
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	err = a.UpdateUserEmailMagicLink("", "email@email.com", "", r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "identifier"))
	err = a.UpdateUserEmailMagicLink("id", "", "", r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "email"))
	err = a.UpdateUserEmailMagicLink("id", "email", "", r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "email"))
	_, err = a.UpdateUserEmailMagicLinkCrossDevice("", "email@email.com", "", r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "identifier"))
	_, err = a.UpdateUserEmailMagicLinkCrossDevice("id", "", "", r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "email"))
	_, err = a.UpdateUserEmailMagicLinkCrossDevice("id", "email", "", r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "email"))
	r = &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: "somename", Value: jwtTokenValid})
	_, err = a.UpdateUserEmailMagicLinkCrossDevice("id", "test@test.com", "", r)
	assert.Error(t, err)
	assert.ErrorIs(t, err, errors.RefreshTokenError)
}

func TestUpdateUserPhoneMagicLink(t *testing.T) {
	externalID := "943248329844"
	phone := "+111111111111"
	uri := "https://some.url.com"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeUpdateUserPhoneMagicLink(MethodSMS), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, externalID, body["externalID"])
		assert.EqualValues(t, phone, body["phone"])
		assert.EqualValues(t, uri, body["URI"])
		assert.Nil(t, body["crossDevice"])
		u, p, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.NotEmpty(t, u)
		assert.NotEmpty(t, p)
	}))
	require.NoError(t, err)
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtTokenValid})
	err = a.UpdateUserPhoneMagicLink(MethodSMS, externalID, phone, uri, r)
	require.NoError(t, err)
}

func TestUpdateUserPhoneMagicLinkCrossDevice(t *testing.T) {
	externalID := "943248329844"
	phone := "+1111111111"
	uri := "https://some.url.com"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeUpdateUserPhoneMagicLink(MethodWhatsApp), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, externalID, body["externalID"])
		assert.EqualValues(t, phone, body["phone"])
		assert.EqualValues(t, uri, body["URI"])
		assert.True(t, body["crossDevice"].(bool))
		u, p, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.NotEmpty(t, u)
		assert.NotEmpty(t, p)
	}))
	require.NoError(t, err)
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtTokenValid})
	_, err = a.UpdateUserPhoneMagicLinkCrossDevice(MethodWhatsApp, externalID, phone, uri, r)
	require.NoError(t, err)
}

func TestUpdatePhoneMagicLinkFailures(t *testing.T) {
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtTokenValid})
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	err = a.UpdateUserPhoneMagicLink(MethodSMS, "", "+1111111111", "", r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "identifier"))
	err = a.UpdateUserPhoneMagicLink(MethodSMS, "id", "", "", r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "phone"))
	err = a.UpdateUserPhoneMagicLink(MethodSMS, "id", "phone", "", r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "phone"))
	err = a.UpdateUserPhoneMagicLink(MethodEmail, "id", "+1111111111", "", r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "method"))
	r = &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: "somename", Value: jwtTokenValid})
	err = a.UpdateUserPhoneMagicLink(MethodSMS, "id", "+111111111111", "", r)
	assert.Error(t, err)
	assert.ErrorIs(t, err, errors.RefreshTokenError)

	r = &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtTokenValid})
	_, err = a.UpdateUserPhoneMagicLinkCrossDevice(MethodSMS, "", "+1111111111", "", r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "identifier"))
	_, err = a.UpdateUserPhoneMagicLinkCrossDevice(MethodSMS, "id", "", "", r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "phone"))
	_, err = a.UpdateUserPhoneMagicLinkCrossDevice(MethodSMS, "id", "phone", "", r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "phone"))
	_, err = a.UpdateUserPhoneMagicLinkCrossDevice(MethodEmail, "id", "+111111111111", "", r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "method"))
	r = &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: "somename", Value: jwtTokenValid})
	_, err = a.UpdateUserPhoneMagicLinkCrossDevice(MethodSMS, "id", "+111111111111", "", r)
	assert.Error(t, err)
	assert.ErrorIs(t, err, errors.RefreshTokenError)
}
