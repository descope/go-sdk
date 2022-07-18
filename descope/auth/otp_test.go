package auth

import (
	"bytes"
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

func TestValidEmailSignInEmail(t *testing.T) {
	email := "test@email.com"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeSignInURL(MethodEmail), r.URL.RequestURI())
		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, body["externalId"])
	}))
	require.NoError(t, err)
	err = a.SignInOTP(MethodEmail, email)
	require.NoError(t, err)
}

func TestSignUpEmail(t *testing.T) {
	email := "test@email.com"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeSignUpURL(MethodEmail), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["email"])
		assert.EqualValues(t, email, m["externalId"])
		assert.EqualValues(t, "test", m["user"].(map[string]interface{})["name"])
	}))
	require.NoError(t, err)
	err = a.SignUpOTP(MethodEmail, email, &User{Name: "test"})
	require.NoError(t, err)
}

func TestSignUpSMS(t *testing.T) {
	phone := "943248329844"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeSignUpURL(MethodSMS), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, body["phone"])
		assert.EqualValues(t, phone, body["externalId"])
		assert.EqualValues(t, "test", body["user"].(map[string]interface{})["name"])
	}))
	require.NoError(t, err)
	err = a.SignUpOTP(MethodSMS, phone, &User{Name: "test"})
	require.NoError(t, err)
}

func TestSignUpWhatsApp(t *testing.T) {
	phone := "943248329844"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeSignUpURL(MethodWhatsApp), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, body["whatsapp"])
		assert.EqualValues(t, phone, body["externalId"])
		assert.EqualValues(t, "test", body["user"].(map[string]interface{})["name"])
	}))
	require.NoError(t, err)
	err = a.SignUpOTP(MethodWhatsApp, phone, &User{Name: "test"})
	require.NoError(t, err)
}

func TestSignUpOrInWhatsApp(t *testing.T) {
	externalID := "943248329844"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeSignUpOrInURL(MethodWhatsApp), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, externalID, body["externalId"])
		assert.Nil(t, body["user"])
	}))
	require.NoError(t, err)
	err = a.SignUpOrInOTP(MethodWhatsApp, externalID)
	require.NoError(t, err)
}

func TestSignUpOrInSMS(t *testing.T) {
	externalID := "943248329844"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeSignUpOrInURL(MethodSMS), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, externalID, body["externalId"])
		assert.Nil(t, body["user"])
	}))
	require.NoError(t, err)
	err = a.SignUpOrInOTP(MethodSMS, externalID)
	require.NoError(t, err)
}

func TestSignUpOrInEmail(t *testing.T) {
	externalID := "943248329844"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeSignUpOrInURL(MethodEmail), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, externalID, body["externalId"])
		assert.Nil(t, body["user"])
	}))
	require.NoError(t, err)
	err = a.SignUpOrInOTP(MethodEmail, externalID)
	require.NoError(t, err)
}

func TestEmptyEmailVerifyCodeEmail(t *testing.T) {
	email := ""
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	_, err = a.VerifyCodeWithOptions(MethodEmail, email, "4444")
	require.Error(t, err)
	assert.EqualValues(t, errors.BadRequestErrorCode, err.(*errors.WebError).Code)
}

func TestInvalidVerifyCode(t *testing.T) {
	email := "a"
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	_, err = a.VerifyCodeWithOptions("", email, "4444")
	require.Error(t, err)
	assert.EqualValues(t, errors.BadRequestErrorCode, err.(*errors.WebError).Code)
}

func TestVerifyCodeDetectEmail(t *testing.T) {
	email := "test@test.com"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeVerifyCodeURL(MethodEmail), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, body["externalId"])
	}))
	require.NoError(t, err)
	_, err = a.VerifyCodeWithOptions("", email, "555")
	require.NoError(t, err)
}

func TestVerifyCodeDetectPhone(t *testing.T) {
	phone := "74987539043"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeVerifyCodeURL(MethodSMS), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, body["externalId"])
	}))
	require.NoError(t, err)
	_, err = a.VerifyCodeWithOptions("", phone, "555")
	require.NoError(t, err)
}

func TestVerifyCodeWithPhone(t *testing.T) {
	phone := "7753131313"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeVerifyCodeURL(MethodSMS), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, body["externalId"])
		assert.EqualValues(t, "4444", body["code"])
	}))
	require.NoError(t, err)
	_, err = a.VerifyCodeWithOptions(MethodSMS, phone, "4444")
	require.NoError(t, err)
}

func TestVerifyCodeEmail(t *testing.T) {
	email := "test@email.com"
	code := "4914"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeVerifyCodeURL(MethodEmail), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, body["externalId"])
		assert.EqualValues(t, code, body["code"])
	}))
	require.NoError(t, err)
	_, err = a.VerifyCodeWithOptions(MethodEmail, email, code)
	require.NoError(t, err)
}

func TestVerifyCodeSMS(t *testing.T) {
	phone := "943248329844"
	code := "4914"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeVerifyCodeURL(MethodSMS), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, body["externalId"])
		assert.EqualValues(t, code, body["code"])
	}))
	require.NoError(t, err)
	_, err = a.VerifyCodeWithOptions(MethodSMS, phone, code)
	require.NoError(t, err)
}

func TestVerifyCodeWhatsApp(t *testing.T) {
	phone := "943248329844"
	code := "4914"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeVerifyCodeURL(MethodWhatsApp), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, body["externalId"])
		assert.EqualValues(t, code, body["code"])
	}))
	require.NoError(t, err)
	_, err = a.VerifyCodeWithOptions(MethodWhatsApp, phone, code)
	require.NoError(t, err)
}

func TestVerifyCodeEmailResponseOption(t *testing.T) {
	email := "test@email.com"
	code := "4914"
	name := "name"
	phone := "+11111111111"
	firstSeen := true
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeVerifyCodeURL(MethodEmail), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, body["externalId"])
		assert.EqualValues(t, code, body["code"])
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
	info, err := a.VerifyCode(MethodEmail, email, code, w)
	require.NoError(t, err)
	require.Len(t, w.Result().Cookies(), 1)
	sessionCookie := w.Result().Cookies()[0]
	require.NoError(t, err)
	assert.EqualValues(t, mockAuthSessionCookie.Value, sessionCookie.Value)
	assert.True(t, info.FirstSeen)
	assert.EqualValues(t, name, info.User.Name)
	assert.EqualValues(t, phone, info.User.Phone)
}

func TestVerifyCodeEmailResponseNil(t *testing.T) {
	email := "test@email.com"
	code := "4914"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeVerifyCodeURL(MethodEmail), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, body["externalId"])
		assert.EqualValues(t, code, body["code"])
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(mockAuthSessionBody))}, nil
	})
	require.NoError(t, err)
	w := httptest.NewRecorder()
	info, err := a.VerifyCode(MethodEmail, email, code, nil)
	require.NoError(t, err)
	assert.Len(t, w.Result().Cookies(), 0)
	require.NotEmpty(t, info)
	require.NotEmpty(t, info.SessionToken)
	assert.EqualValues(t, jwtTokenValid, info.SessionToken.JWT)
}

func TestUpdateEmailOTP(t *testing.T) {
	externalID := "943248329844"
	email := "test@test.com"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeUpdateUserEmailOTP(), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, externalID, body["externalId"])
		assert.EqualValues(t, email, body["email"])
		u, p, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.NotEmpty(t, u)
		assert.NotEmpty(t, p)
	}))
	require.NoError(t, err)
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtTokenValid})
	err = a.UpdateUserEmailOTP(externalID, email, r)
	require.NoError(t, err)
}

func TestUpdateEmailOTPFailures(t *testing.T) {
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtTokenValid})

	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	err = a.UpdateUserEmailOTP("", "email", r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "identifier"))
	err = a.UpdateUserEmailOTP("id", "", r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "email"))
	err = a.UpdateUserEmailOTP("id", "email", r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "email"))

	r = &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: "somename", Value: jwtTokenValid})
	err = a.UpdateUserEmailOTP("id", "test@test.com", r)
	assert.Error(t, err)
	assert.ErrorIs(t, err, errors.RefreshTokenError)
}

func TestUpdatePhoneOTP(t *testing.T) {
	externalID := "943248329844"
	phone := "+111111111111"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeUpdateUserPhoneOTP(MethodSMS), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, externalID, body["externalId"])
		assert.EqualValues(t, phone, body["phone"])
		u, p, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.NotEmpty(t, u)
		assert.NotEmpty(t, p)
	}))
	require.NoError(t, err)
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtTokenValid})
	err = a.UpdateUserPhoneOTP(MethodSMS, externalID, phone, r)
	require.NoError(t, err)
}

func TestUpdatePhoneOTPFailures(t *testing.T) {
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtTokenValid})
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	err = a.UpdateUserPhoneOTP(MethodSMS, "", "+11111111111", r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "identifier"))
	err = a.UpdateUserPhoneOTP(MethodSMS, "id", "", r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "phone"))
	err = a.UpdateUserPhoneOTP(MethodSMS, "id", "aaaaa", r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "phone"))
	err = a.UpdateUserPhoneOTP(MethodEmail, "id", "+11111111111", r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "method"))
	r = &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: "somename", Value: jwtTokenValid})
	err = a.UpdateUserPhoneOTP(MethodSMS, "id", "+11111111111", r)
	assert.Error(t, err)
	assert.ErrorIs(t, err, errors.RefreshTokenError)
}
