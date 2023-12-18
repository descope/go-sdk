package auth

import (
	"bytes"
	"context"
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

func TestValidEmailSignInEmail(t *testing.T) {
	email := "test@email.com"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeSignInURL(descope.MethodEmail), r.URL.RequestURI())
		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, body["loginId"])
	}))
	require.NoError(t, err)
	_, err = a.OTP().SignIn(context.Background(), descope.MethodEmail, email, nil, nil)
	require.NoError(t, err)
}

func TestValidEmailSignInEmailStepup(t *testing.T) {
	email := "test@email.com"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeSignInURL(descope.MethodEmail), r.URL.RequestURI())
		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, body["loginId"])
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
	_, err = a.OTP().SignIn(context.Background(), descope.MethodEmail, email, &http.Request{Header: http.Header{"Cookie": []string{"DSR=test"}}}, &descope.LoginOptions{Stepup: true, CustomClaims: map[string]interface{}{"k1": "v1"}})
	require.NoError(t, err)
}

func TestSignUpEmail(t *testing.T) {
	email := "test@email.com"
	maskedEmail := "t***@email.com"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeSignUpURL(descope.MethodEmail), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["email"])
		assert.EqualValues(t, email, m["loginId"])
		assert.EqualValues(t, "test", m["user"].(map[string]interface{})["name"])
		resp := MaskedEmailRes{MaskedEmail: maskedEmail}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	me, err := a.OTP().SignUp(context.Background(), descope.MethodEmail, email, &descope.User{Name: "test"})
	require.NoError(t, err)
	assert.EqualValues(t, maskedEmail, me)
}

func TestSignUpSMS(t *testing.T) {
	phone := "943248329844"
	maskedPhone := "*********44"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeSignUpURL(descope.MethodSMS), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, body["phone"])
		assert.EqualValues(t, phone, body["loginId"])
		assert.EqualValues(t, "test", body["user"].(map[string]interface{})["name"])
		resp := MaskedPhoneRes{MaskedPhone: maskedPhone}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	mp, err := a.OTP().SignUp(context.Background(), descope.MethodSMS, phone, &descope.User{Name: "test"})
	require.NoError(t, err)
	require.EqualValues(t, maskedPhone, mp)
}

func TestSignUpWhatsApp(t *testing.T) {
	phone := "943248329844"
	maskedPhone := "*********44"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeSignUpURL(descope.MethodWhatsApp), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, body["whatsapp"])
		assert.EqualValues(t, phone, body["loginId"])
		assert.EqualValues(t, "test", body["user"].(map[string]interface{})["name"])
		resp := MaskedPhoneRes{MaskedPhone: maskedPhone}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	mp, err := a.OTP().SignUp(context.Background(), descope.MethodWhatsApp, phone, &descope.User{Name: "test"})
	require.NoError(t, err)
	require.EqualValues(t, maskedPhone, mp)
}

func TestSignUpOrInWhatsApp(t *testing.T) {
	loginID := "943248329844"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeSignUpOrInURL(descope.MethodWhatsApp), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, loginID, body["loginId"])
		assert.Nil(t, body["user"])
	}))
	require.NoError(t, err)
	_, err = a.OTP().SignUpOrIn(context.Background(), descope.MethodWhatsApp, loginID)
	require.NoError(t, err)
}

func TestSignUpOrInSMS(t *testing.T) {
	loginID := "943248329844"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeSignUpOrInURL(descope.MethodSMS), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, loginID, body["loginId"])
		assert.Nil(t, body["user"])
	}))
	require.NoError(t, err)
	_, err = a.OTP().SignUpOrIn(context.Background(), descope.MethodSMS, loginID)
	require.NoError(t, err)
}

func TestSignUpOrInEmail(t *testing.T) {
	loginID := "943248329844"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeSignUpOrInURL(descope.MethodEmail), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, loginID, body["loginId"])
		assert.Nil(t, body["user"])
	}))
	require.NoError(t, err)
	_, err = a.OTP().SignUpOrIn(context.Background(), descope.MethodEmail, loginID)
	require.NoError(t, err)
}

func TestEmptyEmailSignIn(t *testing.T) {
	email := ""
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	_, err = a.OTP().SignIn(context.Background(), descope.MethodEmail, email, nil, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidArguments)
}

func TestEmptyEmailSignUpOrIn(t *testing.T) {
	email := ""
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	_, err = a.OTP().SignUpOrIn(context.Background(), descope.MethodEmail, email)
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidArguments)
}

func TestInvalidEmailSignUp(t *testing.T) {
	email := "+8222941449"
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	_, err = a.OTP().SignUp(context.Background(), descope.MethodEmail, email, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidArguments)
}

func TestInvalidSignInStepupNoJWT(t *testing.T) {
	phone := "+8222941449"
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	_, err = a.OTP().SignIn(context.Background(), descope.MethodSMS, phone, nil, &descope.LoginOptions{Stepup: true})
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidStepUpJWT)
}

func TestEmptyEmailVerifyCodeEmail(t *testing.T) {
	email := ""
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	_, err = a.OTP().VerifyCode(context.Background(), descope.MethodEmail, email, "4444", nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidArguments)
}

func TestInvalidVerifyCode(t *testing.T) {
	email := "a"
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	_, err = a.OTP().VerifyCode(context.Background(), "", email, "4444", nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidArguments)
}

func TestVerifyCodeDetectEmail(t *testing.T) {
	email := "test@test.com"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeVerifyCodeURL(descope.MethodEmail), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, body["loginId"])
	}))
	require.NoError(t, err)
	_, err = a.OTP().VerifyCode(context.Background(), "", email, "555", nil)
	require.NoError(t, err)
}

func TestVerifyCodeDetectPhone(t *testing.T) {
	phone := "74987539043"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeVerifyCodeURL(descope.MethodSMS), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, body["loginId"])
	}))
	require.NoError(t, err)
	_, err = a.OTP().VerifyCode(context.Background(), "", phone, "555", nil)
	require.NoError(t, err)
}

func TestVerifyCodeWithPhone(t *testing.T) {
	phone := "7753131313"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeVerifyCodeURL(descope.MethodSMS), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, body["loginId"])
		assert.EqualValues(t, "4444", body["code"])
	}))
	require.NoError(t, err)
	_, err = a.OTP().VerifyCode(context.Background(), descope.MethodSMS, phone, "4444", nil)
	require.NoError(t, err)
}

func TestVerifyCodeEmail(t *testing.T) {
	email := "test@email.com"
	code := "4914"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeVerifyCodeURL(descope.MethodEmail), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, body["loginId"])
		assert.EqualValues(t, code, body["code"])
	}))
	require.NoError(t, err)
	_, err = a.OTP().VerifyCode(context.Background(), descope.MethodEmail, email, code, nil)
	require.NoError(t, err)
}

func TestVerifyCodeSMS(t *testing.T) {
	phone := "943248329844"
	code := "4914"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeVerifyCodeURL(descope.MethodSMS), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, body["loginId"])
		assert.EqualValues(t, code, body["code"])
	}))
	require.NoError(t, err)
	_, err = a.OTP().VerifyCode(context.Background(), descope.MethodSMS, phone, code, nil)
	require.NoError(t, err)
}

func TestVerifyCodeWhatsApp(t *testing.T) {
	phone := "943248329844"
	code := "4914"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeVerifyCodeURL(descope.MethodWhatsApp), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, body["loginId"])
		assert.EqualValues(t, code, body["code"])
	}))
	require.NoError(t, err)
	_, err = a.OTP().VerifyCode(context.Background(), descope.MethodWhatsApp, phone, code, nil)
	require.NoError(t, err)
}

func TestVerifyCodeEmailResponseOption(t *testing.T) {
	email := "test@email.com"
	code := "4914"
	name := "name"
	phone := "+11111111111"
	picture := "@(^_^)@"
	firstSeen := true
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeVerifyCodeURL(descope.MethodEmail), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, body["loginId"])
		assert.EqualValues(t, code, body["code"])
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
	authInfo, err := a.OTP().VerifyCode(context.Background(), descope.MethodEmail, email, code, w)
	require.NoError(t, err)
	require.Len(t, w.Result().Cookies(), 0)
	assert.Equal(t, firstSeen, authInfo.FirstSeen)
	assert.Equal(t, name, authInfo.User.Name)
	assert.Equal(t, phone, authInfo.User.Phone)
	assert.Equal(t, picture, authInfo.User.Picture)
}

func TestVerifyCodeEmailResponseNil(t *testing.T) {
	email := "test@email.com"
	code := "4914"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeVerifyCodeURL(descope.MethodEmail), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, body["loginId"])
		assert.EqualValues(t, code, body["code"])
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(mockAuthSessionBody))}, nil
	})
	require.NoError(t, err)
	w := httptest.NewRecorder()
	info, err := a.OTP().VerifyCode(context.Background(), descope.MethodEmail, email, code, nil)
	require.NoError(t, err)
	assert.Len(t, w.Result().Cookies(), 0)
	require.NotEmpty(t, info)
	require.NotEmpty(t, info.SessionToken)
	assert.EqualValues(t, jwtTokenValid, info.SessionToken.JWT)
}

func TestUpdateEmailOTP(t *testing.T) {
	loginID := "943248329844"
	email := "test@test.com"
	maskedEmail := "t***@test.com"
	checkOptions := true
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeUpdateUserEmailOTP(), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, loginID, body["loginId"])
		assert.EqualValues(t, email, body["email"])
		if checkOptions {
			assert.EqualValues(t, true, body["addToLoginIDs"])
			assert.EqualValues(t, true, body["onMergeUseExisting"])
		} else {
			assert.EqualValues(t, nil, body["addToLoginIDs"])
			assert.EqualValues(t, nil, body["onMergeUseExisting"])
		}

		u, p := getProjectAndJwt(r)
		assert.NotEmpty(t, u)
		assert.NotEmpty(t, p)
		resp := MaskedEmailRes{MaskedEmail: maskedEmail}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtTokenValid})
	me, err := a.OTP().UpdateUserEmail(context.Background(), loginID, email, &descope.UpdateOptions{AddToLoginIDs: true, OnMergeUseExisting: true}, r)
	require.NoError(t, err)
	require.EqualValues(t, maskedEmail, me)
	checkOptions = false
	me, err = a.OTP().UpdateUserEmail(context.Background(), loginID, email, nil, r)
	require.NoError(t, err)
	require.EqualValues(t, maskedEmail, me)

}

func TestUpdateEmailOTPFailures(t *testing.T) {
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtTokenValid})

	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	_, err = a.OTP().UpdateUserEmail(context.Background(), "", "email", nil, r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "loginID"))
	_, err = a.OTP().UpdateUserEmail(context.Background(), "id", "", nil, r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "email"))
	_, err = a.OTP().UpdateUserEmail(context.Background(), "id", "email", nil, r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "email"))

	r = &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: "somename", Value: jwtTokenValid})
	_, err = a.OTP().UpdateUserEmail(context.Background(), "id", "test@test.com", nil, r)
	assert.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrRefreshToken)
}

func TestUpdatePhoneOTP(t *testing.T) {
	loginID := "943248329844"
	phone := "+111111111111"
	maskedPhone := "+*******111"
	checkOptions := true
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeUpdateUserPhoneOTP(descope.MethodSMS), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, loginID, body["loginId"])
		assert.EqualValues(t, phone, body["phone"])
		if checkOptions {
			assert.EqualValues(t, true, body["addToLoginIDs"])
			assert.EqualValues(t, true, body["onMergeUseExisting"])
		} else {
			assert.EqualValues(t, nil, body["addToLoginIDs"])
			assert.EqualValues(t, nil, body["onMergeUseExisting"])
		}

		u, p := getProjectAndJwt(r)
		assert.NotEmpty(t, u)
		assert.NotEmpty(t, p)
		resp := MaskedPhoneRes{MaskedPhone: maskedPhone}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtTokenValid})
	mp, err := a.OTP().UpdateUserPhone(context.Background(), descope.MethodSMS, loginID, phone, &descope.UpdateOptions{AddToLoginIDs: true, OnMergeUseExisting: true}, r)
	require.NoError(t, err)
	require.EqualValues(t, maskedPhone, mp)
	checkOptions = false
	mp, err = a.OTP().UpdateUserPhone(context.Background(), descope.MethodSMS, loginID, phone, nil, r)
	require.NoError(t, err)
	require.EqualValues(t, maskedPhone, mp)
}

func TestUpdatePhoneOTPFailures(t *testing.T) {
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtTokenValid})
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	_, err = a.OTP().UpdateUserPhone(context.Background(), descope.MethodSMS, "", "+11111111111", nil, r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "loginID"))
	_, err = a.OTP().UpdateUserPhone(context.Background(), descope.MethodSMS, "id", "", nil, r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "phone"))
	_, err = a.OTP().UpdateUserPhone(context.Background(), descope.MethodSMS, "id", "aaaaa", nil, r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "phone"))
	_, err = a.OTP().UpdateUserPhone(context.Background(), descope.MethodEmail, "id", "+11111111111", nil, r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "method"))
	r = &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: "somename", Value: jwtTokenValid})
	_, err = a.OTP().UpdateUserPhone(context.Background(), descope.MethodSMS, "id", "+11111111111", nil, r)
	assert.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrRefreshToken)
}
