package auth

import (
	"bytes"
	"context"
	"fmt"
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
		assert.EqualValues(t, map[string]any{"stepup": true, "customClaims": map[string]any{"k1": "v1"}}, body["loginOptions"])
		reqToken := r.Header.Get(api.AuthorizationHeaderName)
		splitToken := strings.Split(reqToken, api.BearerAuthorizationPrefix)
		require.Len(t, splitToken, 2)
		bearer := splitToken[1]
		bearers := strings.Split(bearer, ":")
		require.Len(t, bearers, 2)
		assert.EqualValues(t, "test", bearers[1])
	}))
	require.NoError(t, err)
	_, err = a.OTP().SignIn(context.Background(), descope.MethodEmail, email, &http.Request{Header: http.Header{"Cookie": []string{"DSR=test"}}}, &descope.LoginOptions{Stepup: true, CustomClaims: map[string]any{"k1": "v1"}})
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
		assert.EqualValues(t, "test", m["user"].(map[string]any)["name"])
		resp := MaskedEmailRes{MaskedEmail: maskedEmail}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	me, err := a.OTP().SignUp(context.Background(), descope.MethodEmail, email, &descope.User{Name: "test"}, nil)
	require.NoError(t, err)
	assert.EqualValues(t, maskedEmail, me)
}

func TestSignUpEmailWithSignUpOptions(t *testing.T) {
	email := "test@email.com"
	maskedEmail := "t***@email.com"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeSignUpURL(descope.MethodEmail), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["email"])
		assert.EqualValues(t, email, m["loginId"])
		assert.EqualValues(t, "test", m["user"].(map[string]any)["name"])
		resp := MaskedEmailRes{MaskedEmail: maskedEmail}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		assert.EqualValues(t, map[string]any{"customClaims": map[string]any{"aa": "bb"}, "templateOptions": map[string]any{"cc": "dd"}, "templateId": "foo"}, m["loginOptions"])
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	me, err := a.OTP().SignUp(context.Background(), descope.MethodEmail, email, &descope.User{Name: "test"}, &descope.SignUpOptions{
		CustomClaims:    map[string]any{"aa": "bb"},
		TemplateOptions: map[string]string{"cc": "dd"},
		TemplateID:      "foo",
	})
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
		assert.EqualValues(t, "test", body["user"].(map[string]any)["name"])
		resp := MaskedPhoneRes{MaskedPhone: maskedPhone}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	mp, err := a.OTP().SignUp(context.Background(), descope.MethodSMS, phone, &descope.User{Name: "test"}, nil)
	require.NoError(t, err)
	require.EqualValues(t, maskedPhone, mp)
}

func TestSignUpVoice(t *testing.T) {
	phone := "943248329844"
	maskedPhone := "*********44"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeSignUpURL(descope.MethodVoice), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, body["phone"])
		assert.EqualValues(t, phone, body["loginId"])
		assert.EqualValues(t, "test", body["user"].(map[string]any)["name"])
		resp := MaskedPhoneRes{MaskedPhone: maskedPhone}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	mp, err := a.OTP().SignUp(context.Background(), descope.MethodVoice, phone, &descope.User{Name: "test"}, nil)
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
		assert.EqualValues(t, "test", body["user"].(map[string]any)["name"])
		resp := MaskedPhoneRes{MaskedPhone: maskedPhone}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	mp, err := a.OTP().SignUp(context.Background(), descope.MethodWhatsApp, phone, &descope.User{Name: "test"}, nil)
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
	_, err = a.OTP().SignUpOrIn(context.Background(), descope.MethodWhatsApp, loginID, nil)
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
	_, err = a.OTP().SignUpOrIn(context.Background(), descope.MethodSMS, loginID, nil)
	require.NoError(t, err)
}

func TestSignUpOrInVoice(t *testing.T) {
	loginID := "943248329844"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeSignUpOrInURL(descope.MethodVoice), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, loginID, body["loginId"])
		assert.Nil(t, body["user"])
	}))
	require.NoError(t, err)
	_, err = a.OTP().SignUpOrIn(context.Background(), descope.MethodVoice, loginID, nil)
	require.NoError(t, err)
}

func TestSignUpOrInSMSWithSignUpOptions(t *testing.T) {
	loginID := "943248329844"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeSignUpOrInURL(descope.MethodSMS), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, loginID, body["loginId"])
		assert.Nil(t, body["user"])
		assert.EqualValues(t, map[string]any{"customClaims": map[string]any{"aa": "bb"}, "templateOptions": map[string]any{"cc": "dd"}}, body["loginOptions"])
	}))
	require.NoError(t, err)
	_, err = a.OTP().SignUpOrIn(context.Background(), descope.MethodSMS, loginID, &descope.SignUpOptions{
		CustomClaims:    map[string]any{"aa": "bb"},
		TemplateOptions: map[string]string{"cc": "dd"},
	})
	require.NoError(t, err)
}

func TestSignUpOrInVoiceWithSignUpOptions(t *testing.T) {
	loginID := "943248329844"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeSignUpOrInURL(descope.MethodVoice), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, loginID, body["loginId"])
		assert.Nil(t, body["user"])
		assert.EqualValues(t, map[string]any{"customClaims": map[string]any{"aa": "bb"}, "templateOptions": map[string]any{"cc": "dd"}}, body["loginOptions"])
	}))
	require.NoError(t, err)
	_, err = a.OTP().SignUpOrIn(context.Background(), descope.MethodVoice, loginID, &descope.SignUpOptions{
		CustomClaims:    map[string]any{"aa": "bb"},
		TemplateOptions: map[string]string{"cc": "dd"},
	})
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
	_, err = a.OTP().SignUpOrIn(context.Background(), descope.MethodEmail, loginID, nil)
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
	_, err = a.OTP().SignUpOrIn(context.Background(), descope.MethodEmail, email, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidArguments)
}

func TestInvalidEmailSignUp(t *testing.T) {
	email := "+8222941449"
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	_, err = a.OTP().SignUp(context.Background(), descope.MethodEmail, email, nil, nil)
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

func TestSignInEmailWithTenantID(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, "test@test.com", body["loginId"])
		loginOpts, ok := body["loginOptions"].(map[string]any)
		require.True(t, ok, "loginOptions should be a map")
		assert.EqualValues(t, "tenant1", loginOpts["tenantId"])
	}))
	require.NoError(t, err)
	_, err = a.OTP().SignIn(context.Background(), descope.MethodEmail, "test@test.com", nil, &descope.LoginOptions{TenantID: "tenant1"})
	require.NoError(t, err)
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

func TestVerifyCodeVoice(t *testing.T) {
	phone := "943248329844"
	code := "4914"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeVerifyCodeURL(descope.MethodVoice), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, body["loginId"])
		assert.EqualValues(t, code, body["code"])
	}))
	require.NoError(t, err)
	_, err = a.OTP().VerifyCode(context.Background(), descope.MethodVoice, phone, code, nil)
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

func TestUpdateEmailOTPWithMFA(t *testing.T) {
	loginID := "943248329844"
	email := "test@test.com"
	maskedEmail := "t***@test.com"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeUpdateUserEmailOTP(), r.URL.RequestURI())
		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, loginID, body["loginId"])
		assert.EqualValues(t, email, body["email"])
		assert.EqualValues(t, true, body["mfa"])
		resp := MaskedEmailRes{MaskedEmail: maskedEmail}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtTokenValid})
	me, err := a.OTP().UpdateUserEmail(context.Background(), loginID, email, &descope.UpdateOptions{MFA: true}, r)
	require.NoError(t, err)
	require.EqualValues(t, maskedEmail, me)
}

func TestUpdatePhoneOTPWithMFA(t *testing.T) {
	loginID := "943248329844"
	phone := "+111111111111"
	maskedPhone := "+*******111"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeUpdateUserPhoneOTP(descope.MethodSMS), r.URL.RequestURI())
		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, loginID, body["loginId"])
		assert.EqualValues(t, phone, body["phone"])
		assert.EqualValues(t, true, body["mfa"])
		resp := MaskedPhoneRes{MaskedPhone: maskedPhone}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtTokenValid})
	mp, err := a.OTP().UpdateUserPhone(context.Background(), descope.MethodSMS, loginID, phone, &descope.UpdateOptions{MFA: true}, r)
	require.NoError(t, err)
	require.EqualValues(t, maskedPhone, mp)
}

func TestUpdateEmailOTPWithTemplateOptions(t *testing.T) {
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
			assert.EqualValues(t, map[string]any{"cc": "dd"}, body["templateOptions"])
		} else {
			assert.EqualValues(t, nil, body["addToLoginIDs"])
			assert.EqualValues(t, nil, body["onMergeUseExisting"])
			assert.EqualValues(t, nil, body["templateOptions"])
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
	me, err := a.OTP().UpdateUserEmail(context.Background(), loginID, email, &descope.UpdateOptions{AddToLoginIDs: true, OnMergeUseExisting: true, TemplateOptions: map[string]string{"cc": "dd"}}, r)
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

func TestUpdatePhoneOTPVoice(t *testing.T) {
	loginID := "943248329844"
	phone := "+111111111111"
	maskedPhone := "+*******111"
	checkOptions := true
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeUpdateUserPhoneOTP(descope.MethodVoice), r.URL.RequestURI())

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
	mp, err := a.OTP().UpdateUserPhone(context.Background(), descope.MethodVoice, loginID, phone, &descope.UpdateOptions{AddToLoginIDs: true, OnMergeUseExisting: true}, r)
	require.NoError(t, err)
	require.EqualValues(t, maskedPhone, mp)
	checkOptions = false
	mp, err = a.OTP().UpdateUserPhone(context.Background(), descope.MethodVoice, loginID, phone, nil, r)
	require.NoError(t, err)
	require.EqualValues(t, maskedPhone, mp)
}

func TestUpdatePhoneOTPWithTemplateOptions(t *testing.T) {
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
			assert.EqualValues(t, map[string]any{"cc": "dd"}, body["templateOptions"])
		} else {
			assert.EqualValues(t, nil, body["addToLoginIDs"])
			assert.EqualValues(t, nil, body["onMergeUseExisting"])
			assert.EqualValues(t, nil, body["templateOptions"])
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
	mp, err := a.OTP().UpdateUserPhone(context.Background(), descope.MethodSMS, loginID, phone, &descope.UpdateOptions{AddToLoginIDs: true, OnMergeUseExisting: true, TemplateOptions: map[string]string{"cc": "dd"}}, r)
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

func TestSignInEmailWithLoginOptions(t *testing.T) {
	email := "test@email.com"
	maskedEmail := "t***@email.com"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.EqualValues(t, "/v1/auth/otp/signin/email", r.URL.RequestURI())
		p, jwt := getProjectAndJwt(r)
		assert.EqualValues(t, "a", p)
		assert.Empty(t, jwt)
		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, body["loginId"])
		assert.EqualValues(t, map[string]any{"ssoAppId": "app1", "locale": "en-US", "pkceChallenge": "Y2hhbGxlbmdl"}, body["loginOptions"])
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(`{"maskedEmail":"` + maskedEmail + `","verificationAttempts":3}`))}, nil
	})
	require.NoError(t, err)
	me, err := a.OTP().SignIn(context.Background(), descope.MethodEmail, email, nil, &descope.LoginOptions{SSOAppID: "app1", Locale: "en-US", PKCEChallenge: []byte("challenge")})
	require.NoError(t, err)
	assert.EqualValues(t, maskedEmail, me)
}

func TestSignInIM(t *testing.T) {
	phone := "+11111111111"
	maskedPhone := "+*******111"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.EqualValues(t, "/v1/auth/otp/signin/im", r.URL.RequestURI())
		p, jwt := getProjectAndJwt(r)
		assert.EqualValues(t, "a", p)
		assert.Empty(t, jwt)
		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, body["loginId"])
		assert.EqualValues(t, map[string]any{"locale": "en-US"}, body["loginOptions"])
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(`{"maskedPhone":"` + maskedPhone + `","verificationAttempts":3}`))}, nil
	})
	require.NoError(t, err)
	mp, err := a.OTP().SignIn(context.Background(), descope.MethodIM, phone, nil, &descope.LoginOptions{Locale: "en-US"})
	require.NoError(t, err)
	assert.EqualValues(t, maskedPhone, mp)
}

func TestSignUpOrInIM(t *testing.T) {
	phone := "+11111111111"
	maskedPhone := "+*******111"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.EqualValues(t, "/v1/auth/otp/signup-in/im", r.URL.RequestURI())
		p, jwt := getProjectAndJwt(r)
		assert.EqualValues(t, "a", p)
		assert.Empty(t, jwt)
		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, body["loginId"])
		assert.EqualValues(t, map[string]any{"tenantId": "t1", "customClaims": map[string]any{"k1": "v1"}, "templateOptions": map[string]any{"a": "b"}}, body["loginOptions"])
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(`{"maskedPhone":"` + maskedPhone + `","verificationAttempts":3}`))}, nil
	})
	require.NoError(t, err)
	mp, err := a.OTP().SignUpOrIn(context.Background(), descope.MethodIM, phone, &descope.SignUpOptions{TenantID: "t1", CustomClaims: map[string]any{"k1": "v1"}, TemplateOptions: map[string]string{"a": "b"}})
	require.NoError(t, err)
	assert.EqualValues(t, maskedPhone, mp)
}

func TestSignUpIMNotSupported(t *testing.T) {
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	_, err = a.OTP().SignUp(context.Background(), descope.MethodIM, "+11111111111", nil, nil)
	assert.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.True(t, strings.Contains(err.Error(), "method"))
}

func TestVerifyCodeIMFullResponse(t *testing.T) {
	phone := "+11111111111"
	code := "123456"
	resBody := fmt.Sprintf(`{
		"sessionJwt": %q, "refreshJwt": %q, "cookiePath": "/", "cookieDomain": "d", "cookieMaxAge": 1, "cookieExpiration": 2,
		"firstSeen": true, "tenantSSOID": "sso1", "sessionExpiration": 3, "externalToken": "ext", "claims": {"c": "v"},
		"trustedDeviceJwt": "tdj", "nextRefreshSeconds": 4, "cookieName": "cn", "sessionCookieName": "scn", "sessionCookieDomain": "scd",
		"unsavedSSO": true, "knownDeviceJwt": "kdj", "ssoAuthenticationOnly": true, "userCreationDeferred": true, "unknownField": 1,
		"idpResponse": {"samlResponse": "sr", "samlGeneratedUser": "sgu", "samlGeneratedRoles": "sgr", "oidcResponse": "or", "oidcGeneratedUser": "ogu", "oidcGeneratedRoles": "ogr", "idpGroups": ["g"]},
		"user": {"userId": "u1", "externalIds": ["e1"], "editable": true, "push": true, "permissions": ["p1"], "consentExpiration": 5,
			"recoveryEmail": "r@e.com", "verifiedRecoveryEmail": true, "recoveryPhone": "+1222", "verifiedRecoveryPhone": true,
			"roleIds": ["r1"], "recoveryCodes": true, "consentTenantId": "ct", "lastLoginTime": 6,
			"userTenants": [{"tenantId": "t1", "roleNames": ["rn"], "roleIds": ["ri"]}]}
	}`, jwtTokenValid, jwtRTokenValid)
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.EqualValues(t, "/v1/auth/otp/verify/im", r.URL.RequestURI())
		p, jwt := getProjectAndJwt(r)
		assert.EqualValues(t, "a", p)
		assert.Empty(t, jwt)
		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, map[string]any{"loginId": phone, "code": code}, body)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(resBody))}, nil
	})
	require.NoError(t, err)
	info, err := a.OTP().VerifyCode(context.Background(), descope.MethodIM, phone, code, nil)
	require.NoError(t, err)
	assert.EqualValues(t, jwtTokenValid, info.SessionToken.JWT)
	assert.True(t, info.FirstSeen)
	assert.EqualValues(t, "sso1", info.TenantSSOID)
	assert.EqualValues(t, 3, info.SessionExpiration)
	assert.EqualValues(t, "ext", info.ExternalToken)
	assert.EqualValues(t, map[string]any{"c": "v"}, info.Claims)
	assert.EqualValues(t, "tdj", info.TrustedDeviceJWT)
	assert.EqualValues(t, 4, info.NextRefreshSeconds)
	assert.EqualValues(t, "cn", info.CookieName)
	assert.EqualValues(t, "scn", info.SessionCookieName)
	assert.EqualValues(t, "scd", info.SessionCookieDomain)
	assert.True(t, info.UnsavedSSO)
	assert.EqualValues(t, "kdj", info.KnownDeviceJWT)
	assert.True(t, info.SSOAuthenticationOnly)
	assert.True(t, info.UserCreationDeferred)
	require.NotNil(t, info.IDPResponse)
	assert.EqualValues(t, "sr", info.IDPResponse.SAMLResponse)
	assert.EqualValues(t, "sgu", info.IDPResponse.SAMLGeneratedUser)
	assert.EqualValues(t, "sgr", info.IDPResponse.SAMLGeneratedRoles)
	assert.EqualValues(t, "or", info.IDPResponse.OIDCResponse)
	assert.EqualValues(t, "ogu", info.IDPResponse.OIDCGeneratedUser)
	assert.EqualValues(t, "ogr", info.IDPResponse.OIDCGeneratedRoles)
	assert.EqualValues(t, []string{"g"}, info.IDPResponse.IDPGroups)
	u := info.User
	require.NotNil(t, u)
	assert.EqualValues(t, "u1", u.UserID)
	assert.EqualValues(t, []string{"e1"}, u.ExternalIDs)
	assert.True(t, u.Editable)
	assert.True(t, u.Push)
	assert.EqualValues(t, []string{"p1"}, u.Permissions)
	assert.EqualValues(t, 5, u.ConsentExpiration)
	assert.EqualValues(t, "r@e.com", u.RecoveryEmail)
	assert.True(t, u.VerifiedRecoveryEmail)
	assert.EqualValues(t, "+1222", u.RecoveryPhone)
	assert.True(t, u.VerifiedRecoveryPhone)
	assert.EqualValues(t, []string{"r1"}, u.RoleIDs)
	assert.True(t, u.RecoveryCodes)
	assert.EqualValues(t, "ct", u.ConsentTenantID)
	assert.EqualValues(t, 6, u.LastLoginTime)
	require.Len(t, u.UserTenants, 1)
	assert.EqualValues(t, []string{"rn"}, u.UserTenants[0].Roles)
	assert.EqualValues(t, []string{"ri"}, u.UserTenants[0].RoleIDs)
}

func TestVerifyCodeEmptyResponse(t *testing.T) {
	a, err := newTestAuth(nil, func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(""))}, nil
	})
	require.NoError(t, err)
	info, err := a.OTP().VerifyCode(context.Background(), descope.MethodSMS, "+11111111111", "123456", nil)
	require.NoError(t, err)
	assert.Empty(t, info.ExternalToken)
}

func TestVerifyCodeInvalidTokenResponse(t *testing.T) {
	a, err := newTestAuth(nil, func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(`{"sessionJwt":"bad"}`))}, nil
	})
	require.NoError(t, err)
	_, err = a.OTP().VerifyCode(context.Background(), descope.MethodSMS, "+11111111111", "123456", nil)
	assert.Error(t, err)
}

func TestUpdateEmailOTPWithLocaleAndFailOnConflict(t *testing.T) {
	loginID := "943248329844"
	email := "test@test.com"
	maskedEmail := "t***@test.com"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.EqualValues(t, "/v1/auth/otp/update/email", r.URL.RequestURI())
		p, jwt := getProjectAndJwt(r)
		assert.EqualValues(t, "a", p)
		assert.EqualValues(t, jwtTokenValid, jwt)
		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, map[string]any{"loginId": loginID, "email": email, "locale": "en-US", "failOnConflict": true}, body)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(`{"maskedEmail":"` + maskedEmail + `","verificationAttempts":3}`))}, nil
	})
	require.NoError(t, err)
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtTokenValid})
	me, err := a.OTP().UpdateUserEmail(context.Background(), loginID, email, &descope.UpdateOptions{Locale: "en-US", FailOnConflict: true}, r)
	require.NoError(t, err)
	assert.EqualValues(t, maskedEmail, me)
}

func TestUpdatePhoneOTPIM(t *testing.T) {
	loginID := "943248329844"
	phone := "+111111111111"
	maskedPhone := "+*******111"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.EqualValues(t, "/v1/auth/otp/update/phone/im", r.URL.RequestURI())
		p, jwt := getProjectAndJwt(r)
		assert.EqualValues(t, "a", p)
		assert.EqualValues(t, jwtTokenValid, jwt)
		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, map[string]any{"loginId": loginID, "phone": phone, "locale": "en-US", "failOnConflict": true}, body)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(`{"maskedPhone":"` + maskedPhone + `","verificationAttempts":3}`))}, nil
	})
	require.NoError(t, err)
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtTokenValid})
	mp, err := a.OTP().UpdateUserPhone(context.Background(), descope.MethodIM, loginID, phone, &descope.UpdateOptions{Locale: "en-US", FailOnConflict: true}, r)
	require.NoError(t, err)
	assert.EqualValues(t, maskedPhone, mp)
}
