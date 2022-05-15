package auth

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func DoOk(checks func(*http.Request)) Do {
	return func(r *http.Request) (*http.Response, error) {
		if checks != nil {
			checks(r)
		}
		return &http.Response{StatusCode: http.StatusOK}, nil
	}
}

func newTestAuth(callback Do) *Auth {
	return newTestAuthConf(Config{ProjectID: "a"}, callback)
}

func newTestAuthConf(conf Config, callback Do) *Auth {
	conf.DefaultClient = newTestClient(callback)
	auth := NewAuth(conf)
	return auth
}

func TestEnvVariableProjectID(t *testing.T) {
	expectedProjectID := "test"
	err := os.Setenv("PROJECT_ID", expectedProjectID)
	defer func() {
		err = os.Setenv("PROJECT_ID", "")
		require.NoError(t, err)
	}()
	require.NoError(t, err)
	a := NewAuth(Config{})
	err = a.prepareClient()
	require.NoError(t, err)
	assert.EqualValues(t, expectedProjectID, a.conf.ProjectID)
}

func TestInvalidEmailSignInEmail(t *testing.T) {
	email := "notavalidemail"
	a := newTestAuth(nil)
	err := a.SignInOTP(MethodEmail, email)
	require.Error(t, err)
	assert.EqualValues(t, badRequestErrorCode, err.(*WebError).Code)
}

func TestInvalidPhoneSignInSMS(t *testing.T) {
	phone := "thisisemail@af.com"
	a := newTestAuth(nil)
	err := a.SignInOTP(MethodSMS, phone)
	require.Error(t, err)
	assert.EqualValues(t, badRequestErrorCode, err.(*WebError).Code)
}

func TestInvalidPhoneSignInWhatsApp(t *testing.T) {
	phone := "thisisemail@af.com"
	a := newTestAuth(nil)
	err := a.SignInOTP(MethodWhatsApp, phone)
	require.Error(t, err)
	assert.EqualValues(t, badRequestErrorCode, err.(*WebError).Code)
}

func TestValidEmailSignInEmail(t *testing.T) {
	email := "test@email.com"
	a := newTestAuth(DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeSignInURL(MethodEmail), r.URL.RequestURI())
		body, err := readBody(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, body["email"])
	}))
	err := a.SignInOTP(MethodEmail, email)
	require.NoError(t, err)
}

func TestInvalidPhoneSignUpSMS(t *testing.T) {
	phone := "thisisemail@af.com"
	a := newTestAuth(nil)
	err := a.SignUpOTP(MethodSMS, phone, &User{Username: "test"})
	require.Error(t, err)
	assert.EqualValues(t, badRequestErrorCode, err.(*WebError).Code)
}

func TestInvalidPhoneSignUpWhatsApp(t *testing.T) {
	phone := "thisisemail@af.com"
	a := newTestAuth(nil)
	err := a.SignUpOTP(MethodSMS, phone, &User{Username: "test"})
	require.Error(t, err)
	assert.EqualValues(t, badRequestErrorCode, err.(*WebError).Code)
}

func TestInvalidEmailSignUpEmail(t *testing.T) {
	email := "943248329844"
	a := newTestAuth(nil)
	err := a.SignUpOTP(MethodEmail, email, &User{Username: "test"})
	require.Error(t, err)
	assert.EqualValues(t, badRequestErrorCode, err.(*WebError).Code)
}

func TestSignUpEmail(t *testing.T) {
	email := "test@email.com"
	a := newTestAuth(DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeSignUpURL(MethodEmail), r.URL.RequestURI())

		m, err := readBody(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["email"])
		assert.EqualValues(t, "test", m["user"].(map[string]interface{})["username"])
	}))
	err := a.SignUpOTP(MethodEmail, email, &User{Username: "test"})
	require.NoError(t, err)
}

func TestSignUpSMS(t *testing.T) {
	phone := "943248329844"
	a := newTestAuth(DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeSignUpURL(MethodSMS), r.URL.RequestURI())

		body, err := readBody(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, body["phone"])
		assert.EqualValues(t, "test", body["user"].(map[string]interface{})["username"])
	}))
	err := a.SignUpOTP(MethodSMS, phone, &User{Username: "test"})
	require.NoError(t, err)
}

func TestSignUpWhatsApp(t *testing.T) {
	phone := "943248329844"
	a := newTestAuth(DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeSignUpURL(MethodWhatsApp), r.URL.RequestURI())

		body, err := readBody(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, body["whatsapp"])
		assert.EqualValues(t, "test", body["user"].(map[string]interface{})["username"])
	}))
	err := a.SignUpOTP(MethodWhatsApp, phone, &User{Username: "test"})
	require.NoError(t, err)
}

func TestInvalidEmailVerifyCodeEmail(t *testing.T) {
	email := "943248329844"
	a := newTestAuth(nil)
	_, err := a.VerifyCodeEmail(email, "4444")
	require.Error(t, err)
	assert.EqualValues(t, badRequestErrorCode, err.(*WebError).Code)
}

func TestInvalidPhoneVerifyCodeSMS(t *testing.T) {
	phone := "ahaatest"
	a := newTestAuth(nil)
	_, err := a.VerifyCodeSMS(phone, "4444")
	require.Error(t, err)
	assert.EqualValues(t, badRequestErrorCode, err.(*WebError).Code)
}

func TestInvalidVerifyCode(t *testing.T) {
	email := "a"
	a := newTestAuth(nil)
	_, err := a.VerifyCode("", email, "4444")
	require.Error(t, err)
	assert.EqualValues(t, badRequestErrorCode, err.(*WebError).Code)
}

func TestVerifyCodeWithPhone(t *testing.T) {
	phone := "7753131313"
	a := newTestAuth(DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeVerifyCodeURL(MethodSMS), r.URL.RequestURI())

		body, err := readBody(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, body["phone"])
		assert.EqualValues(t, "4444", body["code"])
	}))
	_, err := a.VerifyCode(MethodSMS, phone, "4444")
	require.NoError(t, err)
}

func TestVerifyCodeEmail(t *testing.T) {
	email := "test@email.com"
	code := "4914"
	a := newTestAuth(DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeVerifyCodeURL(MethodEmail), r.URL.RequestURI())

		body, err := readBody(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, body["email"])
		assert.EqualValues(t, code, body["code"])
	}))
	_, err := a.VerifyCodeEmail(email, code)
	require.Nil(t, err)
}

func TestVerifyCodeSMS(t *testing.T) {
	phone := "943248329844"
	code := "4914"
	a := newTestAuth(DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeVerifyCodeURL(MethodSMS), r.URL.RequestURI())

		body, err := readBody(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, body["phone"])
		assert.EqualValues(t, code, body["code"])
	}))
	_, err := a.VerifyCodeSMS(phone, code)
	require.NoError(t, err)
}

func TestVerifyCodeWhatsApp(t *testing.T) {
	phone := "943248329844"
	code := "4914"
	a := newTestAuth(DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeVerifyCodeURL(MethodWhatsApp), r.URL.RequestURI())

		body, err := readBody(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, body["whatsapp"])
		assert.EqualValues(t, code, body["code"])
	}))
	_, err := a.VerifyCodeWhatsApp(phone, code)
	require.NoError(t, err)
}

func TestAuthDefaultURL(t *testing.T) {
	url := "http://test.com"
	a := newTestAuthConf(Config{ProjectID: "a", DefaultURL: url}, DoOk(func(r *http.Request) {
		assert.Contains(t, r.URL.String(), url)
	}))
	_, err := a.VerifyCodeWhatsApp("4444", "444")
	require.NoError(t, err)
}

var (
	jwtTokenValid   = `eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCIsImtpZCI6IjMyYjNkYTUyNzdiMTQyYzdlMjRmZGYwZWYwOWUwOTE5In0.eyJleHAiOjE5ODEzOTgxMTF9.GQ3nLYT4XWZWezJ1tRV6ET0ibRvpEipeo6RCuaCQBdP67yu98vtmUvusBElDYVzRxGRtw5d20HICyo0_3Ekb0euUP3iTupgS3EU1DJMeAaJQgOwhdQnQcJFkOpASLKWh`
	jwtTokenExpired = `eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzM4NCIsImtpZCI6IjMyYjNkYTUyNzdiMTQyYzdlMjRmZGYwZWYwOWUwOTE5In0.eyJleHAiOjExODEzOTgxMTF9.EdetpQro-frJV1St1mWGygRSzxf6Bg01NNR_Ipwy_CAQyGDmIQ6ITGQ620hfmjW5HDtZ9-0k7AZnwoLnb709QQgbHMFxlDpIOwtFIAJuU-CqaBDwsNWA1f1RNyPpLxop`
	publicKey       = `{
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
)

func TestEmptyPublicKey(t *testing.T) {
	a := newTestAuthConf(Config{ProjectID: "a"}, DoOk(nil))
	ok, err := a.ValidateSession("test")
	require.False(t, ok)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "public key was not initialized")
}

func TestValidateSession(t *testing.T) {
	a := newTestAuthConf(Config{ProjectID: "a", PublicKey: publicKey}, DoOk(nil))
	ok, err := a.ValidateSession(jwtTokenValid)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestValidateSessionRequest(t *testing.T) {
	a := newTestAuthConf(Config{ProjectID: "a", PublicKey: publicKey}, DoOk(nil))
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: CookieDefaultName, Value: jwtTokenValid})
	ok, err := a.ValidateSessionRequest(request)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestValidateSessionRequestNoCookie(t *testing.T) {
	a := newTestAuthConf(Config{ProjectID: "a", PublicKey: publicKey}, DoOk(nil))
	request := &http.Request{Header: http.Header{}}
	ok, err := a.ValidateSessionRequest(request)
	require.Error(t, err)
	require.False(t, ok)
}

func TestValidateSessionExpired(t *testing.T) {
	a := newTestAuthConf(Config{ProjectID: "a", PublicKey: publicKey}, DoOk(nil))
	ok, err := a.ValidateSession(jwtTokenExpired)
	require.Error(t, err)
	require.False(t, ok)
	assert.EqualValues(t, badRequestErrorCode, err.(*WebError).Code)
}

func readBody(r *http.Request) (m map[string]interface{}, err error) {
	res, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(res, &m)
	return
}
