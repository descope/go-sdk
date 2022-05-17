package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
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

func newTestAuth(callback Do) (*Auth, error) {
	return newTestAuthConf(nil, callback)
}

func newTestAuthConf(confBuilder *ConfigBuilder, callback Do) (*Auth, error) {
	if confBuilder == nil {
		confBuilder = newTestConfig()
	}
	conf := *confBuilder.Build()
	conf.DefaultClient = newTestClient(callback)
	return NewAuth(conf)
}

func TestEnvVariableProjectID(t *testing.T) {
	expectedProjectID := "test"
	err := os.Setenv(environmentVariableProjectID, expectedProjectID)
	defer func() {
		err = os.Setenv(environmentVariableProjectID, "")
		require.NoError(t, err)
	}()
	require.NoError(t, err)
	a, err := NewAuth(Config{})
	require.NoError(t, err)
	assert.EqualValues(t, expectedProjectID, a.conf.ProjectID)
}

func TestEnvVariablePublicKey(t *testing.T) {
	expectedPublicKey := "test"
	err := os.Setenv(environmentVariablePublicKey, expectedPublicKey)
	defer func() {
		err = os.Setenv(environmentVariablePublicKey, "")
		require.NoError(t, err)
	}()
	require.NoError(t, err)
	a, err := newTestAuth(nil)
	require.NoError(t, err)
	assert.EqualValues(t, expectedPublicKey, a.conf.PublicKey)
}

func TestEmptyProjectID(t *testing.T) {
	_, err := NewAuth(Config{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project id is missing")
}

func TestVerifyDeliveryMethodEmptyIdentifier(t *testing.T) {
	a, err := newTestAuth(nil)
	require.NoError(t, err)
	err = a.verifyDeliveryMethod(MethodEmail, "")
	assert.EqualValues(t, badRequestErrorCode, err.(*WebError).Code)
}

func TestInvalidEmailSignInEmail(t *testing.T) {
	email := "notavalidemail"
	a, err := newTestAuth(nil)
	require.NoError(t, err)
	err = a.SignInOTP(MethodEmail, email)
	require.Error(t, err)
	assert.EqualValues(t, badRequestErrorCode, err.(*WebError).Code)
}

func TestInvalidPhoneSignInSMS(t *testing.T) {
	phone := "thisisemail@af.com"
	a, err := newTestAuth(nil)
	require.NoError(t, err)
	err = a.SignInOTP(MethodSMS, phone)
	require.Error(t, err)
	assert.EqualValues(t, badRequestErrorCode, err.(*WebError).Code)
}

func TestInvalidPhoneSignInWhatsApp(t *testing.T) {
	phone := "thisisemail@af.com"
	a, err := newTestAuth(nil)
	require.NoError(t, err)
	err = a.SignInOTP(MethodWhatsApp, phone)
	require.Error(t, err)
	assert.EqualValues(t, badRequestErrorCode, err.(*WebError).Code)
}

func TestValidEmailSignInEmail(t *testing.T) {
	email := "test@email.com"
	a, err := newTestAuth(DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeSignInURL(MethodEmail), r.URL.RequestURI())
		body, err := readBody(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, body["email"])
	}))
	require.NoError(t, err)
	err = a.SignInOTP(MethodEmail, email)
	require.NoError(t, err)
}

func TestInvalidPhoneSignUpSMS(t *testing.T) {
	phone := "thisisemail@af.com"
	a, err := newTestAuth(nil)
	require.NoError(t, err)
	err = a.SignUpOTP(MethodSMS, phone, &User{Username: "test"})
	require.Error(t, err)
	assert.EqualValues(t, badRequestErrorCode, err.(*WebError).Code)
}

func TestInvalidPhoneSignUpWhatsApp(t *testing.T) {
	phone := "thisisemail@af.com"
	a, err := newTestAuth(nil)
	require.NoError(t, err)
	err = a.SignUpOTP(MethodSMS, phone, &User{Username: "test"})
	require.Error(t, err)
	assert.EqualValues(t, badRequestErrorCode, err.(*WebError).Code)
}

func TestInvalidEmailSignUpEmail(t *testing.T) {
	email := "943248329844"
	a, err := newTestAuth(nil)
	require.NoError(t, err)
	err = a.SignUpOTP(MethodEmail, email, &User{Username: "test"})
	require.Error(t, err)
	assert.EqualValues(t, badRequestErrorCode, err.(*WebError).Code)
}

func TestSignUpEmail(t *testing.T) {
	email := "test@email.com"
	a, err := newTestAuth(DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeSignUpURL(MethodEmail), r.URL.RequestURI())

		m, err := readBody(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["email"])
		assert.EqualValues(t, "test", m["user"].(map[string]interface{})["username"])
	}))
	require.NoError(t, err)
	err = a.SignUpOTP(MethodEmail, email, &User{Username: "test"})
	require.NoError(t, err)
}

func TestSignUpSMS(t *testing.T) {
	phone := "943248329844"
	a, err := newTestAuth(DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeSignUpURL(MethodSMS), r.URL.RequestURI())

		body, err := readBody(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, body["phone"])
		assert.EqualValues(t, "test", body["user"].(map[string]interface{})["username"])
	}))
	require.NoError(t, err)
	err = a.SignUpOTP(MethodSMS, phone, &User{Username: "test"})
	require.NoError(t, err)
}

func TestSignUpWhatsApp(t *testing.T) {
	phone := "943248329844"
	a, err := newTestAuth(DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeSignUpURL(MethodWhatsApp), r.URL.RequestURI())

		body, err := readBody(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, body["whatsapp"])
		assert.EqualValues(t, "test", body["user"].(map[string]interface{})["username"])
	}))
	require.NoError(t, err)
	err = a.SignUpOTP(MethodWhatsApp, phone, &User{Username: "test"})
	require.NoError(t, err)
}

func TestInvalidEmailVerifyCodeEmail(t *testing.T) {
	email := "943248329844"
	a, err := newTestAuth(nil)
	require.NoError(t, err)
	_, err = a.VerifyCodeEmail(email, "4444")
	require.Error(t, err)
	assert.EqualValues(t, badRequestErrorCode, err.(*WebError).Code)
}

func TestInvalidPhoneVerifyCodeSMS(t *testing.T) {
	phone := "ahaatest"
	a, err := newTestAuth(nil)
	require.NoError(t, err)
	_, err = a.VerifyCodeSMS(phone, "4444")
	require.Error(t, err)
	assert.EqualValues(t, badRequestErrorCode, err.(*WebError).Code)
}

func TestInvalidVerifyCode(t *testing.T) {
	email := "a"
	a, err := newTestAuth(nil)
	require.NoError(t, err)
	_, err = a.VerifyCode("", email, "4444")
	require.Error(t, err)
	assert.EqualValues(t, badRequestErrorCode, err.(*WebError).Code)
}

func TestVerifyCodeDetectEmail(t *testing.T) {
	email := "test@test.com"
	a, err := newTestAuth(DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeVerifyCodeURL(MethodEmail), r.URL.RequestURI())

		body, err := readBody(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, body["email"])
	}))
	require.NoError(t, err)
	_, err = a.VerifyCode("", email, "555")
	require.NoError(t, err)
}

func TestVerifyCodeDetectPhone(t *testing.T) {
	phone := "74987539043"
	a, err := newTestAuth(DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeVerifyCodeURL(MethodSMS), r.URL.RequestURI())

		body, err := readBody(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, body["phone"])
	}))
	require.NoError(t, err)
	_, err = a.VerifyCode("", phone, "555")
	require.NoError(t, err)
}

func TestVerifyCodeWithPhone(t *testing.T) {
	phone := "7753131313"
	a, err := newTestAuth(DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeVerifyCodeURL(MethodSMS), r.URL.RequestURI())

		body, err := readBody(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, body["phone"])
		assert.EqualValues(t, "4444", body["code"])
	}))
	require.NoError(t, err)
	_, err = a.VerifyCode(MethodSMS, phone, "4444")
	require.NoError(t, err)
}

func TestVerifyCodeEmail(t *testing.T) {
	email := "test@email.com"
	code := "4914"
	a, err := newTestAuth(DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeVerifyCodeURL(MethodEmail), r.URL.RequestURI())

		body, err := readBody(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, body["email"])
		assert.EqualValues(t, code, body["code"])
	}))
	require.NoError(t, err)
	_, err = a.VerifyCodeEmail(email, code)
	require.Nil(t, err)
}

func TestVerifyCodeSMS(t *testing.T) {
	phone := "943248329844"
	code := "4914"
	a, err := newTestAuth(DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeVerifyCodeURL(MethodSMS), r.URL.RequestURI())

		body, err := readBody(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, body["phone"])
		assert.EqualValues(t, code, body["code"])
	}))
	require.NoError(t, err)
	_, err = a.VerifyCodeSMS(phone, code)
	require.NoError(t, err)
}

func TestVerifyCodeWhatsApp(t *testing.T) {
	phone := "943248329844"
	code := "4914"
	a, err := newTestAuth(DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeVerifyCodeURL(MethodWhatsApp), r.URL.RequestURI())

		body, err := readBody(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, body["whatsapp"])
		assert.EqualValues(t, code, body["code"])
	}))
	require.NoError(t, err)
	_, err = a.VerifyCodeWhatsApp(phone, code)
	require.NoError(t, err)
}

func TestAuthDefaultURL(t *testing.T) {
	url := "http://test.com"
	a, err := newTestAuthConf(newTestConfig().WithDefaultURL(url), DoOk(func(r *http.Request) {
		assert.Contains(t, r.URL.String(), url)
	}))
	require.NoError(t, err)
	_, err = a.VerifyCodeWhatsApp("4444", "444")
	require.NoError(t, err)
}

func TestEmptyPublicKey(t *testing.T) {
	a, err := newTestAuthConf(nil, Do(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("[]"))}, nil
	}))
	require.NoError(t, err)
	ok, err := a.ValidateSession(jwtTokenExpired)
	require.False(t, ok)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no public key was found")
}

func TestErrorFetchPublicKey(t *testing.T) {
	a, err := newTestAuthConf(nil, Do(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusInternalServerError, Body: io.NopCloser(strings.NewReader("what"))}, nil
	}))
	require.NoError(t, err)
	ok, err := a.ValidateSession(jwtTokenExpired)
	require.False(t, ok)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no public key was found")
}

func TestValidateSession(t *testing.T) {
	a, err := newTestAuthConf(newTestConfig().WithValidKey(), DoOk(nil))
	require.NoError(t, err)
	ok, err := a.ValidateSession(jwtTokenValid)
	require.NoError(t, err)
	require.True(t, ok)
	ok, err = a.ValidateSession(jwtTokenValid)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestValidateSessionFetchKeyCalledOnce(t *testing.T) {
	count := 0
	a, err := newTestAuthConf(nil, Do(func(r *http.Request) (*http.Response, error) {
		count++
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(fmt.Sprintf("[%s]", publicKey)))}, nil
	}))
	require.NoError(t, err)
	ok, err := a.ValidateSession(jwtTokenValid)
	require.NoError(t, err)
	require.True(t, ok)
	require.EqualValues(t, 1, count)
	ok, err = a.ValidateSession(jwtTokenValid)
	require.NoError(t, err)
	require.True(t, ok)
	require.EqualValues(t, 1, count)
}

func TestValidateSessionFetchKeyMalformed(t *testing.T) {
	a, err := newTestAuthConf(nil, Do(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(fmt.Sprintf("[%s]", unknownPublicKey)))}, nil
	}))
	require.NoError(t, err)
	ok, err := a.ValidateSession(jwtTokenValid)
	require.Error(t, err)
	assert.EqualValues(t, badRequestErrorCode, err.(*WebError).Code)
	require.False(t, ok)
}

func TestValidateSessionFailWithInvalidKey(t *testing.T) {
	count := 0
	a, err := newTestAuthConf(newTestConfig().WithUnkownKey(), Do(func(r *http.Request) (*http.Response, error) {
		count++
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(fmt.Sprintf("[%s]", publicKey)))}, nil
	}))
	require.NoError(t, err)
	ok, err := a.ValidateSession(jwtTokenValid)
	require.Error(t, err)
	assert.EqualValues(t, badRequestErrorCode, err.(*WebError).Code)
	require.False(t, ok)
	require.Zero(t, count)
}

func TestValidateSessionRequest(t *testing.T) {
	a, err := newTestAuthConf(newTestConfig().WithValidKey(), DoOk(nil))
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: CookieDefaultName, Value: jwtTokenValid})
	ok, err := a.ValidateSessionRequest(request)
	require.NoError(t, err)
	require.True(t, ok)
}

func TestValidateSessionRequestNoCookie(t *testing.T) {
	a, err := newTestAuthConf(newTestConfig().WithValidKey(), DoOk(nil))
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	ok, err := a.ValidateSessionRequest(request)
	require.Error(t, err)
	require.False(t, ok)
}

func TestValidateSessionExpired(t *testing.T) {
	a, err := newTestAuthConf(newTestConfig().WithValidKey(), DoOk(nil))
	require.NoError(t, err)
	ok, err := a.ValidateSession(jwtTokenExpired)
	require.Error(t, err)
	require.False(t, ok)
	assert.EqualValues(t, badRequestErrorCode, err.(*WebError).Code)
}

func TestValidateSessionNotYet(t *testing.T) {
	a, err := newTestAuthConf(newTestConfig().WithValidKey(), DoOk(nil))
	require.NoError(t, err)
	ok, err := a.ValidateSession(jwtTokenNotYet)
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
