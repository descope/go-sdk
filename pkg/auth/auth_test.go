package auth

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestAuth(callback func(uriPath string, body interface{}) ([]byte, *http.Response, error)) *Auth {
	auth := NewAuth(Config{})
	auth.client = newTestClient(callback)
	return auth
}

type mockClient struct {
	callback func(uriPath string, body interface{}) ([]byte, *http.Response, error)
}

func newTestClient(callback func(uriPath string, body interface{}) ([]byte, *http.Response, error)) *mockClient {
	return &mockClient{callback: callback}
}

func (c *mockClient) Post(uriPath string, body interface{}) ([]byte, *http.Response, error) {
	if c.callback == nil {
		return nil, nil, nil
	}
	return c.callback(uriPath, body)
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
	a := newTestAuth(func(uriPath string, body interface{}) ([]byte, *http.Response, error) {
		assert.EqualValues(t, composeSignInURL(MethodEmail), uriPath)
		assert.EqualValues(t, email, body.(map[string]interface{})["email"])
		return nil, nil, nil
	})
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
	a := newTestAuth(func(uriPath string, body interface{}) ([]byte, *http.Response, error) {
		assert.EqualValues(t, composeSignUpURL(MethodEmail), uriPath)

		m := body.(map[string]interface{})
		assert.EqualValues(t, email, m["email"])
		assert.EqualValues(t, "test", m["user"].(*User).Username)
		return nil, nil, nil
	})
	err := a.SignUpOTP(MethodEmail, email, &User{Username: "test"})
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

func TestVerifyCodeEmail(t *testing.T) {
	email := "test@email.com"
	code := "4914"
	a := newTestAuth(func(uriPath string, body interface{}) ([]byte, *http.Response, error) {
		assert.EqualValues(t, composeVerifyCodeURL(MethodEmail), uriPath)

		m := body.(map[string]interface{})
		assert.EqualValues(t, email, m["email"])
		assert.EqualValues(t, code, m["code"])
		return nil, nil, nil
	})
	_, err := a.VerifyCodeEmail(email, code)
	require.Nil(t, err)
}

func TestVerifyCodeSMS(t *testing.T) {
	phone := "943248329844"
	code := "4914"
	a := newTestAuth(func(uriPath string, body interface{}) ([]byte, *http.Response, error) {
		assert.EqualValues(t, composeVerifyCodeURL(MethodSMS), uriPath)

		m := body.(map[string]interface{})
		assert.EqualValues(t, phone, m["phone"])
		assert.EqualValues(t, code, m["code"])
		return nil, nil, nil
	})
	_, err := a.VerifyCodeSMS(phone, code)
	require.NoError(t, err)
}

func TestVerifyCodeWhatsApp(t *testing.T) {
	phone := "943248329844"
	code := "4914"
	a := newTestAuth(func(uriPath string, body interface{}) ([]byte, *http.Response, error) {
		assert.EqualValues(t, composeVerifyCodeURL(MethodWhatsApp), uriPath)

		m := body.(map[string]interface{})
		assert.EqualValues(t, phone, m["whatsapp"])
		assert.EqualValues(t, code, m["code"])
		return nil, nil, nil
	})
	_, err := a.VerifyCodeWhatsApp(phone, code)
	require.NoError(t, err)
}
