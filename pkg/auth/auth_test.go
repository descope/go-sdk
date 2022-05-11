package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestAuth(callback func(uriPath string, body interface{}) ([]byte, *WebError)) *Auth {
	auth := NewAuth()
	auth.client = newTestClient(callback)
	return auth
}

type mockClient struct {
	callback func(uriPath string, body interface{}) ([]byte, *WebError)
}

func newTestClient(callback func(uriPath string, body interface{}) ([]byte, *WebError)) *mockClient {
	return &mockClient{callback: callback}
}

func (c *mockClient) post(uriPath string, body interface{}) ([]byte, *WebError) {
	if c.callback == nil {
		return nil, nil
	}
	return c.callback(uriPath, body)
}

func TestInvalidEmailSignInEmail(t *testing.T) {
	email := "notavalidemail"
	a := newTestAuth(nil)
	err := a.SignInEmail(email)
	require.Error(t, err)
	assert.EqualValues(t, badRequestErrorCode, err.Code)
}

func TestInvalidPhoneSignInPhone(t *testing.T) {
	phone := "thisisemail@af.com"
	a := newTestAuth(nil)
	err := a.SignInPhone(phone)
	require.Error(t, err)
	assert.EqualValues(t, badRequestErrorCode, err.Code)
}

func TestInvalidPhoneSignInWhatsapp(t *testing.T) {
	phone := "thisisemail@af.com"
	a := newTestAuth(nil)
	err := a.SignInWhatsapp(phone)
	require.Error(t, err)
	assert.EqualValues(t, badRequestErrorCode, err.Code)
}

func TestValidEmailSignInEmail(t *testing.T) {
	email := "test@email.com"
	a := newTestAuth(func(uriPath string, body interface{}) ([]byte, *WebError) {
		assert.EqualValues(t, signInURL(emailMethod), uriPath)
		assert.EqualValues(t, map[string]interface{}{"email": email}, body.(map[string]interface{})["identifiers"])
		return nil, nil
	})
	err := a.SignInEmail(email)
	require.Nil(t, err)
}

func TestSignUpEmail(t *testing.T) {
	email := "test@email.com"
	a := newTestAuth(func(uriPath string, body interface{}) ([]byte, *WebError) {
		assert.EqualValues(t, signUpURL(emailMethod), uriPath)

		m := body.(map[string]interface{})
		assert.EqualValues(t, map[string]interface{}{"email": email}, m["identifiers"])
		assert.EqualValues(t, "test", m["user"].(*User).Username)
		return nil, nil
	})
	err := a.SignUpEmail(email, &User{Username: "test"})
	require.Nil(t, err)
}
