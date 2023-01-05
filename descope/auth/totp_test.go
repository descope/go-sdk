package auth

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignUp(t *testing.T) {
	loginID := "someID"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeSignUpTOTPURL(), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, loginID, body["loginId"])
		assert.EqualValues(t, "test", body["user"].(map[string]interface{})["name"])

		resp := &TOTPResponse{
			ProvisioningURL: "someurl.com",
			Image:           "image",
			Key:             "my key",
		}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	token, err := a.TOTP().SignUp(loginID, &User{Name: "test"})
	require.NoError(t, err)
	assert.NotNil(t, token)
}

func TestSignUpTOTPFailure(t *testing.T) {
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	_, err = a.TOTP().SignUp("", &User{Name: "test"})
	assert.Error(t, err)
}

func TestUpdateTOTP(t *testing.T) {
	loginID := "someID"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeUpdateTOTPURL(), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, loginID, body["loginId"])
		assert.Nil(t, body["user"])

		u, p := getProjectAndJwt(r)
		assert.NotEmpty(t, u)
		assert.NotEmpty(t, p)

		resp := &TOTPResponse{
			ProvisioningURL: "someurl.com",
			Image:           "image",
			Key:             "my key",
		}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtTokenValid})
	token, err := a.TOTP().UpdateUser(loginID, r)
	require.NoError(t, err)
	assert.NotNil(t, token)
}

func TestUpodateTOTPFailure(t *testing.T) {
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	r := &http.Request{Header: http.Header{}}
	_, err = a.TOTP().UpdateUser("", r)
	assert.Error(t, err)
}

func TestVerifyTOTP(t *testing.T) {
	loginID := "someID"
	code := "123456"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeVerifyTOTPCodeURL(), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, loginID, body["loginId"])
		assert.EqualValues(t, code, body["code"])

		resp := &JWTResponse{
			RefreshJwt: jwtTokenValid,
			User: &UserResponse{
				LoginIDs: []string{loginID},
			},
			FirstSeen: true,
		}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	authInfo, err := a.TOTP().SignInCode(loginID, code, nil, nil, nil)
	require.NoError(t, err)
	assert.NotNil(t, authInfo)
	assert.True(t, authInfo.FirstSeen)
	assert.EqualValues(t, loginID, authInfo.User.LoginIDs[0])
}

func TestVerifyTOTPLoginOptions(t *testing.T) {
	loginID := "someID"
	code := "123456"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeVerifyTOTPCodeURL(), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, loginID, body["loginId"])
		assert.EqualValues(t, code, body["code"])
		assert.EqualValues(t, map[string]interface{}{"stepup": true, "customClaims": map[string]interface{}{"k1": "v1"}}, body["loginOptions"])
		reqToken := r.Header.Get(api.AuthorizationHeaderName)
		splitToken := strings.Split(reqToken, api.BearerAuthorizationPrefix)
		require.Len(t, splitToken, 2)
		bearer := splitToken[1]
		bearers := strings.Split(bearer, ":")
		require.Len(t, bearers, 2)
		assert.EqualValues(t, "test", bearers[1])

		resp := &JWTResponse{
			RefreshJwt: jwtTokenValid,
			User: &UserResponse{
				LoginIDs: []string{loginID},
			},
			FirstSeen: true,
		}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	authInfo, err := a.TOTP().SignInCode(loginID, code, &http.Request{Header: http.Header{"Cookie": []string{"DSR=test"}}}, &LoginOptions{Stepup: true, CustomClaims: map[string]interface{}{"k1": "v1"}}, nil)
	require.NoError(t, err)
	assert.NotNil(t, authInfo)
	assert.True(t, authInfo.FirstSeen)
	assert.EqualValues(t, loginID, authInfo.User.LoginIDs[0])
}

func TestVerifyTOTPFailure(t *testing.T) {
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	_, err = a.TOTP().SignInCode("", "code", nil, nil, nil)
	assert.Error(t, err)

}
