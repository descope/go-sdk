package auth

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
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

		resp := &descope.TOTPResponse{
			ProvisioningURL: "someurl.com",
			Image:           "image",
			Key:             "my key",
		}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	token, err := a.TOTP().SignUp(loginID, &descope.User{Name: "test"})
	require.NoError(t, err)
	assert.NotNil(t, token)
}

func TestSignUpTOTPFailure(t *testing.T) {
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	_, err = a.TOTP().SignUp("", &descope.User{Name: "test"})
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

		resp := &descope.TOTPResponse{
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
	r.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtTokenValid})
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
	firstSeen := true
	name := "name"
	phone := "+11111111111"
	picture := "@(^_^)@"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeVerifyTOTPCodeURL(), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, loginID, body["loginId"])
		assert.EqualValues(t, code, body["code"])

		resp := &descope.JWTResponse{
			RefreshJwt: jwtTokenValid,
			User: &descope.UserResponse{
				User: descope.User{
					Name:  name,
					Phone: phone,
				},
				LoginIDs: []string{loginID},
				Picture:  picture,
			},
			FirstSeen: firstSeen,
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
	assert.Equal(t, firstSeen, authInfo.FirstSeen)
	assert.Equal(t, name, authInfo.User.Name)
	assert.Equal(t, phone, authInfo.User.Phone)
	assert.Equal(t, picture, authInfo.User.Picture)
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

		resp := &descope.JWTResponse{
			RefreshJwt: jwtTokenValid,
			User: &descope.UserResponse{
				LoginIDs: []string{loginID},
			},
			FirstSeen: true,
		}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	authInfo, err := a.TOTP().SignInCode(loginID, code, &http.Request{Header: http.Header{"Cookie": []string{"DSR=test"}}}, &descope.LoginOptions{Stepup: true, CustomClaims: map[string]interface{}{"k1": "v1"}}, nil)
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
