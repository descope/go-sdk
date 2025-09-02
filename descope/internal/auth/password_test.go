package auth

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/tests/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPasswordSignUp(t *testing.T) {
	loginID := "someID"
	password := "password"
	name := "foo"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, api.Routes.SignUpPassword(), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, loginID, body["loginId"])
		assert.NotNil(t, body["user"])
		assert.EqualValues(t, password, body["password"])

		resp := &descope.JWTResponse{
			RefreshJwt: jwtTokenValid,
			User: &descope.UserResponse{
				User: descope.User{
					Name: name,
				},
				LoginIDs: []string{loginID},
			},
			FirstSeen: true,
		}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	authInfo, err := a.Password().SignUp(context.Background(), loginID, nil, password, nil)
	require.NoError(t, err)
	assert.NotNil(t, authInfo)
	assert.EqualValues(t, loginID, authInfo.User.LoginIDs[0])
	assert.True(t, authInfo.FirstSeen)
	assert.Equal(t, name, authInfo.User.Name)
}

func TestPasswordSignUpFailure(t *testing.T) {
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	_, err = a.Password().SignUp(context.Background(), "", &descope.User{Name: "test"}, "foo", nil)
	assert.Error(t, err)
}

func TestPasswordSignIn(t *testing.T) {
	loginID := "someID"
	password := "password"
	name := "foo"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, api.Routes.SignInPassword(), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, loginID, body["loginId"])
		assert.EqualValues(t, password, body["password"])

		resp := &descope.JWTResponse{
			RefreshJwt: jwtTokenValid,
			User: &descope.UserResponse{
				User: descope.User{
					Name: name,
				},
				LoginIDs: []string{loginID},
			},
			FirstSeen: false,
		}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	authInfo, err := a.Password().SignIn(context.Background(), loginID, password, nil)
	require.NoError(t, err)
	assert.NotNil(t, authInfo)
	assert.EqualValues(t, loginID, authInfo.User.LoginIDs[0])
	assert.False(t, authInfo.FirstSeen)
	assert.Equal(t, name, authInfo.User.Name)
}

func TestPasswordSignInFailure(t *testing.T) {
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	_, err = a.Password().SignIn(context.Background(), "", "foo", nil)
	assert.Error(t, err)
}

func TestPasswordSendReset(t *testing.T) {
	loginID := "someID"
	url := "https://test.com"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, api.Routes.SendResetPassword(), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, loginID, body["loginId"])
		assert.EqualValues(t, url, body["redirectUrl"])
		assert.EqualValues(t, map[string]any{"cc": "dd"}, body["templateOptions"])

		respBytes, err := utils.Marshal("")
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	err = a.Password().SendPasswordReset(context.Background(), loginID, url, map[string]string{"cc": "dd"})
	require.NoError(t, err)
}

func TestPasswordSendResetFailure(t *testing.T) {
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	err = a.Password().SendPasswordReset(context.Background(), "", "", nil)
	assert.Error(t, err)
}

func TestPasswordUpdate(t *testing.T) {
	loginID := "someID"
	newPassword := "abc123!@#"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, api.Routes.UpdateUserPassword(), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, loginID, body["loginId"])
		assert.EqualValues(t, newPassword, body["newPassword"])

		respBytes, err := utils.Marshal("")
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtTokenValid})
	err = a.Password().UpdateUserPassword(context.Background(), loginID, newPassword, r)
	require.NoError(t, err)
}

func TestPasswordUpdateFailure(t *testing.T) {
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	err = a.Password().UpdateUserPassword(context.Background(), "", "", nil)
	assert.Error(t, err)
	err = a.Password().UpdateUserPassword(context.Background(), "a@b.c", "", nil)
	assert.Error(t, err)
}

func TestPasswordReplace(t *testing.T) {
	loginID := "someID"
	name := "foo"
	oldPassword := "abc123!@"
	newPassword := "abc123!@#"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, api.Routes.ReplaceUserPassword(), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, loginID, body["loginId"])
		assert.EqualValues(t, oldPassword, body["oldPassword"])
		assert.EqualValues(t, newPassword, body["newPassword"])

		resp := &descope.JWTResponse{
			RefreshJwt: jwtTokenValid,
			User: &descope.UserResponse{
				User: descope.User{
					Name: name,
				},
				LoginIDs: []string{loginID},
			},
			FirstSeen: false,
		}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)

		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	authInfo, err := a.Password().ReplaceUserPassword(context.Background(), loginID, oldPassword, newPassword, nil)
	require.NoError(t, err)
	assert.NotNil(t, authInfo)
	assert.EqualValues(t, loginID, authInfo.User.LoginIDs[0])
	assert.False(t, authInfo.FirstSeen)
	assert.Equal(t, name, authInfo.User.Name)
}

func TestPasswordReplaceFailure(t *testing.T) {
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	_, err = a.Password().ReplaceUserPassword(context.Background(), "", "", "", nil)
	assert.Error(t, err)
}

func TestPasswordPolicy(t *testing.T) {
	response := map[string]any{"minLength": int32(8)}
	a, err := newTestAuth(nil, helpers.DoOkWithBody(nil, response))
	require.NoError(t, err)
	require.NotNil(t, a)
	res, err := a.Password().GetPasswordPolicy(context.Background())
	require.NoError(t, err)
	require.NotNil(t, res)
	require.EqualValues(t, 8, res.MinLength)
}

func TestPasswordPolicyFailure(t *testing.T) {
	a, err := newTestAuth(nil, helpers.DoOkWithBody(nil, ""))
	require.NoError(t, err)
	require.NotNil(t, a)
	res, err := a.Password().GetPasswordPolicy(context.Background())
	require.Error(t, err)
	require.Nil(t, res)
	a, err = newTestAuth(nil, helpers.DoOkWithBody(nil, map[string]any{"minLength": "unexpected-string"}))
	require.NoError(t, err)
	require.NotNil(t, a)
	res, err = a.Password().GetPasswordPolicy(context.Background())
	require.Error(t, err)
	require.Nil(t, res)
}
