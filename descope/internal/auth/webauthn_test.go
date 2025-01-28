package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/descope/go-sdk/v2/descope"
	"github.com/descope/go-sdk/v2/descope/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignUpStart(t *testing.T) {
	expectedResponse := descope.WebAuthnTransactionResponse{TransactionID: "a"}
	a, err := newTestAuth(nil, DoOkWithBody(func(r *http.Request) {
		req := authenticationWebAuthnSignUpRequestBody{}
		err := readBody(r, &req)
		require.NoError(t, err)
		assert.EqualValues(t, "test@test.com", req.LoginID)
		assert.EqualValues(t, "test2@test.com", req.User.Name)
	}, expectedResponse))
	require.NoError(t, err)
	res, err := a.WebAuthn().SignUpStart(context.Background(), "test@test.com", &descope.User{Name: "test2@test.com"}, "https://example.com")
	require.NoError(t, err)
	assert.EqualValues(t, expectedResponse.TransactionID, res.TransactionID)
}

func TestSignUpStartNilUser(t *testing.T) {
	expectedResponse := descope.WebAuthnTransactionResponse{TransactionID: "a"}
	a, err := newTestAuth(nil, DoOkWithBody(func(r *http.Request) {
		req := authenticationWebAuthnSignUpRequestBody{}
		err := readBody(r, &req)
		require.NoError(t, err)
		assert.EqualValues(t, "test@test.com", req.LoginID)
	}, expectedResponse))
	require.NoError(t, err)
	res, err := a.WebAuthn().SignUpStart(context.Background(), "test@test.com", nil, "https://example.com")
	require.NoError(t, err)
	assert.EqualValues(t, expectedResponse.TransactionID, res.TransactionID)
}

func TestSignInFinish(t *testing.T) {
	expectedResponse := &descope.WebAuthnFinishRequest{TransactionID: "a"}
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	w := httptest.NewRecorder()
	res, err := a.WebAuthn().SignInFinish(context.Background(), expectedResponse, w)
	require.NoError(t, err)
	assert.EqualValues(t, jwtTokenValid, res.SessionToken.JWT)
	require.Len(t, w.Result().Cookies(), 1) // Just the refresh token
}

func TestSignInStart(t *testing.T) {
	expectedResponse := descope.WebAuthnTransactionResponse{TransactionID: "a"}
	a, err := newTestAuth(nil, DoOkWithBody(func(r *http.Request) {
		req := authenticationRequestBody{}
		err := readBody(r, &req)
		require.NoError(t, err)
		assert.EqualValues(t, "a", req.LoginID)
	}, expectedResponse))
	require.NoError(t, err)
	res, err := a.WebAuthn().SignInStart(context.Background(), "a", "https://example.com", nil, nil)
	require.NoError(t, err)
	assert.EqualValues(t, expectedResponse.TransactionID, res.TransactionID)
}

func TestSignInStartStepup(t *testing.T) {
	expectedResponse := descope.WebAuthnTransactionResponse{TransactionID: "a"}
	a, err := newTestAuth(nil, DoOkWithBody(func(r *http.Request) {
		req := authenticationRequestBody{}
		err := readBody(r, &req)
		require.NoError(t, err)
		assert.EqualValues(t, "a", req.LoginID)
		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, map[string]interface{}{"stepup": true, "customClaims": map[string]interface{}{"k1": "v1"}}, body["loginOptions"])
		reqToken := r.Header.Get(api.AuthorizationHeaderName)
		splitToken := strings.Split(reqToken, api.BearerAuthorizationPrefix)
		require.Len(t, splitToken, 2)
		bearer := splitToken[1]
		bearers := strings.Split(bearer, ":")
		require.Len(t, bearers, 2)
		assert.EqualValues(t, "test", bearers[1])

	}, expectedResponse))
	require.NoError(t, err)
	res, err := a.WebAuthn().SignInStart(context.Background(), "a", "https://example.com", &http.Request{Header: http.Header{"Cookie": []string{"DSR=test"}}}, &descope.LoginOptions{Stepup: true, CustomClaims: map[string]interface{}{"k1": "v1"}})
	require.NoError(t, err)
	assert.EqualValues(t, expectedResponse.TransactionID, res.TransactionID)
}

func TestSignInWebAuthnStartEmpty(t *testing.T) {
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	res, err := a.WebAuthn().SignInStart(context.Background(), "", "https://example.com", nil, nil)
	require.Error(t, err)
	assert.Empty(t, res)
	assert.ErrorIs(t, err, descope.ErrInvalidArguments)
}

func TestSignInWebAuthnStepupNoJWT(t *testing.T) {
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	res, err := a.WebAuthn().SignInStart(context.Background(), "a", "https://example.com", nil, &descope.LoginOptions{Stepup: true})
	require.Error(t, err)
	assert.Empty(t, res)
	assert.ErrorIs(t, err, descope.ErrInvalidStepUpJWT)
}

func TestSignUpFinish(t *testing.T) {
	expectedResponse := &descope.WebAuthnFinishRequest{TransactionID: "a"}
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	w := httptest.NewRecorder()
	res, err := a.WebAuthn().SignUpFinish(context.Background(), expectedResponse, w)
	require.NoError(t, err)
	assert.EqualValues(t, jwtTokenValid, res.SessionToken.JWT)
	require.Len(t, w.Result().Cookies(), 1) // Just the refresh token
}

func TestSignUpOrInStart(t *testing.T) {
	expectedResponse := descope.WebAuthnTransactionResponse{TransactionID: "a", Create: true}
	a, err := newTestAuth(nil, DoOkWithBody(func(r *http.Request) {
		req := authenticationWebAuthnSignInRequestBody{}
		err := readBody(r, &req)
		require.NoError(t, err)
		assert.EqualValues(t, "test@test.com", req.LoginID)
		assert.EqualValues(t, "https://example.com", req.Origin)
	}, expectedResponse))
	require.NoError(t, err)
	res, err := a.WebAuthn().SignUpOrInStart(context.Background(), "test@test.com", "https://example.com")
	require.NoError(t, err)
	assert.EqualValues(t, expectedResponse.TransactionID, res.TransactionID)
	assert.EqualValues(t, expectedResponse.Create, res.Create)
}

func TestSignUpOrInStartEmpty(t *testing.T) {
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	res, err := a.WebAuthn().SignUpOrInStart(context.Background(), "", "https://example.com")
	require.Error(t, err)
	assert.Nil(t, res)
	assert.ErrorIs(t, err, descope.ErrInvalidArguments)
}

func TestWebAuthnUpdateUserDeviceStart(t *testing.T) {
	expectedResponse := descope.WebAuthnTransactionResponse{TransactionID: "a"}
	a, err := newTestAuth(nil, DoOkWithBody(func(r *http.Request) {
		req := authenticationRequestBody{}
		err := readBody(r, &req)
		require.NoError(t, err)
		assert.EqualValues(t, "test@test.com", req.LoginID)
	}, expectedResponse))
	require.NoError(t, err)
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtTokenValid})
	res, err := a.WebAuthn().UpdateUserDeviceStart(context.Background(), "test@test.com", "https://example.com", r)
	require.NoError(t, err)
	assert.EqualValues(t, expectedResponse.TransactionID, res.TransactionID)
}

func TestWebAuthnUpdateUserDeviceStartEmpty(t *testing.T) {
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtTokenValid})
	res, err := a.WebAuthn().UpdateUserDeviceStart(context.Background(), "", "https://example.com", r)
	require.Error(t, err)
	assert.Empty(t, res)
	assert.ErrorIs(t, err, descope.ErrInvalidArguments)
}

func TestWebAuthnUpdateUserDeviceFinish(t *testing.T) {
	expectedResponse := &descope.WebAuthnFinishRequest{TransactionID: "a"}
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	err = a.WebAuthn().UpdateUserDeviceFinish(context.Background(), expectedResponse)
	require.NoError(t, err)
}
