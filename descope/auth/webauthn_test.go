package auth

import (
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignUpWebAuthnStart(t *testing.T) {
	expectedResponse := WebAuthnTransactionResponse{TransactionID: "a"}
	a, err := newTestAuth(nil, DoOkWithBody(func(r *http.Request) {
		req := authenticationWebAuthnSignUpRequestBody{}
		err := readBody(r, &req)
		require.NoError(t, err)
		assert.EqualValues(t, "test@test.com", req.User.Email)
	}, expectedResponse))
	require.NoError(t, err)
	res, err := a.SignUpWebAuthnStart(&User{Email: "test@test.com"})
	require.NoError(t, err)
	assert.EqualValues(t, expectedResponse.TransactionID, res.TransactionID)
}

func TestSignInWebAuthnFinish(t *testing.T) {
	expectedResponse := &WebAuthnFinishRequest{TransactionID: "a"}
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	res, err := a.SignInWebAuthnFinish(expectedResponse)
	require.NoError(t, err)
	assert.EqualValues(t, jwtTokenValid, res.SessionToken.JWT)
}

func TestSignInWebAuthnStart(t *testing.T) {
	expectedResponse := WebAuthnTransactionResponse{TransactionID: "a"}
	a, err := newTestAuth(nil, DoOkWithBody(func(r *http.Request) {
		req := authenticationRequestBody{}
		err := readBody(r, &req)
		require.NoError(t, err)
		assert.EqualValues(t, "a", req.ExternalID)
	}, expectedResponse))
	require.NoError(t, err)
	res, err := a.SignInWebAuthnStart("a")
	require.NoError(t, err)
	assert.EqualValues(t, expectedResponse.TransactionID, res.TransactionID)
}

func TestSignInWebAuthnStartEmpty(t *testing.T) {
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	res, err := a.SignInWebAuthnStart("")
	require.Error(t, err)
	assert.Empty(t, res)
	assert.EqualValues(t, errors.BadRequestErrorCode, err.(*errors.WebError).Code)
}
