package client

import (
	"os"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/errors"
	mocksauth "github.com/descope/go-sdk/descope/tests/mocks/auth"
	mocksmgmt "github.com/descope/go-sdk/descope/tests/mocks/mgmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnvVariableProjectID(t *testing.T) {
	expectedProjectID := "test"
	err := os.Setenv(descope.EnvironmentVariableProjectID, expectedProjectID)
	defer func() {
		err = os.Setenv(descope.EnvironmentVariableProjectID, "")
		require.NoError(t, err)
	}()
	require.NoError(t, err)
	a, err := NewDescopeClient()
	require.NoError(t, err)
	assert.EqualValues(t, expectedProjectID, a.config.ProjectID)
	assert.NotNil(t, a.Auth)
	assert.NotNil(t, a.Management)
}

func TestEnvVariablePublicKey(t *testing.T) {
	expectedPublicKey := "test"
	err := os.Setenv(descope.EnvironmentVariablePublicKey, expectedPublicKey)
	defer func() {
		err = os.Setenv(descope.EnvironmentVariablePublicKey, "")
		require.NoError(t, err)
	}()
	require.NoError(t, err)
	a, err := NewDescopeClientWithConfig(&Config{ProjectID: "a"})
	require.NoError(t, err)
	assert.EqualValues(t, expectedPublicKey, a.config.PublicKey)
	assert.NotNil(t, a.Auth)
	assert.NotNil(t, a.Management)
}

func TestEmptyProjectID(t *testing.T) {
	_, err := NewDescopeClient()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project id is missing")
}

func TestEmptyConfig(t *testing.T) {
	_, err := NewDescopeClientWithConfig(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "config")
}

func TestDescopeSDKMock(t *testing.T) {
	updateJWTWithCustomClaimsCalled := false
	validateSessionResponse := "test1"
	updateJWTWithCustomClaimsResponse := "test2"
	api := DescopeClient{
		Auth: &mocksauth.MockAuthentication{
			MockSession: mocksauth.MockSession{
				ValidateSessionResponseFailure: true,
				ValidateSessionResponse:        &descope.Token{JWT: validateSessionResponse},
				ValidateSessionError:           errors.NoPublicKeyError,
			},
		},
		Management: &mocksmgmt.MockManagement{
			MockJWT: &mocksmgmt.MockJWT{
				UpdateJWTWithCustomClaimsResponse: updateJWTWithCustomClaimsResponse,
				UpdateJWTWithCustomClaimsAssert: func(jwt string, customClaims map[string]any) {
					updateJWTWithCustomClaimsCalled = true
					assert.EqualValues(t, "some jwt", jwt)
				},
			},
		},
	}
	ok, info, err := api.Auth.ValidateSession(nil, nil)
	assert.False(t, ok)
	assert.NotEmpty(t, info)
	assert.EqualValues(t, validateSessionResponse, info.JWT)
	assert.ErrorIs(t, err, errors.NoPublicKeyError)

	res, err := api.Management.JWT().UpdateJWTWithCustomClaims("some jwt", nil)
	require.NoError(t, err)
	assert.True(t, updateJWTWithCustomClaimsCalled)
	assert.EqualValues(t, updateJWTWithCustomClaimsResponse, res)
}
