package descope

import (
	"os"
	"testing"

	"github.com/descope/go-sdk/descope/auth"
	"github.com/descope/go-sdk/descope/errors"
	"github.com/descope/go-sdk/descope/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnvVariableProjectID(t *testing.T) {
	expectedProjectID := "test"
	err := os.Setenv(utils.EnvironmentVariableProjectID, expectedProjectID)
	defer func() {
		err = os.Setenv(utils.EnvironmentVariableProjectID, "")
		require.NoError(t, err)
	}()
	require.NoError(t, err)
	a, err := NewDescopeClient()
	require.NoError(t, err)
	assert.EqualValues(t, expectedProjectID, a.config.ProjectID)
}

func TestEnvVariablePublicKey(t *testing.T) {
	expectedPublicKey := "test"
	err := os.Setenv(utils.EnvironmentVariablePublicKey, expectedPublicKey)
	defer func() {
		err = os.Setenv(utils.EnvironmentVariablePublicKey, "")
		require.NoError(t, err)
	}()
	require.NoError(t, err)
	a, err := NewDescopeClientWithConfig(Config{ProjectID: "a"})
	require.NoError(t, err)
	assert.EqualValues(t, expectedPublicKey, a.config.PublicKey)
}

func TestEmptyProjectID(t *testing.T) {
	_, err := NewDescopeClient()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project id is missing")
}

func TestDescopeSDKMock(t *testing.T) {
	api := DescopeClient{
		Auth: auth.MockDescopeAuthentication{
			ValidateSessionResponseNotOK: true,
			ValidateSessionResponseInfo:  &auth.AuthenticationInfo{SessionToken: &auth.Token{JWT: "test"}},
			ValidateSessionResponseError: errors.NoPublicKeyError,
		},
	}
	ok, info, err := api.Auth.ValidateSession(nil, nil)
	assert.False(t, ok)
	assert.NotEmpty(t, info)
	assert.ErrorIs(t, err, errors.NoPublicKeyError)
}
