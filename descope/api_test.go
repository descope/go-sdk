package descope

import (
	"net/http"
	"os"
	"testing"

	"github.com/descope/common/pkg/common/errors"
	"github.com/descope/go-sdk/descope/auth"
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
	a, err := NewDescopeClient(Config{})
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
	a, err := NewDescopeClient(Config{ProjectID: "a"})
	require.NoError(t, err)
	assert.EqualValues(t, expectedPublicKey, a.config.PublicKey)
}

func TestEmptyProjectID(t *testing.T) {
	_, err := NewDescopeClient(Config{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project id is missing")
}

func TestDescopeSDKMock(t *testing.T) {
	api := API{
		Auth: auth.MockDescopeAuth{
			ValidateSessionResponseNotOK:   true,
			ValidateSessionResponseCookies: []*http.Cookie{{}},
			ValidateSessionResponseError:   errors.BadRequest,
		},
	}
	ok, cookies, err := api.Auth.ValidateSession(nil, nil)
	assert.False(t, ok)
	assert.NotEmpty(t, cookies)
	assert.ErrorIs(t, err, errors.BadRequest)
}
