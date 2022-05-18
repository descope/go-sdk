package descope

import (
	"os"
	"testing"

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
	a, err := NewDescopeAPI(Config{})
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
	a, err := NewDescopeAPI(Config{ProjectID: "a"})
	require.NoError(t, err)
	assert.EqualValues(t, expectedPublicKey, a.config.PublicKey)
}

func TestEmptyProjectID(t *testing.T) {
	_, err := NewDescopeAPI(Config{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "project id is missing")
}
