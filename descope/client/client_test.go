package client

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/logger"
	"github.com/descope/go-sdk/descope/tests/mocks"
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
	a, err := New()
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
	a, err := NewWithConfig(&Config{ProjectID: "a"})
	require.NoError(t, err)
	assert.EqualValues(t, expectedPublicKey, a.config.PublicKey)
	assert.NotNil(t, a.Auth)
	assert.NotNil(t, a.Management)
}

func TestEnvVariableManagementKey(t *testing.T) {
	expectedManagementKey := "test"
	err := os.Setenv(descope.EnvironmentVariableManagementKey, expectedManagementKey)
	defer func() {
		err = os.Setenv(descope.EnvironmentVariableManagementKey, "")
		require.NoError(t, err)
	}()
	require.NoError(t, err)
	a, err := NewWithConfig(&Config{ProjectID: "a"})
	require.NoError(t, err)
	assert.EqualValues(t, expectedManagementKey, a.config.ManagementKey)
	assert.NotNil(t, a.Auth)
	assert.NotNil(t, a.Management)
}

func TestEnvVariableAuthManagementKey(t *testing.T) {
	expectedManagementKey := "test"
	err := os.Setenv(descope.EnvironmentVariableAuthManagementKey, expectedManagementKey)
	defer func() {
		err = os.Setenv(descope.EnvironmentVariableAuthManagementKey, "")
		require.NoError(t, err)
	}()
	require.NoError(t, err)
	a, err := NewWithConfig(&Config{ProjectID: "a"})
	require.NoError(t, err)
	assert.EqualValues(t, expectedManagementKey, a.config.AuthManagementKey)
	assert.NotNil(t, a.Auth)
	assert.NotNil(t, a.Management)
}

func TestManagementKeys(t *testing.T) {
	expectedManagementKey := "management-key"
	expectedAuthManagementKey := "auth-management-key"
	projectID := "test-project"

	// Capture the last request
	var lastRequest *http.Request
	mockClient := mocks.NewTestClient(func(r *http.Request) (*http.Response, error) {
		lastRequest = r
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(`{}`)),
			Header:     make(http.Header),
		}, nil
	})

	// Create client with both management keys
	client, err := NewWithConfig(&Config{
		ProjectID:         projectID,
		ManagementKey:     expectedManagementKey,
		AuthManagementKey: expectedAuthManagementKey,
		DefaultClient:     mockClient,
	})
	require.NoError(t, err)
	assert.EqualValues(t, expectedManagementKey, client.config.ManagementKey)
	assert.EqualValues(t, expectedAuthManagementKey, client.config.AuthManagementKey)

	ctx := context.Background()

	// Test 1: Management API should use ManagementKey
	_, _ = client.Management.User().Load(ctx, "test-user")
	require.NotNil(t, lastRequest)
	authHeader := lastRequest.Header.Get("Authorization")
	expectedMgmtBearer := fmt.Sprintf("Bearer %s:%s", projectID, expectedManagementKey)
	assert.Equal(t, expectedMgmtBearer, authHeader)

	// Test 2: Auth API should use AuthManagementKey
	_, _ = client.Auth.OTP().SignIn(ctx, descope.MethodEmail, "test@example.com", nil, nil)
	require.NotNil(t, lastRequest)
	authHeader = lastRequest.Header.Get("Authorization")
	expectedAuthBearer := fmt.Sprintf("Bearer %s:%s", projectID, expectedAuthManagementKey)
	assert.Equal(t, expectedAuthBearer, authHeader)

	// Test 3: Auth API with a refresh JWT and a management key
	refreshJWT := "test-refresh-jwt"
	cookie := &http.Cookie{Name: descope.RefreshCookieName, Value: refreshJWT}
	_, _ = client.Auth.OTP().UpdateUserEmail(ctx, "test@example.com", "test@example.com", nil, &http.Request{
		Header: http.Header{"Cookie": []string{cookie.String()}},
	})
	require.NotNil(t, lastRequest)
	authHeader = lastRequest.Header.Get("Authorization")
	expectedAuthBearer = fmt.Sprintf("Bearer %s:%s:%s", projectID, refreshJWT, expectedAuthManagementKey)
	assert.Equal(t, expectedAuthBearer, authHeader)
}

func TestFetchLicenseSuccess(t *testing.T) {
	mockClient := mocks.NewTestClient(func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(`{"licenseType":"enterprise"}`)),
			Header:     make(http.Header),
		}, nil
	})
	client, err := NewWithConfig(&Config{
		ProjectID:     "test",
		ManagementKey: "mgmt-key",
		DefaultClient: mockClient,
	})
	require.NoError(t, err)
	assert.NotNil(t, client)
}

func TestConcurrentClients(t *testing.T) {
	// This test should be run with the 'race' flag, to ensure that
	// creating two client in a concurrent manner is safe

	c, err := NewWithConfig(&Config{ProjectID: "a", PublicKey: "test", LogLevel: logger.LogDebugLevel})
	assert.NoError(t, err)
	go func() {
		_, err2 := NewWithConfig(&Config{ProjectID: "a", PublicKey: "test", LogLevel: logger.LogDebugLevel})
		assert.NoError(t, err2)
	}()

	// SignUpOrIn is called to trigger logging, to ensure it is safe
	// during a concurrent creation of another client
	_, _ = c.Auth.OTP().SignUpOrIn(context.Background(), descope.MethodEmail, "test@test.com", nil)
}

func TestEmptyProjectID(t *testing.T) {
	_, err := New()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Project ID is missing")
}

func TestAllowEmptyProjectID(t *testing.T) {
	a, err := NewWithConfig(&Config{AllowEmptyProjectID: true})
	require.NoError(t, err)
	assert.Empty(t, a.config.ProjectID)
	assert.NotNil(t, a.Auth)
	assert.NotNil(t, a.Management)
}

func TestEmptyConfig(t *testing.T) {
	_, err := NewWithConfig(nil)
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
				ValidateAndRefreshSessionResponseFailure: true,
				ValidateAndRefreshSessionResponse:        &descope.Token{JWT: validateSessionResponse},
				ValidateAndRefreshSessionError:           descope.ErrPublicKey,
			},
		},
		Management: &mocksmgmt.MockManagement{
			MockJWT: &mocksmgmt.MockJWT{
				UpdateJWTWithCustomClaimsResponse: updateJWTWithCustomClaimsResponse,
				UpdateJWTWithCustomClaimsAssert: func(jwt string, _ map[string]any, _ int32) {
					updateJWTWithCustomClaimsCalled = true
					assert.EqualValues(t, "some jwt", jwt)
				},
			},
		},
	}
	ctx := context.Background()
	ok, info, err := api.Auth.ValidateAndRefreshSessionWithRequest(nil, nil)
	assert.False(t, ok)
	assert.NotEmpty(t, info)
	assert.EqualValues(t, validateSessionResponse, info.JWT)
	assert.ErrorIs(t, err, descope.ErrPublicKey)

	res, err := api.Management.JWT().UpdateJWTWithCustomClaims(ctx, "some jwt", nil, 0)
	require.NoError(t, err)
	assert.True(t, updateJWTWithCustomClaimsCalled)
	assert.EqualValues(t, updateJWTWithCustomClaimsResponse, res)
}
