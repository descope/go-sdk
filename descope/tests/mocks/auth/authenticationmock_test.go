package mocksauth

import (
	"context"
	"net/http"
	"testing"

	"github.com/descope/go-sdk/v2/descope"
	"github.com/descope/go-sdk/v2/descope/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMockAuthentication(t *testing.T) {
	called := false
	expectedStartResponse := "some response"

	descopeClient := client.DescopeClient{
		Auth: &MockAuthentication{
			MockOAuth: &MockOAuth{
				StartAssert: func(provider descope.OAuthProvider, _ string, _ *http.Request, _ *descope.LoginOptions, _ http.ResponseWriter) {
					called = true
					assert.EqualValues(t, descope.OAuthApple, provider)
				},
				StartResponse: expectedStartResponse,
			},
		},
	}
	assert.NotNil(t, descopeClient.Auth)
	startResponse, err := descopeClient.Auth.OAuth().Start(context.Background(), descope.OAuthApple, "", nil, nil, nil)
	require.NoError(t, err)
	assert.True(t, called)
	assert.EqualValues(t, startResponse, expectedStartResponse)
}
