package mocksauth

import (
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMockAuthentication(t *testing.T) {
	called := false
	expectedStartResponse := "some response"

	descopeClient := client.DescopeClient{
		Auth: &MockAuthentication{
			MockOAuth: &MockOAuth{
				StartAssert: func(provider descope.OAuthProvider, returnURL string, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter) {
					called = true
					assert.EqualValues(t, descope.OAuthApple, provider)
				},
				StartResponse: expectedStartResponse,
			},
		},
	}
	assert.NotNil(t, descopeClient.Auth)
	startResponse, err := descopeClient.Auth.OAuth().Start(descope.OAuthApple, "", nil, nil, nil)
	require.NoError(t, err)
	assert.True(t, called)
	assert.EqualValues(t, startResponse, expectedStartResponse)
}
