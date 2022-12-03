package mocksauth

import (
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMockAuthentication(t *testing.T) {
	called := false
	expectedStartResponse := "some response"
	descopeClient := descope.DescopeClient{
		Auth: &MockAuthentication{
			MockOAuth: &MockOAuth{
				StartAssert: func(provider auth.OAuthProvider, returnURL string, r *http.Request, loginOptions *auth.LoginOptions, w http.ResponseWriter) {
					called = true
					assert.EqualValues(t, auth.OAuthApple, provider)
				},
				StartResponse: expectedStartResponse,
			},
		},
	}
	assert.NotNil(t, descopeClient.Auth)
	startResponse, err := descopeClient.Auth.OAuth().Start(auth.OAuthApple, "", nil, nil, nil)
	require.NoError(t, err)
	assert.True(t, called)
	assert.EqualValues(t, startResponse, expectedStartResponse)
}
