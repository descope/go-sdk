package mocksmgmt

import (
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMockManagement(t *testing.T) {
	called := false
	expectedLoginID := "mytestloginID"

	descopeClient := client.DescopeClient{
		Management: &MockManagement{
			MockUser: &MockUser{
				CreateAssert: func(loginID string, user *descope.UserRequest) {
					called = true
					assert.EqualValues(t, expectedLoginID, loginID)
				},
				CreateResponse: &descope.UserResponse{UserID: expectedLoginID},
				LoadResponse:   &descope.UserResponse{UserID: expectedLoginID},
			},
		},
	}
	assert.NotNil(t, descopeClient.Management)
	r, err := descopeClient.Management.User().Create(expectedLoginID, &descope.UserRequest{})
	require.NoError(t, err)
	assert.EqualValues(t, expectedLoginID, r.UserID)
	assert.True(t, called)

	u, err := descopeClient.Management.User().Load(expectedLoginID)
	require.NoError(t, err)
	assert.EqualValues(t, expectedLoginID, u.UserID)

	err = descopeClient.Management.Project().Delete()
	require.NoError(t, err)
}
