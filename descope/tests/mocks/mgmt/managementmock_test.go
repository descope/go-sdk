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
				CreateAssert: func(loginID, email, phone, displayName string, roles []string, tenants []*descope.AssociatedTenant) {
					called = true
					assert.EqualValues(t, expectedLoginID, loginID)
				},
				CreateResponse: &descope.UserResponse{UserID: expectedLoginID},
				LoadResponse:   &descope.UserResponse{UserID: expectedLoginID},
			},
		},
	}
	assert.NotNil(t, descopeClient.Management)
	r, err := descopeClient.Management.User().Create(expectedLoginID, "", "", "", nil, nil)
	require.NoError(t, err)
	assert.EqualValues(t, expectedLoginID, r.UserID)
	assert.True(t, called)

	u, err := descopeClient.Management.User().Load(expectedLoginID)
	require.NoError(t, err)
	assert.EqualValues(t, expectedLoginID, u.UserID)
}
