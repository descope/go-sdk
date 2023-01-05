package mocksmgmt

import (
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/auth"
	"github.com/descope/go-sdk/descope/mgmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMockManagement(t *testing.T) {
	called := false
	expectedLoginID := "mytestloginID"

	descopeClient := descope.DescopeClient{
		Management: &MockManagement{
			MockUser: &MockUser{
				CreateAssert: func(loginID, email, phone, displayName string, roles []string, tenants []*mgmt.AssociatedTenant) {
					called = true
					assert.EqualValues(t, expectedLoginID, loginID)
				},
				LoadResponse: &auth.UserResponse{UserID: expectedLoginID},
			},
		},
	}
	assert.NotNil(t, descopeClient.Management)
	require.NoError(t, descopeClient.Management.User().Create(expectedLoginID, "", "", "", nil, nil))
	assert.True(t, called)

	u, err := descopeClient.Management.User().Load(expectedLoginID)
	require.NoError(t, err)
	assert.EqualValues(t, expectedLoginID, u.UserID)
}
