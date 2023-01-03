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
	expectedIdentifier := "mytestidentifier"

	descopeClient := descope.DescopeClient{
		Management: &MockManagement{
			MockUser: &MockUser{
				CreateAssert: func(identifier, email, phone, displayName string, roles []string, tenants []*mgmt.AssociatedTenant) {
					called = true
					assert.EqualValues(t, expectedIdentifier, identifier)
				},
				LoadResponse: &auth.UserResponse{UserID: expectedIdentifier},
			},
		},
	}
	assert.NotNil(t, descopeClient.Management)
	require.NoError(t, descopeClient.Management.User().Create(expectedIdentifier, "", "", "", nil, nil))
	assert.True(t, called)

	u, err := descopeClient.Management.User().Load(expectedIdentifier)
	require.NoError(t, err)
	assert.EqualValues(t, expectedIdentifier, u.UserID)
}
