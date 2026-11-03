package mgmt_test

import (
	"context"
	"os"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newAgenticMockClient(t *testing.T) *client.DescopeClient {
	url := os.Getenv("DESCOPE_MOCK_URL")
	if url == "" {
		t.Skip("DESCOPE_MOCK_URL is not set")
	}
	descopeClient, err := client.NewWithConfig(&client.Config{
		ProjectID:      "test",
		ManagementKey:  "mgmt-key",
		DescopeBaseURL: url,
	})
	require.NoError(t, err)
	return descopeClient
}

func TestMockAgenticSearchIdentities(t *testing.T) {
	descopeClient := newAgenticMockClient(t)
	var identities []*descope.AgenticIdentity
	var total int
	// Mock may randomly return an empty list
	for i := 0; i < 20 && len(identities) == 0; i++ {
		var err error
		identities, total, err = descopeClient.Management.Agentic().SearchIdentities(context.Background(), &descope.AgenticIdentitySearchOptions{
			UserID:     "user1",
			ClientID:   "client1",
			ResourceID: "resource1",
			ConsentID:  "consent1",
			Page:       1,
			Limit:      10,
		})
		require.NoError(t, err)
	}
	assert.NotZero(t, total)
	require.NotEmpty(t, identities)
	for _, identity := range identities {
		require.NotNil(t, identity)
		assert.NotEmpty(t, identity.AgentName)
		assert.NotEmpty(t, identity.ResourceID)
		assert.NotEmpty(t, identity.ClientID)
		assert.NotEmpty(t, identity.CreatedBy)
		consent := identity.Consent
		require.NotNil(t, consent)
		assert.NotEmpty(t, consent.ID)
		assert.NotEmpty(t, consent.AppID)
		assert.NotEmpty(t, consent.UserID)
		assert.NotNil(t, consent.Scopes)
		assert.NotEmpty(t, consent.GrantedBy)
		assert.NotZero(t, consent.CreatedTime)
		assert.NotEmpty(t, consent.TenantID)
		assert.NotZero(t, consent.ExpireTime)
		assert.NotZero(t, consent.ModifiedTime)
		assert.NotEmpty(t, consent.AuthMethod)
	}
}

func TestMockAgenticRevokeIdentities(t *testing.T) {
	descopeClient := newAgenticMockClient(t)
	revoked, err := descopeClient.Management.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{
		UserID:     "user1",
		ClientID:   "client1",
		ResourceID: "resource1",
		ConsentID:  "consent1",
	})
	require.NoError(t, err)
	assert.NotZero(t, revoked)
}
