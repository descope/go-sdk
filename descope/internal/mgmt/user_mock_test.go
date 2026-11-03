package mgmt

import (
	"context"
	"os"
	"testing"

	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/auth"
	"github.com/stretchr/testify/require"
)

func newMockServerMgmt(t *testing.T) *managementService {
	url := os.Getenv("DESCOPE_MOCK_URL")
	if url == "" {
		t.Skip("DESCOPE_MOCK_URL is not set")
	}
	params := api.ClientParams{BaseURL: url, ProjectID: "P2111111111111111111111111", ManagementKey: "key"}
	client := api.NewClient(params)
	return NewManagement(ManagementParams{ProjectID: params.ProjectID}, auth.NewProvider(client, &auth.AuthParams{ProjectID: params.ProjectID, PublicKey: publicKey}), client)
}

func TestMockLogoutUsers(t *testing.T) {
	m := newMockServerMgmt(t)
	res, err := m.User().LogoutUsers(context.Background(), []string{"abc", "def"}, "web")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NotNil(t, res.NotFoundIdentifiers)
}
