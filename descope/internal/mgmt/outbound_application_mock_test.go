package mgmt

import (
	"context"
	"os"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newMockServerMgmt(t *testing.T) *managementService {
	url := os.Getenv("DESCOPE_MOCK_URL")
	if url == "" {
		t.Skip("DESCOPE_MOCK_URL is not set")
	}
	client := api.NewClient(api.ClientParams{ProjectID: "a", BaseURL: url, ManagementKey: "key"})
	return NewManagement(ManagementParams{ProjectID: "a"}, auth.NewProvider(client, &auth.AuthParams{ProjectID: "a"}), client)
}

func assertMockOutboundSCIMConfiguration(t *testing.T, cfg *descope.OutboundSCIMConfiguration) {
	require.NotNil(t, cfg)
	assert.NotEmpty(t, cfg.AppID)
	assert.NotNil(t, cfg.Configuration)
	assert.NotZero(t, cfg.LastExportTime)
	assert.NotZero(t, cfg.LastProcessingTime)
	assert.NotZero(t, cfg.Failures)
	assert.NotEmpty(t, cfg.Version)
}

func TestMockCreateSCIMConfiguration(t *testing.T) {
	mgmt := newMockServerMgmt(t)
	cfg, err := mgmt.OutboundApplication().CreateSCIMConfiguration(context.Background(), "app1", map[string]any{"baseUrl": "https://scim.example.com"})
	require.NoError(t, err)
	assertMockOutboundSCIMConfiguration(t, cfg)
}

func TestMockUpdateSCIMConfiguration(t *testing.T) {
	mgmt := newMockServerMgmt(t)
	cfg, err := mgmt.OutboundApplication().UpdateSCIMConfiguration(context.Background(), &descope.UpdateOutboundSCIMConfigurationRequest{
		AppID:         "app1",
		Configuration: map[string]any{"baseUrl": "https://scim.example.com"},
		Version:       "v1",
	})
	require.NoError(t, err)
	assertMockOutboundSCIMConfiguration(t, cfg)
}

func TestMockDeleteSCIMConfiguration(t *testing.T) {
	mgmt := newMockServerMgmt(t)
	err := mgmt.OutboundApplication().DeleteSCIMConfiguration(context.Background(), "app1")
	require.NoError(t, err)
}

func TestMockLoadSCIMConfiguration(t *testing.T) {
	mgmt := newMockServerMgmt(t)
	cfg, err := mgmt.OutboundApplication().LoadSCIMConfiguration(context.Background(), "app1")
	require.NoError(t, err)
	assertMockOutboundSCIMConfiguration(t, cfg)
}

func TestMockSetSCIMEnabled(t *testing.T) {
	mgmt := newMockServerMgmt(t)
	cfg, err := mgmt.OutboundApplication().SetSCIMEnabled(context.Background(), "app1", true)
	require.NoError(t, err)
	assertMockOutboundSCIMConfiguration(t, cfg)
}
