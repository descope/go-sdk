package mgmt_test

import (
	"context"
	"os"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/client"
	"github.com/stretchr/testify/require"
)

func newMockFlowClient(t *testing.T) *client.DescopeClient {
	url := os.Getenv("DESCOPE_MOCK_URL")
	if url == "" {
		t.Skip("DESCOPE_MOCK_URL is not set")
	}
	c, err := client.NewWithConfig(&client.Config{ProjectID: "a", ManagementKey: "key", DescopeBaseURL: url})
	require.NoError(t, err)
	return c
}

func TestMockGetTenantTheme(t *testing.T) {
	c := newMockFlowClient(t)
	res, err := c.Management.Flow().GetTenantTheme(context.Background(), "t1")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NotNil(t, res.Styles)
	require.NotEmpty(t, res.ComponentsVersion)
}

func TestMockSetTenantTheme(t *testing.T) {
	c := newMockFlowClient(t)
	theme := &descope.TenantTheme{
		Styles:            map[string]any{"light": map[string]any{"foo": "bar"}},
		ComponentsVersion: "1.0.0",
	}
	res, err := c.Management.Flow().SetTenantTheme(context.Background(), "t1", theme)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NotNil(t, res.Styles)
	require.NotEmpty(t, res.ComponentsVersion)
}

func TestMockDeleteTenantTheme(t *testing.T) {
	c := newMockFlowClient(t)
	err := c.Management.Flow().DeleteTenantTheme(context.Background(), "t1")
	require.NoError(t, err)
}
