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
	client := api.NewClient(api.ClientParams{BaseURL: url, ProjectID: "project-ID", ManagementKey: "management-key"})
	return NewManagement(ManagementParams{ProjectID: "project-ID"}, auth.NewProvider(client, &auth.AuthParams{ProjectID: "project-ID"}), client)
}

func assertMockAccessKey(t *testing.T, key *descope.AccessKeyResponse) {
	require.NotNil(t, key)
	assert.NotEmpty(t, key.ID)
	assert.NotEmpty(t, key.Name)
	assert.NotNil(t, key.RoleNames)
	require.NotNil(t, key.KeyTenants)
	for _, tenant := range key.KeyTenants {
		assert.NotEmpty(t, tenant.TenantID)
		assert.NotEmpty(t, tenant.TenantName)
		assert.NotNil(t, tenant.Roles)
	}
	assert.NotEmpty(t, key.Status)
	assert.NotZero(t, key.CreatedTime)
	assert.NotZero(t, key.ExpireTime)
	assert.NotEmpty(t, key.CreatedBy)
	assert.NotEmpty(t, key.ClientID)
	assert.NotEmpty(t, key.UserID)
	assert.NotNil(t, key.CustomClaims)
	assert.NotEmpty(t, key.Description)
	assert.NotNil(t, key.PermittedIPs)
	assert.NotNil(t, key.CustomAttributes)
}

func assertMockSCIMAccessKeyResponse(t *testing.T, res *descope.SCIMAccessKeyResponse) {
	require.NotNil(t, res)
	assert.NotEmpty(t, res.Cleartext)
	assert.NotEmpty(t, res.SCIMURL)
	assert.NotNil(t, res.RevokedKeyIDs)
	assertMockAccessKey(t, res.Key)
}

func TestMockSCIMCreateAccessKey(t *testing.T) {
	mgmt := newMockServerMgmt(t)
	res, err := mgmt.SCIM().CreateAccessKey(context.Background(), &descope.SCIMAccessKeyCreateRequest{
		TenantID:    "tenant-ID",
		SSOID:       "sso-ID",
		Name:        "scim-key",
		Description: "SCIM key",
		ExpireTime:  1700000000,
	})
	require.NoError(t, err)
	assertMockSCIMAccessKeyResponse(t, res)
}

func TestMockSCIMRotateAccessKey(t *testing.T) {
	mgmt := newMockServerMgmt(t)
	res, err := mgmt.SCIM().RotateAccessKey(context.Background(), &descope.SCIMAccessKeyRotateRequest{
		TenantID:    "tenant-ID",
		SSOID:       "sso-ID",
		Name:        "scim-key",
		Description: "SCIM key",
		ExpireTime:  1700000000,
		RevokeMode:  descope.SCIMKeyRevokeModeDeactivate,
	})
	require.NoError(t, err)
	assertMockSCIMAccessKeyResponse(t, res)
}

func TestMockSCIMRevokeAccessKeys(t *testing.T) {
	mgmt := newMockServerMgmt(t)
	ids, err := mgmt.SCIM().RevokeAccessKeys(context.Background(), "tenant-ID", "sso-ID", descope.SCIMKeyRevokeModeDeactivate)
	require.NoError(t, err)
	assert.NotNil(t, ids)
}

func TestMockSCIMActivateAccessKeys(t *testing.T) {
	mgmt := newMockServerMgmt(t)
	ids, err := mgmt.SCIM().ActivateAccessKeys(context.Background(), "tenant-ID", "sso-ID", []string{"key-ID"})
	require.NoError(t, err)
	assert.NotNil(t, ids)
}

func TestMockSCIMLoadAccessKeys(t *testing.T) {
	mgmt := newMockServerMgmt(t)
	keys, err := mgmt.SCIM().LoadAccessKeys(context.Background(), "tenant-ID", "sso-ID")
	require.NoError(t, err)
	require.NotNil(t, keys)
	for _, key := range keys {
		require.NotNil(t, key)
		assert.NotEmpty(t, key.SSOID)
		assertMockAccessKey(t, key.Key)
	}
}
