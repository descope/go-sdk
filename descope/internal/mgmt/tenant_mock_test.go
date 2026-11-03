package mgmt

import (
	"context"
	"os"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/auth"
	"github.com/stretchr/testify/require"
)

func newMockAPITenant(t *testing.T) *tenant {
	url := os.Getenv("DESCOPE_MOCK_URL")
	if url == "" {
		t.Skip("DESCOPE_MOCK_URL not set")
	}
	client := api.NewClient(api.ClientParams{ProjectID: "a", ManagementKey: "key", BaseURL: url})
	m := NewManagement(ManagementParams{ProjectID: "a"}, auth.NewProvider(client, &auth.AuthParams{ProjectID: "a", PublicKey: publicKey}), client)
	return m.Tenant().(*tenant)
}

func TestMockTenantCreateBatch(t *testing.T) {
	tn := newMockAPITenant(t)
	res, err := tn.CreateBatch(context.Background(), []*descope.CreateTenantBatchRequest{{
		ID:                             "t1",
		Name:                           "abc",
		SelfProvisioningDomains:        []string{"example.com"},
		CustomAttributes:               map[string]any{"k1": "v1"},
		AuthType:                       "saml",
		Disabled:                       true,
		EnforceSSO:                     true,
		EnforceSSOExclusions:           []string{"u1"},
		FederatedAppIDs:                []string{"app1"},
		ParentTenantID:                 "pid",
		RoleInheritance:                descope.RoleInheritanceUserOnly,
		ApprovedDomains:                []string{"a.example.com"},
		EnforceSSOExclusionPermissions: []string{"perm1"},
	}})
	require.NoError(t, err)
	require.NotNil(t, res.CreatedTenants)
	for _, c := range res.CreatedTenants {
		require.NotEmpty(t, c.ID)
		require.NotEmpty(t, c.Name)
	}
	require.NotNil(t, res.FailedTenants)
	for _, f := range res.FailedTenants {
		require.NotEmpty(t, f.Failure)
		require.NotNil(t, f.Tenant)
		require.NotEmpty(t, f.Tenant.ID)
		require.NotEmpty(t, f.Tenant.Name)
		require.NotNil(t, f.Tenant.SelfProvisioningDomains)
		require.NotNil(t, f.Tenant.CustomAttributes)
		require.NotEmpty(t, f.Tenant.AuthType)
		require.NotNil(t, f.Tenant.EnforceSSOExclusions)
		require.NotNil(t, f.Tenant.FederatedAppIDs)
		require.NotEmpty(t, f.Tenant.ParentTenantID)
		require.NotEmpty(t, f.Tenant.RoleInheritance)
		require.NotNil(t, f.Tenant.ApprovedDomains)
		require.NotNil(t, f.Tenant.EnforceSSOExclusionPermissions)
	}
	require.NotNil(t, res.AdditionalErrors)
}

func TestMockTenantUpdateBatch(t *testing.T) {
	tn := newMockAPITenant(t)
	res, err := tn.UpdateBatch(context.Background(), []*descope.UpdateTenantBatchRequest{{
		ID:                             "t1",
		Name:                           "abc",
		SelfProvisioningDomains:        []string{"example.com"},
		CustomAttributes:               map[string]any{"k1": "v1"},
		AuthType:                       "saml",
		Disabled:                       true,
		EnforceSSO:                     true,
		EnforceSSOExclusions:           []string{"u1"},
		FederatedAppIDs:                []string{"app1"},
		RoleInheritance:                descope.RoleInheritanceUserOnly,
		ApprovedDomains:                &[]string{"a.example.com"},
		EnforceSSOExclusionPermissions: []string{"perm1"},
	}})
	require.NoError(t, err)
	require.NotNil(t, res.UpdatedTenantIDs)
	require.NotNil(t, res.FailedTenants)
	for _, f := range res.FailedTenants {
		require.NotEmpty(t, f.Failure)
		require.NotNil(t, f.Tenant)
		require.NotEmpty(t, f.Tenant.ID)
		require.NotEmpty(t, f.Tenant.Name)
		require.NotNil(t, f.Tenant.SelfProvisioningDomains)
		require.NotNil(t, f.Tenant.CustomAttributes)
		require.NotEmpty(t, f.Tenant.AuthType)
		require.NotNil(t, f.Tenant.EnforceSSOExclusions)
		require.NotNil(t, f.Tenant.FederatedAppIDs)
		require.NotEmpty(t, f.Tenant.RoleInheritance)
		require.NotNil(t, f.Tenant.EnforceSSOExclusionPermissions)
		// approvedDomains is an untyped Value in the spec, kept only when a string list
	}
	require.NotNil(t, res.AdditionalErrors)
}

func TestMockTenantDeleteBatch(t *testing.T) {
	tn := newMockAPITenant(t)
	res, err := tn.DeleteBatch(context.Background(), []string{"t1", "t2"}, true)
	require.NoError(t, err)
	require.NotNil(t, res.DeletedTenantIDs)
	require.NotNil(t, res.FailedTenants)
	for _, f := range res.FailedTenants {
		require.NotEmpty(t, f.Failure)
		require.NotEmpty(t, f.ID)
	}
	require.NotNil(t, res.AdditionalErrors)
}
