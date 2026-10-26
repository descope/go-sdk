package mgmt

import (
	"context"
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/tests/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTenantCreateSuccess(t *testing.T) {
	response := map[string]any{"id": "qux"}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "", req["id"])
		require.Equal(t, "abc", req["name"])
		selfProvisioningDomains := req["selfProvisioningDomains"].([]any)
		require.Len(t, selfProvisioningDomains, 2)
		require.Equal(t, "foo", selfProvisioningDomains[0])
		require.Equal(t, "bar", selfProvisioningDomains[1])
		require.Equal(t, "pid", req["parent"])
		require.Equal(t, string(descope.RoleInheritanceNone), req["roleInheritance"])
		customAttributes := req["customAttributes"].(map[string]any)
		assert.EqualValues(t, map[string]any{"k1": "v1"}, customAttributes)
		require.True(t, req["enforceSSO"].(bool))
		require.EqualValues(t, []any{"aaaa"}, req["enforceSSOExclusions"].([]any))
		require.True(t, req["disabled"].(bool))
		require.EqualValues(t, []any{"app1"}, req["federatedAppIds"].([]any))
	}, response))

	id, err := mgmt.Tenant().Create(context.Background(), &descope.TenantRequest{Name: "abc", SelfProvisioningDomains: []string{"foo", "bar"}, CustomAttributes: map[string]any{"k1": "v1"}, Disabled: true, EnforceSSO: true, ParentTenantID: "pid", RoleInheritance: descope.RoleInheritanceNone, EnforceSSOExclusions: []string{"aaaa"}, FederatedAppIDs: []string{"app1"}})
	require.NoError(t, err)
	require.Equal(t, "qux", id)
}

func TestTenantCreateError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	id, err := mgmt.Tenant().Create(context.Background(), &descope.TenantRequest{})
	require.Error(t, err)
	require.Empty(t, id)
}

func TestTenantCreateWithIDSuccess(t *testing.T) {
	response := map[string]any{"id": "qux"}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "123", req["id"])
		require.Equal(t, "abc", req["name"])
		selfProvisioningDomains := req["selfProvisioningDomains"].([]any)
		require.Len(t, selfProvisioningDomains, 2)
		require.Equal(t, "foo", selfProvisioningDomains[0])
		require.Equal(t, "bar", selfProvisioningDomains[1])
		customAttributes := req["customAttributes"].(map[string]any)
		assert.EqualValues(t, map[string]any{"k1": "v1"}, customAttributes)
	}, response))
	err := mgmt.Tenant().CreateWithID(context.Background(), "123", &descope.TenantRequest{Name: "abc", SelfProvisioningDomains: []string{"foo", "bar"}, CustomAttributes: map[string]any{"k1": "v1"}})
	require.NoError(t, err)
}

func TestTenantCreateWithIDError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.Tenant().CreateWithID(context.Background(), "", &descope.TenantRequest{Name: "abc"})
	require.Error(t, err)
	err = mgmt.Tenant().CreateWithID(context.Background(), "123", &descope.TenantRequest{})
	require.Error(t, err)
}

func TestTenantUpdateSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "123", req["id"])
		require.Equal(t, "abc", req["name"])
		selfProvisioningDomains := req["selfProvisioningDomains"].([]any)
		require.Len(t, selfProvisioningDomains, 2)
		require.Equal(t, "foo", selfProvisioningDomains[0])
		require.Equal(t, "bar", selfProvisioningDomains[1])
		customAttributes := req["customAttributes"].(map[string]any)
		assert.EqualValues(t, map[string]any{"k1": "v1"}, customAttributes)
		require.True(t, req["enforceSSO"].(bool))
		require.EqualValues(t, []any{"aaaa"}, req["enforceSSOExclusions"].([]any))
		require.True(t, req["disabled"].(bool))
		require.Equal(t, string(descope.RoleInheritanceUserOnly), req["roleInheritance"])
		require.EqualValues(t, []any{"app1"}, req["federatedAppIds"].([]any))
	}))
	err := mgmt.Tenant().Update(context.Background(), "123", &descope.TenantRequest{Name: "abc", SelfProvisioningDomains: []string{"foo", "bar"}, CustomAttributes: map[string]any{"k1": "v1"}, Disabled: true, EnforceSSO: true, RoleInheritance: descope.RoleInheritanceUserOnly, EnforceSSOExclusions: []string{"aaaa"}, FederatedAppIDs: []string{"app1"}})
	require.NoError(t, err)
}

func TestTenantUpdateError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.Tenant().Update(context.Background(), "", &descope.TenantRequest{Name: "abc"})
	require.Error(t, err)
	err = mgmt.Tenant().Update(context.Background(), "123", &descope.TenantRequest{})
	require.Error(t, err)
}

func TestTenantPatchSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "123", req["id"])
		require.Equal(t, "abc", req["name"])
		require.True(t, req["disabled"].(bool))
		_, ok := req["selfProvisioningDomains"]
		require.False(t, ok)
		_, ok = req["customAttributes"]
		require.False(t, ok)
		_, ok = req["authType"]
		require.False(t, ok)
		_, ok = req["enforceSSO"]
		require.False(t, ok)
		_, ok = req["enforceSSOExclusions"]
		require.False(t, ok)
		_, ok = req["federatedAppIds"]
		require.False(t, ok)
		_, ok = req["roleInheritance"]
		require.False(t, ok)
	}))
	name := "abc"
	disabled := true
	err := mgmt.Tenant().Patch(context.Background(), &descope.PatchTenantRequest{ID: "123", Name: &name, Disabled: &disabled})
	require.NoError(t, err)
}

func TestTenantPatchSuccessAllFields(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "123", req["id"])
		require.Equal(t, "abc", req["name"])
		require.EqualValues(t, []any{"foo", "bar"}, req["selfProvisioningDomains"].([]any))
		customAttributes := req["customAttributes"].(map[string]any)
		assert.EqualValues(t, map[string]any{"k1": "v1"}, customAttributes)
		require.Equal(t, "saml", req["authType"])
		require.True(t, req["disabled"].(bool))
		require.True(t, req["enforceSSO"].(bool))
		require.EqualValues(t, []any{"aaaa"}, req["enforceSSOExclusions"].([]any))
		require.EqualValues(t, []any{"app1", "app2"}, req["federatedAppIds"].([]any))
		require.Equal(t, string(descope.RoleInheritanceUserOnly), req["roleInheritance"])
	}))
	name := "abc"
	domains := []string{"foo", "bar"}
	authType := "saml"
	disabled := true
	enforceSSO := true
	exclusions := []string{"aaaa"}
	appIDs := []string{"app1", "app2"}
	roleInheritance := descope.RoleInheritanceUserOnly
	err := mgmt.Tenant().Patch(context.Background(), &descope.PatchTenantRequest{
		ID:                      "123",
		Name:                    &name,
		SelfProvisioningDomains: &domains,
		CustomAttributes:        map[string]any{"k1": "v1"},
		AuthType:                &authType,
		Disabled:                &disabled,
		EnforceSSO:              &enforceSSO,
		EnforceSSOExclusions:    &exclusions,
		FederatedAppIDs:         &appIDs,
		RoleInheritance:         &roleInheritance,
	})
	require.NoError(t, err)
}

func TestTenantPatchError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.Tenant().Patch(context.Background(), nil)
	require.Error(t, err)
	err = mgmt.Tenant().Patch(context.Background(), &descope.PatchTenantRequest{})
	require.Error(t, err)
}

func TestTenantDeleteSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["id"])
		require.Equal(t, true, req["cascade"])
	}))
	err := mgmt.Tenant().Delete(context.Background(), "abc", true)
	require.NoError(t, err)
}

func TestTenantDeleteError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.Tenant().Delete(context.Background(), "", false)
	require.Error(t, err)
}

func TestAllTenantsLoadSuccess(t *testing.T) {
	response := map[string]any{
		"tenants": []map[string]any{{
			"id":                      "t1",
			"name":                    "abc",
			"selfProvisioningDomains": []string{"domain.com"},
			"createdTime":             int32(1726067547),
			"disabled":                true,
			"enforceSSO":              true,
		}}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
	}, response))
	res, err := mgmt.Tenant().LoadAll(context.Background())
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Len(t, res, 1)
	require.Equal(t, "t1", res[0].ID)
	require.Equal(t, "abc", res[0].Name)
	require.Len(t, res[0].SelfProvisioningDomains, 1)
	require.Equal(t, "domain.com", res[0].SelfProvisioningDomains[0])
	require.Equal(t, int32(1726067547), res[0].CreatedTime)
	require.True(t, res[0].Disabled)
	require.True(t, res[0].EnforceSSO)

}

func TestAllTenantsLoadError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.Tenant().LoadAll(context.Background())
	require.Error(t, err)
	require.Nil(t, res)
}

func TestSearchTenantsSuccess(t *testing.T) {
	m := map[string]any{"k1": "v1"}
	response := map[string]any{
		"tenants": []map[string]any{{
			"id":                      "t1",
			"name":                    "abc",
			"selfProvisioningDomains": []string{"domain.com"},
			"enforceSSO":              true,
		}}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.EqualValues(t, []any{"id1"}, req["tenantIds"])
		require.EqualValues(t, []any{"nm1"}, req["tenantNames"])
		require.EqualValues(t, []any{"spdn1"}, req["tenantSelfProvisioningDomains"])
		customAttributes := req["customAttributes"].(map[string]any)
		assert.EqualValues(t, map[string]any{"k1": "v1"}, customAttributes)
	}, response))
	res, err := mgmt.Tenant().SearchAll(context.Background(), &descope.TenantSearchOptions{IDs: []string{"id1"}, Names: []string{"nm1"}, SelfProvisioningDomains: []string{"spdn1"}, CustomAttributes: m})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Len(t, res, 1)
	require.Equal(t, "t1", res[0].ID)
	require.Equal(t, "abc", res[0].Name)
	require.Len(t, res[0].SelfProvisioningDomains, 1)
	require.Equal(t, "domain.com", res[0].SelfProvisioningDomains[0])
	require.False(t, res[0].Disabled)
	require.True(t, res[0].EnforceSSO)
}

func TestSearchTenantsLoadError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.Tenant().SearchAll(context.Background(), &descope.TenantSearchOptions{})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestTenantLoadSuccess(t *testing.T) {
	response := map[string]any{
		"id":                      "t1",
		"name":                    "abc",
		"selfProvisioningDomains": []string{"domain.com"},
		"createdTime":             int32(1726067547),
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
	}, response))
	res, err := mgmt.Tenant().Load(context.Background(), "t1")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "t1", res.ID)
	require.Equal(t, "abc", res.Name)
	require.Len(t, res.SelfProvisioningDomains, 1)
	require.Equal(t, "domain.com", res.SelfProvisioningDomains[0])
	require.Equal(t, int32(1726067547), res.CreatedTime)
}

func TestTenantLoadError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.Tenant().Load(context.Background(), "t1")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestTenantLoadNoIDError(t *testing.T) {
	response := map[string]any{
		"id":                      "t1",
		"name":                    "abc",
		"selfProvisioningDomains": []string{"domain.com"},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
	}, response))
	res, err := mgmt.Tenant().Load(context.Background(), "")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestGetTenantSettingsSuccess(t *testing.T) {
	tenantID := "abc"
	response := map[string]any{
		"inactivityTime":             10,
		"enableInactivity":           true,
		"inactivityTimeUnit":         "minutes",
		"enabled":                    true,
		"refreshTokenExpiration":     10,
		"refreshTokenExpirationUnit": "weeks",
		"sessionTokenExpiration":     11,
		"sessionTokenExpirationUnit": "minutes",
		"JITDisabled":                true,
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		params := helpers.ReadParams(r)
		require.Equal(t, tenantID, params["id"])
	}, response))
	res, err := mgmt.Tenant().GetSettings(context.Background(), tenantID)
	require.NoError(t, err)
	assert.True(t, res.EnableInactivity)
	assert.True(t, res.SessionSettingsEnabled)
	assert.EqualValues(t, 10, res.InactivityTime)
	assert.EqualValues(t, "minutes", res.InactivityTimeUnit)
	assert.EqualValues(t, 11, res.SessionTokenExpiration)
	assert.EqualValues(t, "minutes", res.SessionTokenExpirationUnit)
	assert.EqualValues(t, 10, res.RefreshTokenExpiration)
	assert.EqualValues(t, "weeks", res.RefreshTokenExpirationUnit)
	assert.True(t, res.JITDisabled)
}

func TestGetTenantSettingsError(t *testing.T) {
	tenantID := "abc"
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		params := helpers.ReadParams(r)
		require.Equal(t, tenantID, params["id"])
	}))
	res, err := mgmt.Tenant().GetSettings(context.Background(), tenantID)
	require.Error(t, err)
	assert.Nil(t, res)
}

func TestTenantConfigureSettingsSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "tenant", req["tenantId"])
		require.Equal(t, true, req["enabled"])
		require.Equal(t, true, req["enableInactivity"])
		require.Equal(t, float64(19), req["sessionTokenExpiration"])
		require.Equal(t, true, req["JITDisabled"])
		require.EqualValues(t, []any{"test"}, req["selfProvisioningDomains"])
	}))
	err := mgmt.Tenant().ConfigureSettings(context.Background(), "tenant", &descope.TenantSettings{EnableInactivity: true, SessionSettingsEnabled: true, SessionTokenExpiration: 19, SelfProvisioningDomains: []string{"test"}, JITDisabled: true})
	require.NoError(t, err)
}

func TestTenantConfigureSettingsEmptyError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.Tenant().ConfigureSettings(context.Background(), "", &descope.TenantSettings{})
	require.Error(t, err)
}

func TestTenantConfigureSettingsError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	err := mgmt.Tenant().ConfigureSettings(context.Background(), "test", &descope.TenantSettings{})
	require.Error(t, err)
}

func TestTenantGenerateSSOConfigurationLinkSuccess(t *testing.T) {
	response := map[string]any{
		"adminSSOConfigurationLink": "some link",
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "tenant", req["tenantId"])
		require.Equal(t, "", req["ssoId"])
		require.Equal(t, float64(60*60*24), req["expireTime"])
	}, response))
	link, err := mgmt.Tenant().GenerateSSOConfigurationLink(context.Background(), "tenant", 60*60*24, "", "", "", "")
	require.NoError(t, err)
	assert.EqualValues(t, "some link", link)
}

func TestTenantGenerateSSOConfigurationLinkSuccessWithSSOID(t *testing.T) {
	response := map[string]any{
		"adminSSOConfigurationLink": "some link",
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "tenant", req["tenantId"])
		require.Equal(t, "bla", req["ssoId"])
		require.Equal(t, float64(60*60*24), req["expireTime"])
		require.Equal(t, "a@a.com", req["email"])
		require.Equal(t, "template-id", req["templateId"])
	}, response))
	link, err := mgmt.Tenant().GenerateSSOConfigurationLink(context.Background(), "tenant", 60*60*24, "bla", "a@a.com", "template-id", "")
	require.NoError(t, err)
	assert.EqualValues(t, "some link", link)
}

func TestTenantGenerateSSOConfigurationLinkWithActor(t *testing.T) {
	response := map[string]any{
		"adminSSOConfigurationLink": "some link",
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "tenant", req["tenantId"])
		require.Equal(t, "admin-actor-1", req["actorId"])
	}, response))
	link, err := mgmt.Tenant().GenerateSSOConfigurationLink(context.Background(), "tenant", 60*60*24, "", "", "", "admin-actor-1")
	require.NoError(t, err)
	assert.EqualValues(t, "some link", link)
}

func TestTenantGenerateSSOConfigurationLinkError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "tenant", req["tenantId"])
		require.Equal(t, "", req["ssoId"])
		require.Equal(t, float64(60*60*24), req["expireTime"])
	}))
	link, err := mgmt.Tenant().GenerateSSOConfigurationLink(context.Background(), "tenant", 60*60*24, "", "", "", "")
	require.Error(t, err)
	assert.Empty(t, link)
}

func TestTenantGenerateSSOConfigurationLinkNoTenantID(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "tenant", req["tenantId"])
		require.Equal(t, "ssoId", "")
		require.Equal(t, float64(60*60*24), req["expireTime"])
	}))
	link, err := mgmt.Tenant().GenerateSSOConfigurationLink(context.Background(), "", 60*60*24, "", "", "", "")
	require.ErrorIs(t, err, utils.NewInvalidArgumentError("tenantId"))
	assert.Empty(t, link)
}

func TestTenantRevokeSSOConfigurationLinkSuccess(t *testing.T) {
	response := map[string]any{}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "tenant", req["tenantId"])
		require.Equal(t, "", req["ssoId"])
	}, response))
	err := mgmt.Tenant().RevokeSSOConfigurationLink(context.Background(), "tenant", "")
	require.NoError(t, err)
}

func TestTenantRevokeSSOConfigurationLinkSuccessWithSSOID(t *testing.T) {
	response := map[string]any{}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "tenant", req["tenantId"])
		require.Equal(t, "bla", req["ssoId"])
	}, response))
	err := mgmt.Tenant().RevokeSSOConfigurationLink(context.Background(), "tenant", "bla")
	require.NoError(t, err)
}

func TestTenantRevokeSSOConfigurationLinkError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "tenant", req["tenantId"])
		require.Equal(t, "", req["ssoId"])
	}))
	err := mgmt.Tenant().RevokeSSOConfigurationLink(context.Background(), "tenant", "")
	require.Error(t, err)
}

func TestTenantRevokeSSOConfigurationLinkNoTenantID(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "tenant", req["tenantId"])
		require.Equal(t, "ssoId", "")
	}))
	err := mgmt.Tenant().RevokeSSOConfigurationLink(context.Background(), "", "")
	require.ErrorIs(t, err, utils.NewInvalidArgumentError("tenantId"))
}

func TestTenantUpdateDefaultRolesSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "tenant", req["id"])
		roles := req["defaultRoles"].([]any)
		require.Len(t, roles, 2)
		require.Equal(t, "Role1", roles[0])
		require.Equal(t, "Role2", roles[1])
	}))
	err := mgmt.Tenant().UpdateDefaultRoles(context.Background(), "tenant", []string{"Role1", "Role2"})
	require.NoError(t, err)
}

func TestTenantUpdateDefaultRolesError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "tenant", req["id"])
	}))
	err := mgmt.Tenant().UpdateDefaultRoles(context.Background(), "tenant", []string{"Role1"})
	require.Error(t, err)
}

func TestTenantUpdateDefaultRolesNoTenantID(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.Tenant().UpdateDefaultRoles(context.Background(), "", []string{"Role1"})
	require.ErrorIs(t, err, utils.NewInvalidArgumentError("tenantId"))
}

func TestTenantCreateBatchSuccess(t *testing.T) {
	response := map[string]any{
		"createdTenants": []map[string]any{{"id": "t1", "name": "abc"}},
		"failedTenants": []map[string]any{{
			"failure": "already exists",
			"tenant": map[string]any{
				"id":                      "t2",
				"name":                    "def",
				"selfProvisioningDomains": []string{"foo"},
				"customAttributes":        map[string]any{"k1": "v1"},
				"authType":                "saml",
				"disabled":                true,
				"enforceSSO":              true,
				"enforceSSOExclusions":    []string{"u1"},
				"federatedAppIds":         []string{"app1"},
				"parent":                  "pid",
				"roleInheritance":         "none",
				"unknownField":            "ignored",
			},
		}},
		"additionalErrors": map[string]string{"t3": "some error"},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/tenant/create/batch", r.URL.Path)
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		tenants := req["tenants"].([]any)
		require.Len(t, tenants, 2)
		t1 := tenants[0].(map[string]any)
		require.Equal(t, "abc", t1["name"])
		require.NotContains(t, t1, "id")
		require.NotContains(t, t1, "parent")
		t2 := tenants[1].(map[string]any)
		require.Equal(t, "t2", t2["id"])
		require.Equal(t, "def", t2["name"])
		require.EqualValues(t, []any{"foo"}, t2["selfProvisioningDomains"])
		require.EqualValues(t, map[string]any{"k1": "v1"}, t2["customAttributes"])
		require.Equal(t, "saml", t2["authType"])
		require.True(t, t2["disabled"].(bool))
		require.True(t, t2["enforceSSO"].(bool))
		require.EqualValues(t, []any{"u1"}, t2["enforceSSOExclusions"])
		require.EqualValues(t, []any{"app1"}, t2["federatedAppIds"])
		require.Equal(t, "pid", t2["parent"])
		require.Equal(t, string(descope.RoleInheritanceNone), t2["roleInheritance"])
	}, response))

	res, err := mgmt.Tenant().CreateBatch(context.Background(), []*descope.BatchCreateTenant{
		{Name: "abc"},
		{ID: "t2", Name: "def", SelfProvisioningDomains: []string{"foo"}, CustomAttributes: map[string]any{"k1": "v1"}, AuthType: "saml", Disabled: true, EnforceSSO: true, EnforceSSOExclusions: []string{"u1"}, FederatedAppIDs: []string{"app1"}, ParentTenantID: "pid", RoleInheritance: descope.RoleInheritanceNone},
	})
	require.NoError(t, err)
	require.Len(t, res.CreatedTenants, 1)
	require.Equal(t, "t1", res.CreatedTenants[0].ID)
	require.Equal(t, "abc", res.CreatedTenants[0].Name)
	require.Len(t, res.FailedTenants, 1)
	require.Equal(t, "already exists", res.FailedTenants[0].Failure)
	require.Equal(t, &descope.BatchCreateTenant{ID: "t2", Name: "def", SelfProvisioningDomains: []string{"foo"}, CustomAttributes: map[string]any{"k1": "v1"}, AuthType: "saml", Disabled: true, EnforceSSO: true, EnforceSSOExclusions: []string{"u1"}, FederatedAppIDs: []string{"app1"}, ParentTenantID: "pid", RoleInheritance: descope.RoleInheritanceNone}, res.FailedTenants[0].Tenant)
	require.Equal(t, map[string]string{"t3": "some error"}, res.AdditionalErrors)
}

func TestTenantCreateBatchEmptyResponse(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(nil, map[string]any{"createdTenants": []any{}, "failedTenants": []any{}}))
	res, err := mgmt.Tenant().CreateBatch(context.Background(), []*descope.BatchCreateTenant{{Name: "abc"}})
	require.NoError(t, err)
	require.Empty(t, res.CreatedTenants)
	require.Empty(t, res.FailedTenants)
	require.Nil(t, res.AdditionalErrors)
}

func TestTenantCreateBatchInvalidArguments(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		require.Fail(t, "request should not be sent")
	}))
	for name, tc := range map[string]struct {
		tenants []*descope.BatchCreateTenant
		arg     string
	}{
		"no tenants":                   {nil, "tenants"},
		"nil tenant":                   {[]*descope.BatchCreateTenant{nil}, "tenants"},
		"no name":                      {[]*descope.BatchCreateTenant{{ID: "t1"}}, "name"},
		"empty selfProvisioningDomain": {[]*descope.BatchCreateTenant{{Name: "abc", SelfProvisioningDomains: []string{""}}}, "selfProvisioningDomains"},
		"empty enforceSSOExclusion":    {[]*descope.BatchCreateTenant{{Name: "abc", EnforceSSOExclusions: []string{""}}}, "enforceSSOExclusions"},
		"empty federatedAppID":         {[]*descope.BatchCreateTenant{{Name: "abc", FederatedAppIDs: []string{""}}}, "federatedAppIds"},
	} {
		t.Run(name, func(t *testing.T) {
			res, err := mgmt.Tenant().CreateBatch(context.Background(), tc.tenants)
			require.ErrorIs(t, err, descope.ErrInvalidArguments)
			require.ErrorContains(t, err, tc.arg)
			require.Nil(t, res)
		})
	}
}

func TestTenantCreateBatchError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.Tenant().CreateBatch(context.Background(), []*descope.BatchCreateTenant{{Name: "abc"}})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestTenantCreateBatchBadResponse(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(nil, "not an object"))
	res, err := mgmt.Tenant().CreateBatch(context.Background(), []*descope.BatchCreateTenant{{Name: "abc"}})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestTenantUpdateBatchSuccess(t *testing.T) {
	response := map[string]any{
		"updatedTenantIds": []string{"t1"},
		"failedTenants": []map[string]any{{
			"failure": "not found",
			"tenant": map[string]any{
				"id":                      "t2",
				"name":                    "def",
				"selfProvisioningDomains": []string{"foo"},
				"customAttributes":        map[string]any{"k1": "v1"},
				"authType":                "oidc",
				"disabled":                true,
				"enforceSSO":              true,
				"enforceSSOExclusions":    []string{"u1"},
				"federatedAppIds":         []string{"app1"},
				"roleInheritance":         "none",
			},
		}},
		"additionalErrors": map[string]string{"t3": "some error"},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/tenant/update/batch", r.URL.Path)
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		tenants := req["tenants"].([]any)
		require.Len(t, tenants, 2)
		t1 := tenants[0].(map[string]any)
		require.Equal(t, "t1", t1["id"])
		require.Equal(t, "abc", t1["name"])
		t2 := tenants[1].(map[string]any)
		require.Equal(t, "t2", t2["id"])
		require.Equal(t, "def", t2["name"])
		require.EqualValues(t, []any{"foo"}, t2["selfProvisioningDomains"])
		require.EqualValues(t, map[string]any{"k1": "v1"}, t2["customAttributes"])
		require.Equal(t, "oidc", t2["authType"])
		require.True(t, t2["disabled"].(bool))
		require.True(t, t2["enforceSSO"].(bool))
		require.EqualValues(t, []any{"u1"}, t2["enforceSSOExclusions"])
		require.EqualValues(t, []any{"app1"}, t2["federatedAppIds"])
		require.Equal(t, string(descope.RoleInheritanceNone), t2["roleInheritance"])
		require.NotContains(t, t2, "parent")
	}, response))

	res, err := mgmt.Tenant().UpdateBatch(context.Background(), []*descope.BatchUpdateTenant{
		{ID: "t1", Name: "abc"},
		{ID: "t2", Name: "def", SelfProvisioningDomains: []string{"foo"}, CustomAttributes: map[string]any{"k1": "v1"}, AuthType: "oidc", Disabled: true, EnforceSSO: true, EnforceSSOExclusions: []string{"u1"}, FederatedAppIDs: []string{"app1"}, RoleInheritance: descope.RoleInheritanceNone},
	})
	require.NoError(t, err)
	require.Equal(t, []string{"t1"}, res.UpdatedTenantIDs)
	require.Len(t, res.FailedTenants, 1)
	require.Equal(t, "not found", res.FailedTenants[0].Failure)
	require.Equal(t, &descope.BatchUpdateTenant{ID: "t2", Name: "def", SelfProvisioningDomains: []string{"foo"}, CustomAttributes: map[string]any{"k1": "v1"}, AuthType: "oidc", Disabled: true, EnforceSSO: true, EnforceSSOExclusions: []string{"u1"}, FederatedAppIDs: []string{"app1"}, RoleInheritance: descope.RoleInheritanceNone}, res.FailedTenants[0].Tenant)
	require.Equal(t, map[string]string{"t3": "some error"}, res.AdditionalErrors)
}

func TestTenantUpdateBatchInvalidArguments(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		require.Fail(t, "request should not be sent")
	}))
	for name, tc := range map[string]struct {
		tenants []*descope.BatchUpdateTenant
		arg     string
	}{
		"no tenants":                   {nil, "tenants"},
		"nil tenant":                   {[]*descope.BatchUpdateTenant{nil}, "tenants"},
		"no id":                        {[]*descope.BatchUpdateTenant{{Name: "abc"}}, "id"},
		"no name":                      {[]*descope.BatchUpdateTenant{{ID: "t1"}}, "name"},
		"empty selfProvisioningDomain": {[]*descope.BatchUpdateTenant{{ID: "t1", Name: "abc", SelfProvisioningDomains: []string{""}}}, "selfProvisioningDomains"},
		"empty enforceSSOExclusion":    {[]*descope.BatchUpdateTenant{{ID: "t1", Name: "abc", EnforceSSOExclusions: []string{""}}}, "enforceSSOExclusions"},
		"empty federatedAppID":         {[]*descope.BatchUpdateTenant{{ID: "t1", Name: "abc", FederatedAppIDs: []string{""}}}, "federatedAppIds"},
	} {
		t.Run(name, func(t *testing.T) {
			res, err := mgmt.Tenant().UpdateBatch(context.Background(), tc.tenants)
			require.ErrorIs(t, err, descope.ErrInvalidArguments)
			require.ErrorContains(t, err, tc.arg)
			require.Nil(t, res)
		})
	}
}

func TestTenantUpdateBatchError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.Tenant().UpdateBatch(context.Background(), []*descope.BatchUpdateTenant{{ID: "t1", Name: "abc"}})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestTenantUpdateBatchBadResponse(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(nil, "not an object"))
	res, err := mgmt.Tenant().UpdateBatch(context.Background(), []*descope.BatchUpdateTenant{{ID: "t1", Name: "abc"}})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestTenantDeleteBatchSuccess(t *testing.T) {
	response := map[string]any{
		"deletedTenantIds": []string{"t1"},
		"failedTenants":    []map[string]any{{"failure": "not found", "id": "t2"}},
		"additionalErrors": map[string]string{"t3": "some error"},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/tenant/delete/batch", r.URL.Path)
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.EqualValues(t, []any{"t1", "t2"}, req["ids"])
		require.Equal(t, true, req["cascade"])
	}, response))
	res, err := mgmt.Tenant().DeleteBatch(context.Background(), []string{"t1", "t2"}, true)
	require.NoError(t, err)
	require.Equal(t, []string{"t1"}, res.DeletedTenantIDs)
	require.Equal(t, []*descope.DeleteTenantBatchFailure{{Failure: "not found", ID: "t2"}}, res.FailedTenants)
	require.Equal(t, map[string]string{"t3": "some error"}, res.AdditionalErrors)
}

func TestTenantDeleteBatchSendsCascadeFalse(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, false, req["cascade"])
	}, map[string]any{}))
	_, err := mgmt.Tenant().DeleteBatch(context.Background(), []string{"t1"}, false)
	require.NoError(t, err)
}

func TestTenantDeleteBatchInvalidArguments(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		require.Fail(t, "request should not be sent")
	}))
	res, err := mgmt.Tenant().DeleteBatch(context.Background(), nil, false)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	require.ErrorContains(t, err, "ids")
	require.Nil(t, res)
	res, err = mgmt.Tenant().DeleteBatch(context.Background(), []string{"t1", ""}, false)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	require.ErrorContains(t, err, "ids")
	require.Nil(t, res)
}

func TestTenantDeleteBatchError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.Tenant().DeleteBatch(context.Background(), []string{"t1"}, false)
	require.Error(t, err)
	require.Nil(t, res)
}

func TestTenantDeleteBatchBadResponse(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(nil, "not an object"))
	res, err := mgmt.Tenant().DeleteBatch(context.Background(), []string{"t1"}, false)
	require.Error(t, err)
	require.Nil(t, res)
}
