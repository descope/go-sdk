package mgmt

import (
	"context"
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope"
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
		customAttributes := req["customAttributes"].(map[string]any)
		assert.EqualValues(t, map[string]any{"k1": "v1"}, customAttributes)
	}, response))

	id, err := mgmt.Tenant().Create(context.Background(), &descope.TenantRequest{Name: "abc", SelfProvisioningDomains: []string{"foo", "bar"}, CustomAttributes: map[string]any{"k1": "v1"}})
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
	}))
	err := mgmt.Tenant().Update(context.Background(), "123", &descope.TenantRequest{Name: "abc", SelfProvisioningDomains: []string{"foo", "bar"}, CustomAttributes: map[string]any{"k1": "v1"}})
	require.NoError(t, err)
}

func TestTenantUpdateError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.Tenant().Update(context.Background(), "", &descope.TenantRequest{Name: "abc"})
	require.Error(t, err)
	err = mgmt.Tenant().Update(context.Background(), "123", &descope.TenantRequest{})
	require.Error(t, err)
}

func TestTenantDeleteSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["id"])
	}))
	err := mgmt.Tenant().Delete(context.Background(), "abc")
	require.NoError(t, err)
}

func TestTenantDeleteError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.Tenant().Delete(context.Background(), "")
	require.Error(t, err)
}

func TestAllTenantsLoadSuccess(t *testing.T) {
	response := map[string]any{
		"tenants": []map[string]any{{
			"id":                      "t1",
			"name":                    "abc",
			"selfProvisioningDomains": []string{"domain.com"},
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
