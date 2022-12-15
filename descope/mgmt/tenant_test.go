package mgmt

import (
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope/tests/helpers"
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
	}, response))
	id, err := mgmt.Tenant().Create("abc", []string{"foo", "bar"})
	require.NoError(t, err)
	require.Equal(t, "qux", id)
}

func TestTenantCreateError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	id, err := mgmt.Tenant().Create("", nil)
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
	}, response))
	err := mgmt.Tenant().CreateWithID("123", "abc", []string{"foo", "bar"})
	require.NoError(t, err)
}

func TestTenantCreateWithIDError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.Tenant().CreateWithID("", "abc", nil)
	require.Error(t, err)
	err = mgmt.Tenant().CreateWithID("123", "", nil)
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
	}))
	err := mgmt.Tenant().Update("123", "abc", []string{"foo", "bar"})
	require.NoError(t, err)
}

func TestTenantUpdateError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.Tenant().Update("", "abc", nil)
	require.Error(t, err)
	err = mgmt.Tenant().Update("123", "", nil)
	require.Error(t, err)
}

func TestTenantDeleteSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["id"])
	}))
	err := mgmt.Tenant().Delete("abc")
	require.NoError(t, err)
}

func TestTenantDeleteError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.Tenant().Delete("")
	require.Error(t, err)
}

func TestTenantLoadSuccess(t *testing.T) {
	response := map[string]any{
		"tenants": []map[string]any{{
			"id":                      "t1",
			"name":                    "abc",
			"selfProvisioningDomains": []string{"domain.com"},
		}}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
	}, response))
	res, err := mgmt.Tenant().LoadAll()
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Len(t, res, 1)
	require.Equal(t, "t1", res[0].ID)
	require.Equal(t, "abc", res[0].Name)
	require.Len(t, res[0].SelfProvisioningDomains, 1)
	require.Equal(t, "domain.com", res[0].SelfProvisioningDomains[0])
}

func TestTenantLoadError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.Tenant().LoadAll()
	require.Error(t, err)
	require.Nil(t, res)
}
