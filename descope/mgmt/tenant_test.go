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
	id, err := mgmt.Tenant().Create("key", "abc", []string{"foo", "bar"})
	require.NoError(t, err)
	require.Equal(t, "qux", id)
}

func TestTenantCreateError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	id, err := mgmt.Tenant().Create("key", "", nil)
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
	err := mgmt.Tenant().CreateWithID("key", "123", "abc", []string{"foo", "bar"})
	require.NoError(t, err)
}

func TestTenantCreateWithIDError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.Tenant().CreateWithID("key", "", "abc", nil)
	require.Error(t, err)
	err = mgmt.Tenant().CreateWithID("key", "123", "", nil)
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
	err := mgmt.Tenant().Update("key", "123", "abc", []string{"foo", "bar"})
	require.NoError(t, err)
}

func TestTenantUpdateError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.Tenant().Update("key", "", "abc", nil)
	require.Error(t, err)
	err = mgmt.Tenant().Update("key", "123", "", nil)
	require.Error(t, err)
}

func TestTenantDeleteSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["id"])
	}))
	err := mgmt.Tenant().Delete("key", "abc")
	require.NoError(t, err)
}

func TestTenantDeleteError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.Tenant().Delete("key", "")
	require.Error(t, err)
}
