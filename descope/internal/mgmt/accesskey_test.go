package mgmt

import (
	"context"
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/tests/helpers"
	"github.com/stretchr/testify/require"
)

func TestAccessKeyCreateSuccess(t *testing.T) {
	desc := "abc123"
	response := map[string]any{
		"cleartext": "cleartext",
		"key": map[string]any{
			"name":         "abc",
			"customClaims": map[string]any{"k1": "v1"},
			"description":  desc,
			"permittedIps": []string{"10.0.0.1"},
		}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["name"])
		require.Equal(t, "uid", req["userId"])
		require.EqualValues(t, 0, req["expireTime"])
		roleNames := req["roleNames"].([]any)
		require.Len(t, roleNames, 1)
		require.Equal(t, "foo", roleNames[0])
		require.Len(t, req["customClaims"], 1)
		require.Equal(t, desc, req["description"])
		permittedIPs := req["permittedIps"].([]any)
		require.Len(t, permittedIPs, 1)
		require.Equal(t, "10.0.0.1", permittedIPs[0])
	}, response))
	cc := map[string]any{"k1": "v1"}
	cleartext, key, err := mgmt.AccessKey().Create(context.Background(), "abc", desc, 0, []string{"foo"}, nil, "uid", cc, []string{"10.0.0.1"})
	require.NoError(t, err)
	require.Equal(t, "cleartext", cleartext)
	require.Equal(t, "abc", key.Name)
	require.Len(t, key.CustomClaims, 1)
	require.Equal(t, "v1", key.CustomClaims["k1"])
	require.Equal(t, desc, key.Description)
	require.Len(t, key.PermittedIPs, 1)
	require.Equal(t, "10.0.0.1", key.PermittedIPs[0])
}

func TestAccessKeyCreateError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, _, err := mgmt.AccessKey().Create(context.Background(), "", "", 0, nil, nil, "", nil, nil)
	require.Error(t, err)
}

func TestAccessKeyLoadSuccess(t *testing.T) {
	response := map[string]any{
		"key": map[string]any{
			"id":          "ak1",
			"name":        "abc",
			"description": "a123f",
		}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		params := helpers.ReadParams(r)
		require.Equal(t, "ak1", params["id"])
	}, response))
	res, err := mgmt.AccessKey().Load(context.Background(), "ak1")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "abc", res.Name)
	require.Equal(t, "a123f", res.Description)
}

func TestAccessKeyLoadBadInput(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.AccessKey().Load(context.Background(), "")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestAccessKeyLoadError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.AccessKey().Load(context.Background(), "ak1")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestSearchAllAccessKeysSuccess(t *testing.T) {
	response := map[string]any{
		"keys": []map[string]any{{
			"id": "ak1",
		}},
	}
	tenantIDs := []string{"t1"}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.EqualValues(t, tenantIDs[0], req["tenantIds"].([]any)[0])
	}, response))
	res, err := mgmt.AccessKey().SearchAll(context.Background(), tenantIDs)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Len(t, res, 1)
	require.Equal(t, "ak1", res[0].ID)
}

func TestSearchAllAccessKeysError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.AccessKey().SearchAll(context.Background(), nil)
	require.Error(t, err)
	require.Nil(t, res)
}

func TestAccessKeyUpdateSuccess(t *testing.T) {
	desc := "desc"
	response := map[string]any{
		"key": map[string]any{
			"id":   "ak1",
			"name": "abc",
			"keyTenants": []map[string]any{{
				"tenantId":  "t1",
				"roleNames": []string{"role"},
			}},
			"description":  "desc",
			"permittedIps": []string{"1.2.3.4"},
		}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "ak1", req["id"])
		require.Equal(t, "abc", req["name"])
		require.Equal(t, desc, req["description"])
		require.EqualValues(t, []any{"role"}, req["roleNames"])
		require.Len(t, req["keyTenants"].([]any), 1)
		require.EqualValues(t, "t1", req["keyTenants"].([]any)[0].(map[string]any)["tenantId"])
		require.EqualValues(t, []any{"role"}, req["keyTenants"].([]any)[0].(map[string]any)["roleNames"])
		require.EqualValues(t, map[string]any{"k1": "v1"}, req["customClaims"])
		require.EqualValues(t, []any{"1.2.3.4"}, req["permittedIps"])
	}, response))
	res, err := mgmt.AccessKey().Update(context.Background(), "ak1", "abc", &desc, []string{"role"}, []*descope.AssociatedTenant{{TenantID: "t1", Roles: []string{"role"}}}, map[string]any{"k1": "v1"}, []string{"1.2.3.4"})
	require.NoError(t, err)
	require.Equal(t, "ak1", res.ID)
	require.Equal(t, "abc", res.Name)
	require.Equal(t, desc, res.Description)
	require.Len(t, res.KeyTenants, 1)
	require.Equal(t, "t1", res.KeyTenants[0].TenantID)
	require.Equal(t, "role", res.KeyTenants[0].Roles[0])
	require.Len(t, res.PermittedIPs, 1)
	require.Equal(t, "1.2.3.4", res.PermittedIPs[0])
}

func TestAccessKeyUpdateWontChangeSuccess(t *testing.T) {
	response := map[string]any{
		"key": map[string]any{
			"id":   "ak1",
			"name": "abc",
			"keyTenants": []map[string]any{{
				"tenantId":  "t1",
				"roleNames": []string{"role"},
			}},
			"description": "desc",
		}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "ak1", req["id"])
		require.Equal(t, "abc", req["name"])
		// We make sure description is not present in the request
		_, ok := req["description"]
		require.False(t, ok)
	}, response))
	res, err := mgmt.AccessKey().Update(context.Background(), "ak1", "abc", nil, nil, nil, nil, nil)
	require.NoError(t, err)
	require.Equal(t, "ak1", res.ID)
	require.Equal(t, "abc", res.Name)
	require.Equal(t, "desc", res.Description)
	require.Len(t, res.KeyTenants, 1)
	require.Equal(t, "t1", res.KeyTenants[0].TenantID)
	require.Equal(t, "role", res.KeyTenants[0].Roles[0])
}

func TestAccessKeyUpdateError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, err := mgmt.AccessKey().Update(context.Background(), "", "abc", nil, nil, nil, nil, nil)
	require.Error(t, err)
	_, err = mgmt.AccessKey().Update(context.Background(), "ak1", "", nil, nil, nil, nil, nil)
	require.Error(t, err)
}

func TestAccessKeyDeactivateSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "ak1", req["id"])
	}))
	err := mgmt.AccessKey().Deactivate(context.Background(), "ak1")
	require.NoError(t, err)
}

func TestAccessKeyDeactivateError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.AccessKey().Deactivate(context.Background(), "")
	require.Error(t, err)
}

func TestAccessKeyActivateSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "ak1", req["id"])
	}))
	err := mgmt.AccessKey().Activate(context.Background(), "ak1")
	require.NoError(t, err)
}

func TestAccessKeyActivateError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.AccessKey().Activate(context.Background(), "")
	require.Error(t, err)
}

func TestAccessKeyDeleteSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "ak1", req["id"])
	}))
	err := mgmt.AccessKey().Delete(context.Background(), "ak1")
	require.NoError(t, err)
}

func TestAccessKeyDeleteError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.AccessKey().Delete(context.Background(), "")
	require.Error(t, err)
}
