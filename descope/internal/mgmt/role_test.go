package mgmt

import (
	"context"
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/tests/helpers"
	"github.com/stretchr/testify/require"
)

func TestRoleCreateSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["name"])
		require.Equal(t, "description", req["description"])
		roleNames := req["permissionNames"].([]any)
		require.Len(t, roleNames, 1)
		require.Equal(t, "foo", roleNames[0])
		require.Equal(t, "t1", req["tenantId"])
		require.Equal(t, true, req["default"])
	}))
	err := mgmt.Role().Create(context.Background(), "abc", "description", []string{"foo"}, "t1", true)
	require.NoError(t, err)
}

func TestRoleCreateError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.Role().Create(context.Background(), "", "description", []string{"foo"}, "", false)
	require.Error(t, err)
}

func TestRoleUpdateSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["name"])
		require.Equal(t, "def", req["newName"])
		require.Equal(t, "description", req["description"])
		roleNames := req["permissionNames"].([]any)
		require.Len(t, roleNames, 1)
		require.Equal(t, "foo", roleNames[0])
		require.Equal(t, "t1", req["tenantId"])
		require.Equal(t, true, req["default"])
	}))
	err := mgmt.Role().Update(context.Background(), "abc", "t1", "def", "description", []string{"foo"}, true)
	require.NoError(t, err)
}

func TestRoleUpdateError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.Role().Update(context.Background(), "", "", "def", "description", []string{"foo"}, false)
	require.Error(t, err)
	err = mgmt.Role().Update(context.Background(), "abc", "", "", "description", []string{"foo"}, false)
	require.Error(t, err)
}

func TestRoleDeleteSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["name"])
		require.Equal(t, "t1", req["tenantId"])
	}))
	err := mgmt.Role().Delete(context.Background(), "abc", "t1")
	require.NoError(t, err)
}

func TestRoleDeleteError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.Role().Delete(context.Background(), "", "")
	require.Error(t, err)
}

func TestRoleLoadSuccess(t *testing.T) {
	response := map[string]any{
		"roles": []map[string]any{{
			"name":    "abc",
			"default": true,
		}}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
	}, response))
	res, err := mgmt.Role().LoadAll(context.Background())
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Len(t, res, 1)
	require.Equal(t, "abc", res[0].Name)
	require.Equal(t, true, res[0].Default)
}

func TestRoleLoadError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.Role().LoadAll(context.Background())
	require.Error(t, err)
	require.Nil(t, res)
}

func TestRoleSearchSuccess(t *testing.T) {
	response := map[string]any{
		"roles": []map[string]any{{
			"name": "abc",
		}}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.ElementsMatch(t, []string{"t1"}, req["tenantIds"])
		require.ElementsMatch(t, []string{"r1"}, req["roleNames"])
		require.Equal(t, "abc", req["roleNameLike"])
		require.ElementsMatch(t, []string{"p1"}, req["permissionNames"])
	}, response))
	res, err := mgmt.Role().Search(context.Background(), &descope.RoleSearchOptions{
		TenantIDs:       []string{"t1"},
		RoleNames:       []string{"r1"},
		RoleNameLike:    "abc",
		PermissionNames: []string{"p1"},
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Len(t, res, 1)
	require.Equal(t, "abc", res[0].Name)
}

func TestRoleSearchError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.Role().Search(context.Background(), &descope.RoleSearchOptions{})
	require.Error(t, err)
	require.Nil(t, res)
}
