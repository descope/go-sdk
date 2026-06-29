package mgmt

import (
	"context"
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/tests/helpers"
	"github.com/stretchr/testify/require"
)

func TestPermissionCreateBatchSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		permissions, ok := req["permissions"].([]any)
		require.True(t, ok)
		require.Len(t, permissions, 2)
	}))
	err := mgmt.Permission().CreateBatch(context.Background(), []*descope.Permission{
		{Name: "abc", Description: "first"},
		{Name: "def", Description: "second"},
	})
	require.NoError(t, err)
}

func TestPermissionCreateBatchError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.Permission().CreateBatch(context.Background(), nil)
	require.Error(t, err)
}

func TestPermissionUpdateBatchSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		permissions, ok := req["permissions"].([]any)
		require.True(t, ok)
		require.Len(t, permissions, 1)
	}))
	err := mgmt.Permission().UpdateBatch(context.Background(), []*descope.PermissionUpdateRequest{
		{Name: "abc", NewName: "def", Description: "description"},
	})
	require.NoError(t, err)
}

func TestPermissionUpdateBatchError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.Permission().UpdateBatch(context.Background(), nil)
	require.Error(t, err)
}

func TestPermissionDeleteBatchSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		names, ok := req["names"].([]any)
		require.True(t, ok)
		require.Len(t, names, 2)
	}))
	err := mgmt.Permission().DeleteBatch(context.Background(), []string{"abc", "def"}, nil)
	require.NoError(t, err)
}

func TestPermissionDeleteBatchError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.Permission().DeleteBatch(context.Background(), nil, nil)
	require.Error(t, err)
}

func TestPermissionCreateSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["name"])
		require.Equal(t, "description", req["description"])
	}))
	err := mgmt.Permission().Create(context.Background(), "abc", "description")
	require.NoError(t, err)
}

func TestPermissionCreateError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.Permission().Create(context.Background(), "", "description")
	require.Error(t, err)
}

func TestPermissionUpdateSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["name"])
		require.Equal(t, "def", req["newName"])
		require.Equal(t, "description", req["description"])
	}))
	err := mgmt.Permission().Update(context.Background(), "abc", "def", "description")
	require.NoError(t, err)
}

func TestPermissionUpdateError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.Permission().Update(context.Background(), "", "def", "description")
	require.Error(t, err)
	err = mgmt.Permission().Update(context.Background(), "abc", "", "description")
	require.Error(t, err)
}

func TestPermissionUpdateWithIDSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "PERM3D57zwRsVJhImuBMdlYSg88To4W0", req["id"])
		require.Equal(t, "def", req["newName"])
		require.Equal(t, "description", req["description"])
		require.Nil(t, req["name"])
	}))
	err := mgmt.Permission().UpdateWithID(context.Background(), "PERM3D57zwRsVJhImuBMdlYSg88To4W0", "def", "description")
	require.NoError(t, err)
}

func TestPermissionUpdateWithIDError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.Permission().UpdateWithID(context.Background(), "", "def", "description")
	require.Error(t, err)
	err = mgmt.Permission().UpdateWithID(context.Background(), "PERM3D57zwRsVJhImuBMdlYSg88To4W0", "", "description")
	require.Error(t, err)
}

func TestPermissionDeleteSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["name"])
	}))
	err := mgmt.Permission().Delete(context.Background(), "abc")
	require.NoError(t, err)
}

func TestPermissionDeleteError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.Permission().Delete(context.Background(), "")
	require.Error(t, err)
}

func TestPermissionDeleteWithIDSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "PERM3D57zwRsVJhImuBMdlYSg88To4W0", req["id"])
		require.Nil(t, req["name"])
	}))
	err := mgmt.Permission().DeleteWithID(context.Background(), "PERM3D57zwRsVJhImuBMdlYSg88To4W0")
	require.NoError(t, err)
}

func TestPermissionDeleteWithIDError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.Permission().DeleteWithID(context.Background(), "")
	require.Error(t, err)
}

func TestPermissionLoadSuccess(t *testing.T) {
	response := map[string]any{
		"permissions": []map[string]any{{
			"id":   "PERM3D57zwRsVJhImuBMdlYSg88To4W0",
			"name": "abc",
		}}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
	}, response))
	res, err := mgmt.Permission().LoadAll(context.Background())
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Len(t, res, 1)
	require.Equal(t, "abc", res[0].Name)
	require.Equal(t, "PERM3D57zwRsVJhImuBMdlYSg88To4W0", res[0].ID)
}

func TestPermissionLoadError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.Permission().LoadAll(context.Background())
	require.Error(t, err)
	require.Nil(t, res)
}
