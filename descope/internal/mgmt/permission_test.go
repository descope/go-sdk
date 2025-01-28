package mgmt

import (
	"context"
	"net/http"
	"testing"

	"github.com/descope/go-sdk/v2/descope/tests/helpers"
	"github.com/stretchr/testify/require"
)

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

func TestPermissionLoadSuccess(t *testing.T) {
	response := map[string]any{
		"permissions": []map[string]any{{
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
}

func TestPermissionLoadError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.Permission().LoadAll(context.Background())
	require.Error(t, err)
	require.Nil(t, res)
}
