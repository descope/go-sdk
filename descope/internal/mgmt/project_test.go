package mgmt

import (
	"context"
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope/tests/helpers"
	"github.com/stretchr/testify/require"
)

func TestProjectExportRaw(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
	}, map[string]any{"files": map[string]any{"foo": "bar"}}))
	m, err := mgmt.Project().ExportRaw(context.Background())
	require.NoError(t, err)
	require.NotNil(t, m)
	require.Equal(t, "bar", m["foo"])
}

func TestProjectImportRaw(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		files, ok := req["files"].(map[string]any)
		require.True(t, ok)
		require.Equal(t, "bar", files["foo"])
	}))
	err := mgmt.Project().ImportRaw(context.Background(), map[string]any{"foo": "bar"})
	require.NoError(t, err)
}

func TestProjectUpdateNameSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		name, ok := req["name"].(string)
		require.True(t, ok)
		require.Equal(t, "foo", name)
	}))
	err := mgmt.Project().UpdateName(context.Background(), "foo")
	require.NoError(t, err)
}

func TestProjectUpdateNameError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	err := mgmt.Project().UpdateName(context.Background(), "foo")
	require.Error(t, err)
}

func TestProjectCloneSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		name, ok := req["name"].(string)
		require.True(t, ok)
		require.Equal(t, "foo", name)
		tag, ok := req["tag"].(string)
		require.True(t, ok)
		require.Equal(t, "production", tag)
	}, map[string]any{"projectId": "id1", "projectName": "foo"}))
	res, err := mgmt.Project().Clone(context.Background(), "foo", "production")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "foo", res.ProjectName)
	require.Equal(t, "id1", res.ProjectID)

}

func TestProjectCloneError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	_, err := mgmt.Project().Clone(context.Background(), "foo", "")
	require.Error(t, err)
}

func TestProjectDeleteSuccess(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
	}))
	err := m.Project().Delete(context.Background())
	require.NoError(t, err)
}

func TestProjectDeleteError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	err := mgmt.Project().Delete(context.Background())
	require.Error(t, err)
}
