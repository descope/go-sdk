package mgmt

import (
	"context"
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/tests/helpers"
	"github.com/stretchr/testify/require"
)

func TestProjectExport(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
	}, map[string]any{"files": map[string]any{"foo": "bar"}}))
	m, err := mgmt.Project().Export(context.Background())
	require.NoError(t, err)
	require.NotNil(t, m)
	require.Equal(t, "bar", m.Files["foo"])
}

func TestProjectImport(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		files, ok := req["files"].(map[string]any)
		require.True(t, ok)
		require.Equal(t, "bar", files["foo"])
	}))
	req := &descope.ImportProjectRequest{Files: map[string]any{"foo": "bar"}}
	err := mgmt.Project().Import(context.Background(), req)
	require.NoError(t, err)
}

func TestValidateProjectImport(t *testing.T) {
	resbody := map[string]any{
		"ok":       false,
		"failures": []any{"foo"},
		"missingSecrets": map[string]any{
			"connectors": []any{map[string]any{"id": "i"}},
		},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		files, ok := req["files"].(map[string]any)
		require.True(t, ok)
		require.Equal(t, "bar", files["foo"])
		secrets, ok := req["inputSecrets"].(map[string]any)
		require.True(t, ok)
		list, ok := secrets["connectors"].([]any)
		require.True(t, ok)
		require.Len(t, list, 1)
		conn, ok := list[0].(map[string]any)
		require.True(t, ok)
		require.Equal(t, "i", conn["id"])
		require.Equal(t, "v", conn["value"])
	}, resbody))
	req := &descope.ImportProjectRequest{
		Files: map[string]any{"foo": "bar"},
		InputSecrets: &descope.ImportProjectSecrets{
			Connectors: []*descope.ImportProjectSecret{{ID: "i", Name: "n", Type: "t", Value: "v"}},
		},
	}
	res, err := mgmt.Project().ValidateImport(context.Background(), req)
	require.NoError(t, err)
	require.False(t, res.Ok)
	require.Len(t, res.Failures, 1)
	require.Equal(t, "foo", res.Failures[0])
	require.NotNil(t, res.MissingSecrets)
	require.Len(t, res.MissingSecrets.Connectors, 1)
	require.Equal(t, "i", res.MissingSecrets.Connectors[0].ID)
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
