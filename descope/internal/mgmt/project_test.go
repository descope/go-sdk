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
		require.EqualValues(t, "split", req["format"])
	}, map[string]any{"files": map[string]any{"foo": "bar"}}))
	m, err := mgmt.Project().ExportSnapshot(context.Background(), &descope.ExportSnapshotRequest{Format: "split"})
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
	req := &descope.ImportSnapshotRequest{Files: map[string]any{"foo": "bar"}}
	err := mgmt.Project().ImportSnapshot(context.Background(), req)
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

		outboundApps, ok := secrets["outboundApps"].([]any)
		require.True(t, ok)
		require.Len(t, outboundApps, 1)
		app, ok := outboundApps[0].(map[string]any)
		require.True(t, ok)
		require.Equal(t, "outbnd1", app["id"])
		require.Equal(t, "v", app["value"])
		require.Equal(t, "clientSecret", app["type"])
	}, resbody))
	req := &descope.ValidateSnapshotRequest{
		Files: map[string]any{"foo": "bar"},
		InputSecrets: &descope.SnapshotSecrets{
			Connectors:   []*descope.SnapshotSecret{{ID: "i", Name: "n", Type: "t", Value: "v"}},
			OutboundApps: []*descope.SnapshotSecret{{ID: "outbnd1", Name: "n", Type: "clientSecret", Value: "v"}},
		},
	}
	res, err := mgmt.Project().ValidateSnapshot(context.Background(), req)
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

func TestProjectSetTagsSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		tags, ok := req["tags"]
		require.True(t, ok)
		require.Equal(t, []any{"foo"}, tags)
	}))
	err := mgmt.Project().UpdateTags(context.Background(), []string{"foo"})
	require.NoError(t, err)
}

func TestProjectSetTagsError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	err := mgmt.Project().UpdateTags(context.Background(), []string{"foo"})
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
		env, ok := req["environment"].(string)
		require.True(t, ok)
		require.Equal(t, "production", env)
		tags, ok := req["tags"]
		require.True(t, ok)
		require.Equal(t, []any{"tag1", "tag2!"}, tags)
	}, map[string]any{"projectId": "id1", "projectName": "foo"}))
	res, err := mgmt.Project().Clone(context.Background(), "foo", "production", []string{"tag1", "tag2!"})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "foo", res.ProjectName)
	require.Equal(t, "id1", res.ProjectID)
}

func TestProjectCloneError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	_, err := mgmt.Project().Clone(context.Background(), "foo", "", nil)
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

func TestProjectListSuccess(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
	}, map[string]any{"projects": []any{map[string]any{"id": "i", "name": "n", "environment": "t", "tags": []string{"tag1", "t!"}}}}))
	res, err := m.Project().ListProjects(context.Background())
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Len(t, res, 1)
	require.Equal(t, "i", res[0].ID)
	require.Equal(t, "n", res[0].Name)
	require.Equal(t, "t", res[0].Environment)
	require.Equal(t, []string{"tag1", "t!"}, res[0].Tags)
}

func TestProjectListError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.Project().ListProjects(context.Background())
	require.Error(t, err)
	require.Nil(t, res)
}
