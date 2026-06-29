package mgmt

import (
	"context"
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/tests/helpers"
	"github.com/stretchr/testify/require"
)

func TestJWTTemplateCreateSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		tmpl, ok := req["template"].(map[string]any)
		require.True(t, ok)
		require.Equal(t, "my-template", tmpl["name"])
	}, map[string]any{"template": map[string]any{"id": "T1", "name": "my-template"}}))
	res, err := mgmt.JWTTemplate().Create(context.Background(), &descope.JWTTemplate{Name: "my-template"})
	require.NoError(t, err)
	require.Equal(t, "T1", res.ID)
	require.Equal(t, "my-template", res.Name)
}

func TestJWTTemplateCreateError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, err := mgmt.JWTTemplate().Create(context.Background(), nil)
	require.Error(t, err)
}

func TestJWTTemplateUpdateSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		tmpl, ok := req["template"].(map[string]any)
		require.True(t, ok)
		require.Equal(t, "T1", tmpl["id"])
	}, map[string]any{"template": map[string]any{"id": "T1", "name": "updated"}}))
	res, err := mgmt.JWTTemplate().Update(context.Background(), &descope.JWTTemplate{ID: "T1", Name: "updated"})
	require.NoError(t, err)
	require.Equal(t, "updated", res.Name)
}

func TestJWTTemplateUpdateError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, err := mgmt.JWTTemplate().Update(context.Background(), nil)
	require.Error(t, err)
	_, err = mgmt.JWTTemplate().Update(context.Background(), &descope.JWTTemplate{Name: "no-id"})
	require.Error(t, err)
}

func TestJWTTemplateDeleteSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "T1", req["id"])
	}))
	err := mgmt.JWTTemplate().Delete(context.Background(), "T1")
	require.NoError(t, err)
}

func TestJWTTemplateDeleteError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.JWTTemplate().Delete(context.Background(), "")
	require.Error(t, err)
}

func TestJWTTemplateListSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
	}, map[string]any{"templates": []map[string]any{
		{"id": "T1", "name": "a"},
		{"id": "T2", "name": "b"},
	}}))
	res, err := mgmt.JWTTemplate().List(context.Background())
	require.NoError(t, err)
	require.Len(t, res, 2)
	require.Equal(t, "a", res[0].Name)
}

func TestJWTTemplateListError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.JWTTemplate().List(context.Background())
	require.Error(t, err)
	require.Nil(t, res)
}

func TestJWTTemplateLoadSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "T1", req["id"])
	}, map[string]any{"template": map[string]any{"id": "T1", "name": "a"}}))
	res, err := mgmt.JWTTemplate().Load(context.Background(), "T1")
	require.NoError(t, err)
	require.Equal(t, "T1", res.ID)
}

func TestJWTTemplateLoadError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, err := mgmt.JWTTemplate().Load(context.Background(), "")
	require.Error(t, err)
}

func TestJWTTemplateValidateSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "T1", req["id"])
	}, map[string]any{"valid": false, "issues": []map[string]any{
		{"field": "name", "code": "required", "message": "name is required"},
	}}))
	res, err := mgmt.JWTTemplate().Validate(context.Background(), "T1", nil)
	require.NoError(t, err)
	require.False(t, res.Valid)
	require.Len(t, res.Issues, 1)
	require.Equal(t, "required", res.Issues[0].Code)
}

func TestJWTTemplateValidateError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, err := mgmt.JWTTemplate().Validate(context.Background(), "", nil)
	require.Error(t, err)
}

func TestJWTTemplateListLibrarySuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
	}, map[string]any{"entries": []map[string]any{
		{"id": "L1", "name": "starter", "experimental": true},
	}}))
	res, err := mgmt.JWTTemplate().ListLibrary(context.Background())
	require.NoError(t, err)
	require.Len(t, res, 1)
	require.Equal(t, "starter", res[0].Name)
	require.True(t, res[0].Experimental)
}

func TestJWTTemplateLoadLibraryEntrySuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "L1", req["id"])
	}, map[string]any{"entry": map[string]any{"id": "L1", "name": "starter"}}))
	res, err := mgmt.JWTTemplate().LoadLibraryEntry(context.Background(), "L1")
	require.NoError(t, err)
	require.Equal(t, "L1", res.ID)
}

func TestJWTTemplateLoadLibraryEntryError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, err := mgmt.JWTTemplate().LoadLibraryEntry(context.Background(), "")
	require.Error(t, err)
}

func TestJWTTemplateApplyFromLibrarySuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "L1", req["libraryEntryId"])
		require.Equal(t, "renamed", req["nameOverride"])
	}, map[string]any{"template": map[string]any{"id": "T9", "name": "renamed"}}))
	res, err := mgmt.JWTTemplate().ApplyFromLibrary(context.Background(), &descope.ApplyJWTTemplateFromLibraryRequest{
		LibraryEntryID: "L1",
		NameOverride:   "renamed",
	})
	require.NoError(t, err)
	require.Equal(t, "T9", res.ID)
}

func TestJWTTemplateApplyFromLibraryError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, err := mgmt.JWTTemplate().ApplyFromLibrary(context.Background(), nil)
	require.Error(t, err)
	_, err = mgmt.JWTTemplate().ApplyFromLibrary(context.Background(), &descope.ApplyJWTTemplateFromLibraryRequest{})
	require.Error(t, err)
}
