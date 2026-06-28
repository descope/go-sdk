package mgmt

import (
	"context"
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope/tests/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEngineCreateSuccess(t *testing.T) {
	// createdTime/version are int64 in the proto, so the management gateway serializes them
	// as JSON strings — the response below uses strings to exercise the ",string" tags.
	response := map[string]any{"engine": map[string]any{
		"id":          "eng1",
		"name":        "my-engine",
		"secret":      "s3cret",
		"projectId":   "p1",
		"createdTime": "1719571200",
		"version":     "1",
	}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/engine/create", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "my-engine", req["name"])
	}, response))

	engine, err := mgmt.Engine().Create(context.Background(), "my-engine")
	require.NoError(t, err)
	require.NotNil(t, engine)
	assert.Equal(t, "eng1", engine.ID)
	assert.Equal(t, "my-engine", engine.Name)
	assert.Equal(t, "s3cret", engine.Secret)
	assert.Equal(t, int64(1719571200), engine.CreatedTime)
	assert.Equal(t, int64(1), engine.Version)
}

func TestEngineCreateMissingName(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) { called = true }))
	_, err := mgmt.Engine().Create(context.Background(), "")
	require.Error(t, err)
	assert.False(t, called)
}

func TestEngineCreateError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	_, err := mgmt.Engine().Create(context.Background(), "my-engine")
	require.Error(t, err)
}

func TestEngineUpdateSuccess(t *testing.T) {
	response := map[string]any{"engine": map[string]any{"id": "eng1", "name": "renamed"}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/engine/update", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "eng1", req["id"])
		assert.Equal(t, "renamed", req["name"])
	}, response))

	engine, err := mgmt.Engine().Update(context.Background(), "eng1", "renamed")
	require.NoError(t, err)
	require.NotNil(t, engine)
	assert.Equal(t, "renamed", engine.Name)
	// Update never returns a secret.
	assert.Empty(t, engine.Secret)
}

func TestEngineUpdateMissingArgs(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, err := mgmt.Engine().Update(context.Background(), "", "renamed")
	require.Error(t, err)
	_, err = mgmt.Engine().Update(context.Background(), "eng1", "")
	require.Error(t, err)
}

func TestEngineDeleteSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/engine/delete", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "eng1", req["id"])
	}))

	require.NoError(t, mgmt.Engine().Delete(context.Background(), "eng1"))
}

func TestEngineDeleteMissingID(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	require.Error(t, mgmt.Engine().Delete(context.Background(), ""))
}

func TestEngineLoadSuccess(t *testing.T) {
	// Load never returns a secret.
	response := map[string]any{"engine": map[string]any{"id": "eng1", "name": "my-engine"}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/engine/load", r.URL.Path)
		assert.Equal(t, "eng1", r.URL.Query().Get("id"))
	}, response))

	engine, err := mgmt.Engine().Load(context.Background(), "eng1")
	require.NoError(t, err)
	require.NotNil(t, engine)
	assert.Equal(t, "eng1", engine.ID)
	assert.Empty(t, engine.Secret)
}

func TestEngineLoadMissingID(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, err := mgmt.Engine().Load(context.Background(), "")
	require.Error(t, err)
}

func TestEngineLoadAllSuccess(t *testing.T) {
	response := map[string]any{"engines": []map[string]any{
		{"id": "eng1", "name": "a"},
		{"id": "eng2", "name": "b"},
	}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/engines/load", r.URL.Path)
	}, response))

	engines, err := mgmt.Engine().LoadAll(context.Background())
	require.NoError(t, err)
	require.Len(t, engines, 2)
	assert.Equal(t, "eng1", engines[0].ID)
	assert.Equal(t, "eng2", engines[1].ID)
}

func TestEngineLoadAllError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	_, err := mgmt.Engine().LoadAll(context.Background())
	require.Error(t, err)
}

func TestEngineRotateSecretSuccess(t *testing.T) {
	response := map[string]any{"secret": "newS3cret"}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/engine/rotate", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "eng1", req["id"])
	}, response))

	secret, err := mgmt.Engine().RotateSecret(context.Background(), "eng1")
	require.NoError(t, err)
	assert.Equal(t, "newS3cret", secret)
}

func TestEngineRotateSecretMissingID(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, err := mgmt.Engine().RotateSecret(context.Background(), "")
	require.Error(t, err)
}

func TestEngineRotateSecretError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	_, err := mgmt.Engine().RotateSecret(context.Background(), "eng1")
	require.Error(t, err)
}
