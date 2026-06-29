package mgmt

import (
	"context"
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/tests/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScopeClaimMappingGetSuccess(t *testing.T) {
	response := map[string]any{"mappings": []map[string]any{
		{"scope": "email", "claims": map[string]any{"email": "{{user.email}}"}, "description": "email scope"},
		{"scope": "profile", "claims": map[string]any{"name": "{{user.name}}"}},
	}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/scopeClaimMapping/get", r.URL.Path)
	}, response))

	mappings, err := mgmt.ScopeClaimMapping().Get(context.Background())
	require.NoError(t, err)
	require.Len(t, mappings, 2)
	assert.Equal(t, "email", mappings[0].Scope)
	assert.Equal(t, "{{user.email}}", mappings[0].Claims["email"])
	assert.Equal(t, "email scope", mappings[0].Description)
	assert.Equal(t, "profile", mappings[1].Scope)
}

func TestScopeClaimMappingGetError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	mappings, err := mgmt.ScopeClaimMapping().Get(context.Background())
	require.Error(t, err)
	require.Nil(t, mappings)
}

func TestScopeClaimMappingSetSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/scopeClaimMapping/set", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		mappings, ok := req["mappings"].([]any)
		require.True(t, ok)
		require.Len(t, mappings, 1)
		entry := mappings[0].(map[string]any)
		assert.Equal(t, "email", entry["scope"])
	}))

	err := mgmt.ScopeClaimMapping().Set(context.Background(), []*descope.ScopeClaimMappingEntry{
		{Scope: "email", Claims: map[string]string{"email": "{{user.email}}"}},
	})
	require.NoError(t, err)
}

func TestScopeClaimMappingSetError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	err := mgmt.ScopeClaimMapping().Set(context.Background(), nil)
	require.Error(t, err)
}

func TestScopeClaimMappingDeleteSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/scopeClaimMapping/delete", r.URL.Path)
	}))
	err := mgmt.ScopeClaimMapping().Delete(context.Background())
	require.NoError(t, err)
}

func TestScopeClaimMappingDeleteError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	err := mgmt.ScopeClaimMapping().Delete(context.Background())
	require.Error(t, err)
}
