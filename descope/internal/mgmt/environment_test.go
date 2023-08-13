package mgmt

import (
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope/tests/helpers"
	"github.com/stretchr/testify/require"
)

func TestEnvironmentExportRaw(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
	}, map[string]any{"files": map[string]any{"foo": "bar"}}))
	m, err := mgmt.Environment().ExportRaw()
	require.NoError(t, err)
	require.NotNil(t, m)
	require.Equal(t, "bar", m["foo"])
}

func TestEnvironmentImportRaw(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		files, ok := req["files"].(map[string]any)
		require.True(t, ok)
		require.Equal(t, "bar", files["foo"])
	}))
	err := mgmt.Environment().ImportRaw(map[string]any{"foo": "bar"})
	require.NoError(t, err)
}
