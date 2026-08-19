package mgmt

import (
	"context"
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/tests/helpers"
	"github.com/stretchr/testify/require"
)

func TestMCPServerCreateSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "my-server", req["name"])
	}, map[string]any{"server": map[string]any{"id": "M1", "name": "my-server"}}))
	res, err := mgmt.MCPServer().Create(context.Background(), &descope.MCPServer{Name: "my-server"})
	require.NoError(t, err)
	require.Equal(t, "M1", res.ID)
	require.Equal(t, "my-server", res.Name)
}

func TestMCPServerCreateError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, err := mgmt.MCPServer().Create(context.Background(), nil)
	require.Error(t, err)
}

func TestMCPServerUpdateSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		server, ok := req["server"].(map[string]any)
		require.True(t, ok)
		require.Equal(t, "M1", server["id"])
	}, map[string]any{"server": map[string]any{"id": "M1", "name": "renamed"}}))
	res, err := mgmt.MCPServer().Update(context.Background(), &descope.MCPServer{ID: "M1", Name: "renamed"})
	require.NoError(t, err)
	require.Equal(t, "renamed", res.Name)
}

func TestMCPServerUpdateError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, err := mgmt.MCPServer().Update(context.Background(), nil)
	require.Error(t, err)
	_, err = mgmt.MCPServer().Update(context.Background(), &descope.MCPServer{Name: "no-id"})
	require.Error(t, err)
}

func TestMCPServerDeleteSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "M1", req["id"])
	}))
	err := mgmt.MCPServer().Delete(context.Background(), "M1")
	require.NoError(t, err)
}

func TestMCPServerDeleteError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.MCPServer().Delete(context.Background(), "")
	require.Error(t, err)
}

func TestMCPServerDeleteBatchSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		ids, ok := req["ids"].([]any)
		require.True(t, ok)
		require.Len(t, ids, 2)
	}))
	err := mgmt.MCPServer().DeleteBatch(context.Background(), []string{"M1", "M2"})
	require.NoError(t, err)
}

func TestMCPServerDeleteBatchError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.MCPServer().DeleteBatch(context.Background(), nil)
	require.Error(t, err)
}

func TestMCPServerLoadSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "M1", req["id"])
	}, map[string]any{"server": map[string]any{"id": "M1", "name": "a"}}))
	res, err := mgmt.MCPServer().Load(context.Background(), "M1")
	require.NoError(t, err)
	require.Equal(t, "M1", res.ID)
}

func TestMCPServerLoadError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, err := mgmt.MCPServer().Load(context.Background(), "")
	require.Error(t, err)
}

func TestMCPServerLoadAllSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
	}, map[string]any{"servers": []map[string]any{
		{"id": "M1", "name": "a"},
		{"id": "M2", "name": "b"},
	}, "total": 2}))
	res, err := mgmt.MCPServer().LoadAll(context.Background())
	require.NoError(t, err)
	require.Len(t, res, 2)
	require.Equal(t, "b", res[1].Name)
}

func TestMCPServerLoadAllError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.MCPServer().LoadAll(context.Background())
	require.Error(t, err)
	require.Nil(t, res)
}

func TestMCPServerCreateClientSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "M1", req["mcpServerId"])
		require.Equal(t, "my-client", req["name"])
	}, map[string]any{"id": "C1", "clientId": "client-123", "cleartext": "secret-xyz"}))
	res, err := mgmt.MCPServer().CreateClient(context.Background(), &descope.MCPServerClientRequest{
		MCPServerID: "M1",
		Name:        "my-client",
	})
	require.NoError(t, err)
	require.Equal(t, "C1", res.ID)
	require.Equal(t, "client-123", res.ClientID)
	require.Equal(t, "secret-xyz", res.Cleartext)
}

func TestMCPServerCreateClientError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, err := mgmt.MCPServer().CreateClient(context.Background(), nil)
	require.Error(t, err)
	_, err = mgmt.MCPServer().CreateClient(context.Background(), &descope.MCPServerClientRequest{Name: "no-server"})
	require.Error(t, err)
}

func TestMCPServerUpdateClientSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "C1", req["id"])
		require.Equal(t, "M1", req["mcpServerId"])
	}, map[string]any{"client": map[string]any{"id": "C1", "name": "renamed"}}))
	res, err := mgmt.MCPServer().UpdateClient(context.Background(), &descope.MCPServerClientRequest{
		ID:          "C1",
		MCPServerID: "M1",
		Name:        "renamed",
	})
	require.NoError(t, err)
	require.Equal(t, "renamed", res.Name)
}

func TestMCPServerUpdateClientError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, err := mgmt.MCPServer().UpdateClient(context.Background(), &descope.MCPServerClientRequest{MCPServerID: "M1"})
	require.Error(t, err)
	_, err = mgmt.MCPServer().UpdateClient(context.Background(), &descope.MCPServerClientRequest{ID: "C1"})
	require.Error(t, err)
}

func TestMCPServerDeleteClientSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "C1", req["id"])
		require.Equal(t, "M1", req["mcpServerId"])
	}))
	err := mgmt.MCPServer().DeleteClient(context.Background(), "M1", "C1")
	require.NoError(t, err)
}

func TestMCPServerDeleteClientError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.MCPServer().DeleteClient(context.Background(), "", "C1")
	require.Error(t, err)
	err = mgmt.MCPServer().DeleteClient(context.Background(), "M1", "")
	require.Error(t, err)
}

func TestMCPServerDeleteClientsSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "M1", req["mcpServerId"])
		ids, ok := req["ids"].([]any)
		require.True(t, ok)
		require.Len(t, ids, 2)
	}))
	err := mgmt.MCPServer().DeleteClients(context.Background(), "M1", []string{"C1", "C2"})
	require.NoError(t, err)
}

func TestMCPServerDeleteClientsError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.MCPServer().DeleteClients(context.Background(), "M1", nil)
	require.Error(t, err)
	err = mgmt.MCPServer().DeleteClients(context.Background(), "", []string{"C1"})
	require.Error(t, err)
}

func TestMCPServerLoadClientSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "M1", req["mcpServerId"])
		require.Equal(t, "C1", req["id"])
	}, map[string]any{"client": map[string]any{"id": "C1", "clientId": "client-123"}}))
	res, err := mgmt.MCPServer().LoadClient(context.Background(), "M1", "C1", "")
	require.NoError(t, err)
	require.Equal(t, "client-123", res.ClientID)
}

func TestMCPServerLoadClientError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, err := mgmt.MCPServer().LoadClient(context.Background(), "", "C1", "")
	require.Error(t, err)
	_, err = mgmt.MCPServer().LoadClient(context.Background(), "M1", "", "")
	require.Error(t, err)
}

func TestMCPServerGetClientSecretSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "C1", req["id"])
		require.Equal(t, "M1", req["mcpServerId"])
	}, map[string]any{"cleartext": "secret-xyz"}))
	secret, err := mgmt.MCPServer().GetClientSecret(context.Background(), "M1", "C1")
	require.NoError(t, err)
	require.Equal(t, "secret-xyz", secret)
}

func TestMCPServerGetClientSecretError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, err := mgmt.MCPServer().GetClientSecret(context.Background(), "M1", "")
	require.Error(t, err)
	_, err = mgmt.MCPServer().GetClientSecret(context.Background(), "", "C1")
	require.Error(t, err)
}

func TestMCPServerRotateClientSecretSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "C1", req["id"])
	}, map[string]any{"cleartext": "new-secret"}))
	secret, err := mgmt.MCPServer().RotateClientSecret(context.Background(), "M1", "C1")
	require.NoError(t, err)
	require.Equal(t, "new-secret", secret)
}

func TestMCPServerRotateClientSecretError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, err := mgmt.MCPServer().RotateClientSecret(context.Background(), "M1", "")
	require.Error(t, err)
}

func TestMCPServerSearchClientsSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "M1", req["mcpServerId"])
	}, map[string]any{"clients": []map[string]any{
		{"id": "C1", "name": "a"},
	}, "total": 1}))
	res, total, err := mgmt.MCPServer().SearchClients(context.Background(), &descope.MCPServerClientSearchOptions{MCPServerID: "M1"})
	require.NoError(t, err)
	require.Len(t, res, 1)
	require.Equal(t, 1, total)
}

func TestMCPServerSearchClientsError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, _, err := mgmt.MCPServer().SearchClients(context.Background(), nil)
	require.Error(t, err)
}
