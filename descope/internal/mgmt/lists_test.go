package mgmt

import (
	"context"
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/tests/helpers"
	"github.com/stretchr/testify/require"
)

func TestListCreateSuccess(t *testing.T) {
	response := map[string]any{
		"list": map[string]any{
			"id":          "list-123",
			"name":        "Test List",
			"description": "Test Description",
			"type":        "ips",
			"data":        []any{"192.168.1.1", "10.0.0.1"},
		},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "Test List", req["name"])
		require.Equal(t, "Test Description", req["description"])
		require.Equal(t, "ips", req["type"])
		data := req["data"].([]any)
		require.Len(t, data, 2)
		require.Equal(t, "192.168.1.1", data[0])
	}, response))

	listReq := &descope.ListRequest{
		Name:        "Test List",
		Description: "Test Description",
		Type:        "ips",
		Data:        []string{"192.168.1.1", "10.0.0.1"},
	}
	list, err := mgmt.List().Create(context.Background(), listReq)
	require.NoError(t, err)
	require.NotNil(t, list)
	require.Equal(t, "list-123", list.ID)
	require.Equal(t, "Test List", list.Name)
	require.Equal(t, "Test Description", list.Description)
	require.Equal(t, "ips", list.Type)
}

func TestListCreateJSONSuccess(t *testing.T) {
	response := map[string]any{
		"list": map[string]any{
			"id":          "list-456",
			"name":        "JSON List",
			"description": "JSON Description",
			"type":        "json",
			"data":        map[string]any{"key": "value"},
		},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "JSON List", req["name"])
		require.Equal(t, "json", req["type"])
		data := req["data"].(map[string]any)
		require.Equal(t, "value", data["key"])
	}, response))

	listReq := &descope.ListRequest{
		Name:        "JSON List",
		Description: "JSON Description",
		Type:        "json",
		Data:        map[string]any{"key": "value"},
	}
	list, err := mgmt.List().Create(context.Background(), listReq)
	require.NoError(t, err)
	require.NotNil(t, list)
	require.Equal(t, "list-456", list.ID)
	require.Equal(t, "JSON List", list.Name)
	require.Equal(t, "json", list.Type)
}

func TestListUpdateSuccess(t *testing.T) {
	response := map[string]any{
		"list": map[string]any{
			"id":          "list-123",
			"name":        "Updated List",
			"description": "Updated Description",
			"type":        "texts",
			"data":        []any{"item1", "item2"},
		},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "list-123", req["id"])
		require.Equal(t, "Updated List", req["name"])
		require.Equal(t, "texts", req["type"])
	}, response))

	listReq := &descope.ListRequest{
		Name:        "Updated List",
		Description: "Updated Description",
		Type:        "texts",
		Data:        []string{"item1", "item2"},
	}
	list, err := mgmt.List().Update(context.Background(), "list-123", listReq)
	require.NoError(t, err)
	require.NotNil(t, list)
	require.Equal(t, "list-123", list.ID)
	require.Equal(t, "Updated List", list.Name)
}

func TestListDeleteSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "list-123", req["id"])
	}, nil))

	err := mgmt.List().Delete(context.Background(), "list-123")
	require.NoError(t, err)
}

func TestListLoadSuccess(t *testing.T) {
	response := map[string]any{
		"list": map[string]any{
			"id":          "list-123",
			"name":        "Test List",
			"description": "Test Description",
			"type":        "ips",
		},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		require.Contains(t, r.URL.Path, "list-123")
	}, response))

	list, err := mgmt.List().Load(context.Background(), "list-123")
	require.NoError(t, err)
	require.NotNil(t, list)
	require.Equal(t, "list-123", list.ID)
	require.Equal(t, "Test List", list.Name)
}

func TestListLoadByNameSuccess(t *testing.T) {
	response := map[string]any{
		"list": map[string]any{
			"id":          "list-456",
			"name":        "Named List",
			"description": "Description",
			"type":        "texts",
		},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		// URL path is decoded by the HTTP library, so we check for the actual decoded name
		require.Contains(t, r.URL.Path, "Named List")
	}, response))

	list, err := mgmt.List().LoadByName(context.Background(), "Named List")
	require.NoError(t, err)
	require.NotNil(t, list)
	require.Equal(t, "list-456", list.ID)
	require.Equal(t, "Named List", list.Name)
}

func TestListLoadAllSuccess(t *testing.T) {
	response := map[string]any{
		"lists": []map[string]any{
			{
				"id":   "list-1",
				"name": "List 1",
				"type": "ips",
			},
			{
				"id":   "list-2",
				"name": "List 2",
				"type": "texts",
			},
		},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
	}, response))

	lists, err := mgmt.List().LoadAll(context.Background())
	require.NoError(t, err)
	require.NotNil(t, lists)
	require.Len(t, lists, 2)
	require.Equal(t, "list-1", lists[0].ID)
	require.Equal(t, "List 1", lists[0].Name)
	require.Equal(t, "list-2", lists[1].ID)
}

func TestListImportSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		lists := req["lists"].([]any)
		require.Len(t, lists, 2)
		firstList := lists[0].(map[string]any)
		require.Equal(t, "list-1", firstList["id"])
		require.Equal(t, "List 1", firstList["name"])
	}, nil))

	lists := []*descope.List{
		{
			ID:   "list-1",
			Name: "List 1",
			Type: "ips",
		},
		{
			ID:   "list-2",
			Name: "List 2",
			Type: "texts",
		},
	}
	err := mgmt.List().Import(context.Background(), lists)
	require.NoError(t, err)
}

func TestListAddIPsSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "list-123", req["id"])
		ips := req["ips"].([]any)
		require.Len(t, ips, 2)
		require.Equal(t, "192.168.1.1", ips[0])
		require.Equal(t, "10.0.0.1", ips[1])
	}, nil))

	err := mgmt.List().AddIPs(context.Background(), "list-123", []string{"192.168.1.1", "10.0.0.1"})
	require.NoError(t, err)
}

func TestListRemoveIPsSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "list-123", req["id"])
		ips := req["ips"].([]any)
		require.Len(t, ips, 1)
		require.Equal(t, "192.168.1.1", ips[0])
	}, nil))

	err := mgmt.List().RemoveIPs(context.Background(), "list-123", []string{"192.168.1.1"})
	require.NoError(t, err)
}

func TestListCheckIPSuccess(t *testing.T) {
	response := map[string]any{
		"exists": true,
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "list-123", req["id"])
		require.Equal(t, "192.168.1.1", req["ip"])
	}, response))

	exists, err := mgmt.List().CheckIP(context.Background(), "list-123", "192.168.1.1")
	require.NoError(t, err)
	require.True(t, exists)
}

func TestListCheckIPNotExists(t *testing.T) {
	response := map[string]any{
		"exists": false,
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
	}, response))

	exists, err := mgmt.List().CheckIP(context.Background(), "list-123", "10.0.0.1")
	require.NoError(t, err)
	require.False(t, exists)
}

func TestListClearSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "list-123", req["id"])
	}, nil))

	err := mgmt.List().Clear(context.Background(), "list-123")
	require.NoError(t, err)
}

func TestListCreateError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	listReq := &descope.ListRequest{
		Name: "Test List",
		Type: "ips",
	}
	list, err := mgmt.List().Create(context.Background(), listReq)
	require.Error(t, err)
	require.Nil(t, list)
}

func TestListUpdateError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	listReq := &descope.ListRequest{
		Name: "Updated List",
		Type: "ips",
	}
	list, err := mgmt.List().Update(context.Background(), "list-123", listReq)
	require.Error(t, err)
	require.Nil(t, list)
}

func TestListDeleteError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	err := mgmt.List().Delete(context.Background(), "list-123")
	require.Error(t, err)
}

func TestListCreateNilRequest(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	list, err := mgmt.List().Create(context.Background(), nil)
	require.Error(t, err)
	require.Nil(t, list)
	require.Contains(t, err.Error(), "request")
}

func TestListUpdateNilRequest(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	list, err := mgmt.List().Update(context.Background(), "list-123", nil)
	require.Error(t, err)
	require.Nil(t, list)
	require.Contains(t, err.Error(), "request")
}

func TestListLoadByNameEmpty(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	list, err := mgmt.List().LoadByName(context.Background(), "")
	require.Error(t, err)
	require.Nil(t, list)
	require.Contains(t, err.Error(), "name")
}

func TestListLoadError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	list, err := mgmt.List().Load(context.Background(), "list-123")
	require.Error(t, err)
	require.Nil(t, list)
}
