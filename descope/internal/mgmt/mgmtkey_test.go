package mgmt

import (
	"context"
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/tests/helpers"
	"github.com/stretchr/testify/require"
)

func TestMgmtKeyCreate_Success(t *testing.T) {
	desc := "test key"
	reBac := &descope.MgmtKeyReBac{
		CompanyRoles: []string{"role1"},
	}
	response := map[string]any{
		"cleartext": "cleartext-secret",
		"key": map[string]any{
			"id":           "mk1",
			"name":         "test-key",
			"description":  desc,
			"permittedIps": []string{"10.0.0.1"},
			"status":       "active",
			"createdTime":  1764849768,
			"expireTime":   3600,
			"reBac": map[string]any{
				"companyRoles": []string{"role1"},
				"projectRoles": []string{},
				"tagRoles":     []string{},
			},
			"version":      1,
			"authzVersion": 1,
		}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "test-key", req["name"])
		require.Equal(t, desc, req["description"])
		require.EqualValues(t, 3600, req["expiresIn"])
		permittedIPs := req["permittedIps"].([]any)
		require.Len(t, permittedIPs, 1)
		require.Equal(t, "10.0.0.1", permittedIPs[0])
		reBacMap := req["reBac"].(map[string]any)
		require.NotNil(t, reBacMap)
		companyRoles := reBacMap["companyRoles"].([]any)
		require.Len(t, companyRoles, 1)
		require.Equal(t, "role1", companyRoles[0])
	}, response))
	key, cleartext, err := mgmt.ManagementKey().Create(context.Background(), "test-key", desc, 3600, []string{"10.0.0.1"}, reBac)
	require.NoError(t, err)
	require.Equal(t, "cleartext-secret", cleartext)
	require.Equal(t, "test-key", key.Name)
	require.Equal(t, desc, key.Description)
	require.Len(t, key.PermittedIPs, 1)
	require.Equal(t, "10.0.0.1", key.PermittedIPs[0])
	require.Equal(t, int64(3600), key.ExpireTime)
	require.NotNil(t, key.ReBac)
	require.Len(t, key.ReBac.CompanyRoles, 1)
	require.Equal(t, "role1", key.ReBac.CompanyRoles[0])
}

func TestMgmtKeyUpdate_Success(t *testing.T) {
	desc := "updated key"
	response := map[string]any{
		"key": map[string]any{
			"id":           "mk1",
			"name":         "updated-key",
			"description":  desc,
			"permittedIps": []string{"1.2.3.4"},
			"status":       "inactive",
			"createdTime":  1764673442,
			"expireTime":   0,
			"reBac": map[string]any{
				"companyRoles": []string{},
				"projectRoles": []string{},
				"tagRoles":     []string{},
			},
			"version":      22,
			"authzVersion": 1,
		}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "mk1", req["id"])
		require.Equal(t, "updated-key", req["name"])
		require.Equal(t, desc, req["description"])
		require.EqualValues(t, []any{"1.2.3.4"}, req["permittedIps"])
		require.Equal(t, "inactive", req["status"])
	}, response))
	res, err := mgmt.ManagementKey().Update(context.Background(), "mk1", "updated-key", desc, []string{"1.2.3.4"}, descope.MgmtKeyInactive)
	require.NoError(t, err)
	require.Equal(t, "mk1", res.ID)
	require.Equal(t, "updated-key", res.Name)
	require.Equal(t, desc, res.Description)
	require.Len(t, res.PermittedIPs, 1)
	require.Equal(t, "1.2.3.4", res.PermittedIPs[0])
	require.Equal(t, descope.MgmtKeyInactive, res.Status)
}

func TestMgmtKeyGet_Success(t *testing.T) {
	response := map[string]any{
		"key": map[string]any{
			"id":           "mk1",
			"name":         "test-key",
			"description":  "a key description",
			"status":       "active",
			"createdTime":  1764677065,
			"expireTime":   0,
			"permittedIps": []string{},
			"reBac": map[string]any{
				"companyRoles": []string{},
				"projectRoles": []string{},
				"tagRoles":     []string{},
			},
			"version":      1,
			"authzVersion": 1,
		}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		params := helpers.ReadParams(r)
		require.Equal(t, "mk1", params["id"])
	}, response))
	res, err := mgmt.ManagementKey().Get(context.Background(), "mk1")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "test-key", res.Name)
	require.Equal(t, "a key description", res.Description)
	require.Equal(t, descope.MgmtKeyActive, res.Status)
}

func TestMgmtKeyDelete_Success(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		ids := req["ids"].([]any)
		require.Len(t, ids, 2)
		require.Equal(t, "mk1", ids[0])
		require.Equal(t, "mk2", ids[1])
	}))
	err := mgmt.ManagementKey().Delete(context.Background(), []string{"mk1", "mk2"})
	require.NoError(t, err)
}

func TestMgmtKeySearch_Success(t *testing.T) {
	response := map[string]any{
		"keys": []map[string]any{
			{
				"id":           "mk1",
				"name":         "key1",
				"description":  "",
				"status":       "active",
				"createdTime":  1764677065,
				"expireTime":   0,
				"permittedIps": []string{},
				"reBac": map[string]any{
					"companyRoles": []string{},
					"projectRoles": []string{},
					"tagRoles":     []string{},
				},
				"version":      1,
				"authzVersion": 1,
			},
			{
				"id":           "mk2",
				"name":         "key2",
				"description":  "",
				"status":       "inactive",
				"createdTime":  1764773205,
				"expireTime":   1234,
				"permittedIps": []string{},
				"reBac": map[string]any{
					"companyRoles": []string{},
					"projectRoles": []string{},
					"tagRoles":     []string{},
				},
				"version":      1,
				"authzVersion": 1,
			},
		},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
	}, response))
	res, err := mgmt.ManagementKey().Search(context.Background(), &descope.MgmtKeySearchOptions{})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Len(t, res, 2)
	require.Equal(t, "mk1", res[0].ID)
	require.Equal(t, "key1", res[0].Name)
	require.Equal(t, descope.MgmtKeyActive, res[0].Status)
	require.Equal(t, "mk2", res[1].ID)
	require.Equal(t, "key2", res[1].Name)
	require.Equal(t, descope.MgmtKeyInactive, res[1].Status)
}

func TestMgmtKeyCreate_Error(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, _, err := mgmt.ManagementKey().Create(context.Background(), "", "", 0, nil, nil)
	require.Error(t, err)
}

func TestMgmtKeyUpdate_Error(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, err := mgmt.ManagementKey().Update(context.Background(), "", "name", "desc", nil, descope.MgmtKeyActive)
	require.Error(t, err)
}

func TestMgmtKeyGet_ErrorBadInput(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.ManagementKey().Get(context.Background(), "")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestMgmtKeyGet_Error(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.ManagementKey().Get(context.Background(), "mk1")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestMgmtKeyDelete_Error(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.ManagementKey().Delete(context.Background(), []string{})
	require.Error(t, err)
}

func TestMgmtKeySearch_Error(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.ManagementKey().Search(context.Background(), nil)
	require.Error(t, err)
	require.Nil(t, res)
}
