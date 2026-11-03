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

var scimAccessKeyResponseBody = map[string]any{
	"cleartext": "a:cleartext",
	"key": map[string]any{
		"id":           "key1",
		"name":         "scim-key",
		"roleNames":    []string{"Tenant Admin"},
		"keyTenants":   []map[string]any{{"tenantId": "t1", "tenantName": "tenant", "roleNames": []string{"SCIM"}}},
		"status":       "active",
		"createdTime":  10,
		"expireTime":   20,
		"createdBy":    "creator",
		"clientId":     "client",
		"boundUserId":  "user",
		"customClaims": map[string]any{"c": "v"},
		"editable":     true,
		"description":  "desc",
		"permittedIps": []string{"1.1.1.1"},
		"customAttributes": map[string]any{
			"a": "b",
		},
	},
	"scimUrl":       "https://api.descope.com/scim/v2",
	"revokedKeyIds": []string{"old1"},
}

func assertSCIMAccessKeyResponse(t *testing.T, res *descope.SCIMAccessKeyResponse) {
	require.NotNil(t, res)
	assert.Equal(t, "a:cleartext", res.Cleartext)
	assert.Equal(t, "https://api.descope.com/scim/v2", res.SCIMURL)
	assert.Equal(t, []string{"old1"}, res.RevokedKeyIDs)
	require.NotNil(t, res.Key)
	assert.Equal(t, "key1", res.Key.ID)
	assert.Equal(t, "scim-key", res.Key.Name)
	assert.Equal(t, []string{"Tenant Admin"}, res.Key.RoleNames)
	require.Len(t, res.Key.KeyTenants, 1)
	assert.Equal(t, "t1", res.Key.KeyTenants[0].TenantID)
	assert.Equal(t, "tenant", res.Key.KeyTenants[0].TenantName)
	assert.Equal(t, []string{"SCIM"}, res.Key.KeyTenants[0].Roles)
	assert.Equal(t, "active", res.Key.Status)
	assert.EqualValues(t, 10, res.Key.CreatedTime)
	assert.EqualValues(t, 20, res.Key.ExpireTime)
	assert.Equal(t, "creator", res.Key.CreatedBy)
	assert.Equal(t, "client", res.Key.ClientID)
	assert.Equal(t, "user", res.Key.UserID)
	assert.Equal(t, "v", res.Key.CustomClaims["c"])
	assert.True(t, res.Key.Editable)
	assert.Equal(t, "desc", res.Key.Description)
	assert.Equal(t, []string{"1.1.1.1"}, res.Key.PermittedIPs)
	assert.Equal(t, "b", res.Key.CustomAttributes["a"])
}

func TestSCIMCreateAccessKeySuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/v1/mgmt/scim/key/create", r.URL.Path)
		assert.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, map[string]any{
			"tenantId":    "t1",
			"ssoId":       "sso1",
			"name":        "scim-key",
			"description": "desc",
			"expireTime":  "1700000000",
		}, req)
	}, scimAccessKeyResponseBody))
	res, err := mgmt.SCIM().CreateAccessKey(context.Background(), &descope.SCIMAccessKeyCreateRequest{
		TenantID:    "t1",
		SSOID:       "sso1",
		Name:        "scim-key",
		Description: "desc",
		ExpireTime:  1700000000,
	})
	require.NoError(t, err)
	assertSCIMAccessKeyResponse(t, res)
}

func TestSCIMCreateAccessKeyOmitsUnsetFields(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, map[string]any{"tenantId": "t1"}, req)
	}, map[string]any{}))
	res, err := mgmt.SCIM().CreateAccessKey(context.Background(), &descope.SCIMAccessKeyCreateRequest{TenantID: "t1"})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Nil(t, res.Key)
}

func TestSCIMCreateAccessKeyMissingArguments(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		assert.Fail(t, "request should not be sent")
	}))
	res, err := mgmt.SCIM().CreateAccessKey(context.Background(), nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	require.Nil(t, res)
	res, err = mgmt.SCIM().CreateAccessKey(context.Background(), &descope.SCIMAccessKeyCreateRequest{})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	require.Contains(t, err.Error(), "tenantID")
	require.Nil(t, res)
}

func TestSCIMCreateAccessKeyError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.SCIM().CreateAccessKey(context.Background(), &descope.SCIMAccessKeyCreateRequest{TenantID: "t1"})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestSCIMCreateAccessKeyBadResponse(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(nil, []string{"x"}))
	res, err := mgmt.SCIM().CreateAccessKey(context.Background(), &descope.SCIMAccessKeyCreateRequest{TenantID: "t1"})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestSCIMRotateAccessKeySuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/v1/mgmt/scim/key/rotate", r.URL.Path)
		assert.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, map[string]any{
			"tenantId":    "t1",
			"ssoId":       "sso1",
			"name":        "scim-key",
			"description": "desc",
			"expireTime":  "1700000000",
			"revokeMode":  "SCIM_KEY_REVOKE_MODE_DEACTIVATE",
		}, req)
	}, scimAccessKeyResponseBody))
	res, err := mgmt.SCIM().RotateAccessKey(context.Background(), &descope.SCIMAccessKeyRotateRequest{
		TenantID:    "t1",
		SSOID:       "sso1",
		Name:        "scim-key",
		Description: "desc",
		ExpireTime:  1700000000,
		RevokeMode:  descope.SCIMKeyRevokeModeDeactivate,
	})
	require.NoError(t, err)
	assertSCIMAccessKeyResponse(t, res)
}

func TestSCIMRotateAccessKeyMissingArguments(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		assert.Fail(t, "request should not be sent")
	}))
	res, err := mgmt.SCIM().RotateAccessKey(context.Background(), nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	require.Nil(t, res)
	res, err = mgmt.SCIM().RotateAccessKey(context.Background(), &descope.SCIMAccessKeyRotateRequest{})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	require.Contains(t, err.Error(), "tenantID")
	require.Nil(t, res)
}

func TestSCIMRotateAccessKeyError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.SCIM().RotateAccessKey(context.Background(), &descope.SCIMAccessKeyRotateRequest{TenantID: "t1"})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestSCIMRevokeAccessKeysSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/v1/mgmt/scim/key/revoke", r.URL.Path)
		assert.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, map[string]any{
			"tenantId":   "t1",
			"ssoId":      "sso1",
			"revokeMode": "SCIM_KEY_REVOKE_MODE_DELETE",
		}, req)
	}, map[string]any{"revokedKeyIds": []string{"k1", "k2"}}))
	ids, err := mgmt.SCIM().RevokeAccessKeys(context.Background(), "t1", "sso1", descope.SCIMKeyRevokeModeDelete)
	require.NoError(t, err)
	assert.Equal(t, []string{"k1", "k2"}, ids)
}

func TestSCIMRevokeAccessKeysOmitsUnsetFields(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, map[string]any{"tenantId": "t1"}, req)
	}, map[string]any{"revokedKeyIds": []string{}}))
	ids, err := mgmt.SCIM().RevokeAccessKeys(context.Background(), "t1", "", "")
	require.NoError(t, err)
	assert.Empty(t, ids)
}

func TestSCIMRevokeAccessKeysMissingArguments(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		assert.Fail(t, "request should not be sent")
	}))
	ids, err := mgmt.SCIM().RevokeAccessKeys(context.Background(), "", "sso1", "")
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	require.Contains(t, err.Error(), "tenantID")
	require.Nil(t, ids)
}

func TestSCIMRevokeAccessKeysError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	ids, err := mgmt.SCIM().RevokeAccessKeys(context.Background(), "t1", "", "")
	require.Error(t, err)
	require.Nil(t, ids)
}

func TestSCIMRevokeAccessKeysBadResponse(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(nil, []string{"x"}))
	ids, err := mgmt.SCIM().RevokeAccessKeys(context.Background(), "t1", "", "")
	require.Error(t, err)
	require.Nil(t, ids)
}

func TestSCIMActivateAccessKeysSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/v1/mgmt/scim/key/activate", r.URL.Path)
		assert.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, map[string]any{
			"tenantId": "t1",
			"ssoId":    "sso1",
			"keyIds":   []any{"k1", "k2"},
		}, req)
	}, map[string]any{"activatedKeyIds": []string{"k1", "k2"}}))
	ids, err := mgmt.SCIM().ActivateAccessKeys(context.Background(), "t1", "sso1", []string{"k1", "k2"})
	require.NoError(t, err)
	assert.Equal(t, []string{"k1", "k2"}, ids)
}

func TestSCIMActivateAccessKeysOmitsUnsetFields(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, map[string]any{"tenantId": "t1", "keyIds": []any{"k1"}}, req)
	}, map[string]any{}))
	ids, err := mgmt.SCIM().ActivateAccessKeys(context.Background(), "t1", "", []string{"k1"})
	require.NoError(t, err)
	assert.Empty(t, ids)
}

func TestSCIMActivateAccessKeysMissingArguments(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		assert.Fail(t, "request should not be sent")
	}))
	ids, err := mgmt.SCIM().ActivateAccessKeys(context.Background(), "", "", []string{"k1"})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	require.Contains(t, err.Error(), "tenantID")
	require.Nil(t, ids)
	ids, err = mgmt.SCIM().ActivateAccessKeys(context.Background(), "t1", "", nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	require.Contains(t, err.Error(), "keyIDs")
	require.Nil(t, ids)
	ids, err = mgmt.SCIM().ActivateAccessKeys(context.Background(), "t1", "", []string{"k1", ""})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	require.Contains(t, err.Error(), "keyIDs")
	require.Nil(t, ids)
}

func TestSCIMActivateAccessKeysError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	ids, err := mgmt.SCIM().ActivateAccessKeys(context.Background(), "t1", "", []string{"k1"})
	require.Error(t, err)
	require.Nil(t, ids)
}

func TestSCIMActivateAccessKeysBadResponse(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(nil, []string{"x"}))
	ids, err := mgmt.SCIM().ActivateAccessKeys(context.Background(), "t1", "", []string{"k1"})
	require.Error(t, err)
	require.Nil(t, ids)
}

func TestSCIMLoadAccessKeysSuccess(t *testing.T) {
	response := map[string]any{"keys": []map[string]any{
		{"key": scimAccessKeyResponseBody["key"], "ssoId": "sso1"},
	}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/v1/mgmt/scim/key", r.URL.Path)
		assert.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		assert.Equal(t, map[string]string{"tenantId": "t1", "ssoId": "sso1"}, helpers.ReadParams(r))
	}, response))
	keys, err := mgmt.SCIM().LoadAccessKeys(context.Background(), "t1", "sso1")
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, "sso1", keys[0].SSOID)
	assertSCIMAccessKeyResponse(t, &descope.SCIMAccessKeyResponse{
		Cleartext:     "a:cleartext",
		Key:           keys[0].Key,
		SCIMURL:       "https://api.descope.com/scim/v2",
		RevokedKeyIDs: []string{"old1"},
	})
}

func TestSCIMLoadAccessKeysOmitsUnsetParams(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Empty(t, helpers.ReadParams(r))
	}, map[string]any{"keys": []any{}}))
	keys, err := mgmt.SCIM().LoadAccessKeys(context.Background(), "", "")
	require.NoError(t, err)
	assert.Empty(t, keys)
}

func TestSCIMLoadAccessKeysError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	keys, err := mgmt.SCIM().LoadAccessKeys(context.Background(), "t1", "")
	require.Error(t, err)
	require.Nil(t, keys)
}

func TestSCIMLoadAccessKeysBadResponse(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(nil, []string{"x"}))
	keys, err := mgmt.SCIM().LoadAccessKeys(context.Background(), "t1", "")
	require.Error(t, err)
	require.Nil(t, keys)
}
