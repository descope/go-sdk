package mgmt

import (
	"context"
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/tests/helpers"
	"github.com/stretchr/testify/require"
)

func scimAccessKeyResponseBody() map[string]any {
	return map[string]any{
		"cleartext": "P2abc:secret",
		"scimUrl":   "https://api.descope.com/scim/v2/P2abc",
		"key": map[string]any{
			"id":           "k1",
			"name":         "scim-key",
			"roleNames":    []string{"SCIM Admin"},
			"keyTenants":   []map[string]any{{"tenantId": "t1", "tenantName": "Tenant", "roleNames": []string{"r1"}}},
			"status":       "active",
			"createdTime":  1764849768,
			"expireTime":   1864849768,
			"createdBy":    "admin",
			"clientId":     "c1",
			"boundUserId":  "u1",
			"customClaims": map[string]any{"ssoId": "s1"},
			"editable":     true,
			"description":  "desc",
			"permittedIps": []string{"10.0.0.1"},
			"customAttributes": map[string]any{
				"attr": "val",
			},
		},
		"revokedKeyIds": []string{"k0"},
	}
}

func requireSCIMAccessKeyResponse(t *testing.T, res *descope.SCIMAccessKeyResponse) {
	require.NotNil(t, res)
	require.Equal(t, "P2abc:secret", res.Cleartext)
	require.Equal(t, "https://api.descope.com/scim/v2/P2abc", res.SCIMURL)
	require.Equal(t, []string{"k0"}, res.RevokedKeyIDs)
	requireSCIMKey(t, res.Key)
}

func requireSCIMKey(t *testing.T, key *descope.AccessKeyResponse) {
	require.NotNil(t, key)
	require.Equal(t, "k1", key.ID)
	require.Equal(t, "scim-key", key.Name)
	require.Equal(t, []string{"SCIM Admin"}, key.RoleNames)
	require.Len(t, key.KeyTenants, 1)
	require.Equal(t, "t1", key.KeyTenants[0].TenantID)
	require.Equal(t, "Tenant", key.KeyTenants[0].TenantName)
	require.Equal(t, []string{"r1"}, key.KeyTenants[0].Roles)
	require.Equal(t, "active", key.Status)
	require.EqualValues(t, 1764849768, key.CreatedTime)
	require.EqualValues(t, 1864849768, key.ExpireTime)
	require.Equal(t, "admin", key.CreatedBy)
	require.Equal(t, "c1", key.ClientID)
	require.Equal(t, "u1", key.UserID)
	require.Equal(t, "s1", key.CustomClaims["ssoId"])
	require.True(t, key.Editable)
	require.Equal(t, "desc", key.Description)
	require.Equal(t, []string{"10.0.0.1"}, key.PermittedIPs)
	require.Equal(t, "val", key.CustomAttributes["attr"])
}

func TestSCIMCreateAccessKeySuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/scim/key/create", r.URL.Path)
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, map[string]any{
			"tenantId":    "t1",
			"ssoId":       "s1",
			"name":        "scim-key",
			"description": "desc",
			"expireTime":  "1864849768",
		}, req)
	}, scimAccessKeyResponseBody()))
	res, err := mgmt.SCIM().CreateAccessKey(context.Background(), &descope.CreateSCIMAccessKeyRequest{
		TenantID:    "t1",
		SSOID:       "s1",
		Name:        "scim-key",
		Description: "desc",
		ExpireTime:  1864849768,
	})
	require.NoError(t, err)
	requireSCIMAccessKeyResponse(t, res)
}

func TestSCIMCreateAccessKeyOmitsUnsetFields(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, map[string]any{"tenantId": "t1"}, req)
	}, map[string]any{}))
	res, err := mgmt.SCIM().CreateAccessKey(context.Background(), &descope.CreateSCIMAccessKeyRequest{TenantID: "t1"})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Nil(t, res.Key)
}

func TestSCIMCreateAccessKeyBadInput(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		require.Fail(t, "request should not be sent")
	}))
	_, err := mgmt.SCIM().CreateAccessKey(context.Background(), nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	_, err = mgmt.SCIM().CreateAccessKey(context.Background(), &descope.CreateSCIMAccessKeyRequest{})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
}

func TestSCIMCreateAccessKeyError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.SCIM().CreateAccessKey(context.Background(), &descope.CreateSCIMAccessKeyRequest{TenantID: "t1"})
	require.Error(t, err)
	require.Nil(t, res)

	mgmt = newTestMgmt(nil, helpers.DoOkWithBody(nil, "invalid"))
	res, err = mgmt.SCIM().CreateAccessKey(context.Background(), &descope.CreateSCIMAccessKeyRequest{TenantID: "t1"})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestSCIMRotateAccessKeySuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/scim/key/rotate", r.URL.Path)
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, map[string]any{
			"tenantId":    "t1",
			"ssoId":       "s1",
			"name":        "scim-key",
			"description": "desc",
			"expireTime":  "1864849768",
			"revokeMode":  "SCIM_KEY_REVOKE_MODE_DEACTIVATE",
		}, req)
	}, scimAccessKeyResponseBody()))
	res, err := mgmt.SCIM().RotateAccessKey(context.Background(), &descope.RotateSCIMAccessKeyRequest{
		TenantID:    "t1",
		SSOID:       "s1",
		Name:        "scim-key",
		Description: "desc",
		ExpireTime:  1864849768,
		RevokeMode:  descope.SCIMKeyRevokeModeDeactivate,
	})
	require.NoError(t, err)
	requireSCIMAccessKeyResponse(t, res)
}

func TestSCIMRotateAccessKeyBadInput(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		require.Fail(t, "request should not be sent")
	}))
	_, err := mgmt.SCIM().RotateAccessKey(context.Background(), nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	_, err = mgmt.SCIM().RotateAccessKey(context.Background(), &descope.RotateSCIMAccessKeyRequest{})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
}

func TestSCIMRotateAccessKeyError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.SCIM().RotateAccessKey(context.Background(), &descope.RotateSCIMAccessKeyRequest{TenantID: "t1"})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestSCIMRevokeAccessKeysSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/scim/key/revoke", r.URL.Path)
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, map[string]any{
			"tenantId":   "t1",
			"ssoId":      "s1",
			"revokeMode": "SCIM_KEY_REVOKE_MODE_DELETE",
		}, req)
	}, map[string]any{"revokedKeyIds": []string{"k1", "k2"}}))
	ids, err := mgmt.SCIM().RevokeAccessKeys(context.Background(), &descope.RevokeSCIMAccessKeysRequest{
		TenantID:   "t1",
		SSOID:      "s1",
		RevokeMode: descope.SCIMKeyRevokeModeDelete,
	})
	require.NoError(t, err)
	require.Equal(t, []string{"k1", "k2"}, ids)
}

func TestSCIMRevokeAccessKeysBadInput(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		require.Fail(t, "request should not be sent")
	}))
	_, err := mgmt.SCIM().RevokeAccessKeys(context.Background(), nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	_, err = mgmt.SCIM().RevokeAccessKeys(context.Background(), &descope.RevokeSCIMAccessKeysRequest{})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
}

func TestSCIMRevokeAccessKeysError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	ids, err := mgmt.SCIM().RevokeAccessKeys(context.Background(), &descope.RevokeSCIMAccessKeysRequest{TenantID: "t1"})
	require.Error(t, err)
	require.Nil(t, ids)

	mgmt = newTestMgmt(nil, helpers.DoOkWithBody(nil, "invalid"))
	ids, err = mgmt.SCIM().RevokeAccessKeys(context.Background(), &descope.RevokeSCIMAccessKeysRequest{TenantID: "t1"})
	require.Error(t, err)
	require.Nil(t, ids)
}

func TestSCIMActivateAccessKeysSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/scim/key/activate", r.URL.Path)
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, map[string]any{
			"tenantId": "t1",
			"ssoId":    "s1",
			"keyIds":   []any{"k1", "k2"},
		}, req)
	}, map[string]any{"activatedKeyIds": []string{"k1", "k2"}}))
	ids, err := mgmt.SCIM().ActivateAccessKeys(context.Background(), &descope.ActivateSCIMAccessKeysRequest{
		TenantID: "t1",
		SSOID:    "s1",
		KeyIDs:   []string{"k1", "k2"},
	})
	require.NoError(t, err)
	require.Equal(t, []string{"k1", "k2"}, ids)
}

func TestSCIMActivateAccessKeysBadInput(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		require.Fail(t, "request should not be sent")
	}))
	_, err := mgmt.SCIM().ActivateAccessKeys(context.Background(), nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	_, err = mgmt.SCIM().ActivateAccessKeys(context.Background(), &descope.ActivateSCIMAccessKeysRequest{KeyIDs: []string{"k1"}})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	_, err = mgmt.SCIM().ActivateAccessKeys(context.Background(), &descope.ActivateSCIMAccessKeysRequest{TenantID: "t1"})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	_, err = mgmt.SCIM().ActivateAccessKeys(context.Background(), &descope.ActivateSCIMAccessKeysRequest{TenantID: "t1", KeyIDs: []string{"k1", ""}})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
}

func TestSCIMActivateAccessKeysError(t *testing.T) {
	req := &descope.ActivateSCIMAccessKeysRequest{TenantID: "t1", KeyIDs: []string{"k1"}}
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	ids, err := mgmt.SCIM().ActivateAccessKeys(context.Background(), req)
	require.Error(t, err)
	require.Nil(t, ids)

	mgmt = newTestMgmt(nil, helpers.DoOkWithBody(nil, "invalid"))
	ids, err = mgmt.SCIM().ActivateAccessKeys(context.Background(), req)
	require.Error(t, err)
	require.Nil(t, ids)
}

func TestSCIMLoadAccessKeysSuccess(t *testing.T) {
	body := map[string]any{"keys": []map[string]any{{"key": scimAccessKeyResponseBody()["key"], "ssoId": "s1"}}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/v1/mgmt/scim/key", r.URL.Path)
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, map[string]string{"tenantId": "t1", "ssoId": "s1"}, helpers.ReadParams(r))
	}, body))
	keys, err := mgmt.SCIM().LoadAccessKeys(context.Background(), "t1", "s1")
	require.NoError(t, err)
	require.Len(t, keys, 1)
	require.Equal(t, "s1", keys[0].SSOID)
	requireSCIMKey(t, keys[0].Key)
}

func TestSCIMLoadAccessKeysWithoutSSOID(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, map[string]string{"tenantId": "t1"}, helpers.ReadParams(r))
	}, map[string]any{"keys": []any{}}))
	keys, err := mgmt.SCIM().LoadAccessKeys(context.Background(), "t1", "")
	require.NoError(t, err)
	require.Empty(t, keys)
}

func TestSCIMLoadAccessKeysBadInput(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		require.Fail(t, "request should not be sent")
	}))
	_, err := mgmt.SCIM().LoadAccessKeys(context.Background(), "", "s1")
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
}

func TestSCIMLoadAccessKeysError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	keys, err := mgmt.SCIM().LoadAccessKeys(context.Background(), "t1", "")
	require.Error(t, err)
	require.Nil(t, keys)

	mgmt = newTestMgmt(nil, helpers.DoOkWithBody(nil, "invalid"))
	keys, err = mgmt.SCIM().LoadAccessKeys(context.Background(), "t1", "")
	require.Error(t, err)
	require.Nil(t, keys)
}
