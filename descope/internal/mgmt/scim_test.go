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

var scimAccessKeyJSON = map[string]any{
	"id":               "K1",
	"name":             "scim-key",
	"roleNames":        []string{"SCIM"},
	"keyTenants":       []map[string]any{{"tenantId": "T1", "tenantName": "Tenant", "roleNames": []string{"SCIM"}}},
	"status":           "active",
	"createdTime":      1700000000,
	"expireTime":       1800000000,
	"createdBy":        "admin",
	"clientId":         "client1",
	"boundUserId":      "U1",
	"customClaims":     map[string]any{"k1": "v1"},
	"editable":         false,
	"description":      "desc",
	"permittedIps":     []string{"10.0.0.1"},
	"customAttributes": map[string]any{"attr": "val"},
}

var scimAccessKeyResponse = map[string]any{
	"cleartext":     "secret",
	"key":           scimAccessKeyJSON,
	"scimUrl":       "https://api.descope.com/scim/v2",
	"revokedKeyIds": []string{"K0"},
}

func assertSCIMAccessKey(t *testing.T, key *descope.AccessKeyResponse) {
	require.NotNil(t, key)
	assert.Equal(t, "K1", key.ID)
	assert.Equal(t, "scim-key", key.Name)
	assert.Equal(t, []string{"SCIM"}, key.RoleNames)
	require.Len(t, key.KeyTenants, 1)
	assert.Equal(t, "T1", key.KeyTenants[0].TenantID)
	assert.Equal(t, "Tenant", key.KeyTenants[0].TenantName)
	assert.Equal(t, []string{"SCIM"}, key.KeyTenants[0].Roles)
	assert.Equal(t, "active", key.Status)
	assert.EqualValues(t, 1700000000, key.CreatedTime)
	assert.EqualValues(t, 1800000000, key.ExpireTime)
	assert.Equal(t, "admin", key.CreatedBy)
	assert.Equal(t, "client1", key.ClientID)
	assert.Equal(t, "U1", key.UserID)
	assert.Equal(t, map[string]any{"k1": "v1"}, key.CustomClaims)
	require.NotNil(t, key.Editable)
	assert.False(t, *key.Editable)
	assert.Equal(t, "desc", key.Description)
	assert.Equal(t, []string{"10.0.0.1"}, key.PermittedIPs)
	assert.Equal(t, map[string]any{"attr": "val"}, key.CustomAttributes)
}

func assertSCIMAccessKeyResponse(t *testing.T, res *descope.SCIMAccessKeyResponse) {
	require.NotNil(t, res)
	assert.Equal(t, "secret", res.Cleartext)
	assert.Equal(t, "https://api.descope.com/scim/v2", res.SCIMURL)
	assert.Equal(t, []string{"K0"}, res.RevokedKeyIDs)
	assertSCIMAccessKey(t, res.Key)
}

func TestSCIMCreateAccessKeySuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/scim/key/create", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, map[string]any{
			"tenantId":    "T1",
			"ssoId":       "sso1",
			"name":        "scim-key",
			"description": "desc",
			"expireTime":  "1800000000",
		}, req)
	}, scimAccessKeyResponse))
	res, err := mgmt.SCIM().CreateAccessKey(context.Background(), &descope.CreateSCIMAccessKeyRequest{
		TenantID:    "T1",
		SSOID:       "sso1",
		Name:        "scim-key",
		Description: "desc",
		ExpireTime:  1800000000,
	})
	require.NoError(t, err)
	assertSCIMAccessKeyResponse(t, res)
}

func TestSCIMCreateAccessKeyMinimalSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, map[string]any{"tenantId": "T1"}, req)
	}, map[string]any{"cleartext": "secret", "key": nil}))
	res, err := mgmt.SCIM().CreateAccessKey(context.Background(), &descope.CreateSCIMAccessKeyRequest{TenantID: "T1"})
	require.NoError(t, err)
	assert.Equal(t, "secret", res.Cleartext)
	assert.Nil(t, res.Key)
	assert.Empty(t, res.RevokedKeyIDs)
}

func TestSCIMCreateAccessKeyError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, err := mgmt.SCIM().CreateAccessKey(context.Background(), nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	_, err = mgmt.SCIM().CreateAccessKey(context.Background(), &descope.CreateSCIMAccessKeyRequest{})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	require.ErrorContains(t, err, "tenantID")

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	_, err = mgmt.SCIM().CreateAccessKey(context.Background(), &descope.CreateSCIMAccessKeyRequest{TenantID: "T1"})
	require.Error(t, err)
}

func TestSCIMRotateAccessKeySuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/scim/key/rotate", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, map[string]any{
			"tenantId":    "T1",
			"ssoId":       "sso1",
			"name":        "scim-key",
			"description": "desc",
			"expireTime":  "1800000000",
			"revokeMode":  "SCIM_KEY_REVOKE_MODE_DEACTIVATE",
		}, req)
	}, scimAccessKeyResponse))
	res, err := mgmt.SCIM().RotateAccessKey(context.Background(), &descope.RotateSCIMAccessKeyRequest{
		TenantID:    "T1",
		SSOID:       "sso1",
		Name:        "scim-key",
		Description: "desc",
		ExpireTime:  1800000000,
		RevokeMode:  descope.SCIMKeyRevokeModeDeactivate,
	})
	require.NoError(t, err)
	assertSCIMAccessKeyResponse(t, res)
}

func TestSCIMRotateAccessKeyMinimalSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, map[string]any{"tenantId": "T1"}, req)
	}, scimAccessKeyResponse))
	res, err := mgmt.SCIM().RotateAccessKey(context.Background(), &descope.RotateSCIMAccessKeyRequest{TenantID: "T1"})
	require.NoError(t, err)
	assertSCIMAccessKeyResponse(t, res)
}

func TestSCIMRotateAccessKeyError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, err := mgmt.SCIM().RotateAccessKey(context.Background(), nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	_, err = mgmt.SCIM().RotateAccessKey(context.Background(), &descope.RotateSCIMAccessKeyRequest{})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	require.ErrorContains(t, err, "tenantID")

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	_, err = mgmt.SCIM().RotateAccessKey(context.Background(), &descope.RotateSCIMAccessKeyRequest{TenantID: "T1"})
	require.Error(t, err)
}

func TestSCIMRevokeAccessKeysSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/scim/key/revoke", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, map[string]any{
			"tenantId":   "T1",
			"ssoId":      "sso1",
			"revokeMode": "SCIM_KEY_REVOKE_MODE_DELETE",
		}, req)
	}, map[string]any{"revokedKeyIds": []string{"K1", "K2"}}))
	res, err := mgmt.SCIM().RevokeAccessKeys(context.Background(), &descope.RevokeSCIMAccessKeysRequest{
		TenantID:   "T1",
		SSOID:      "sso1",
		RevokeMode: descope.SCIMKeyRevokeModeDelete,
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"K1", "K2"}, res)
}

func TestSCIMRevokeAccessKeysError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, err := mgmt.SCIM().RevokeAccessKeys(context.Background(), nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	_, err = mgmt.SCIM().RevokeAccessKeys(context.Background(), &descope.RevokeSCIMAccessKeysRequest{})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	require.ErrorContains(t, err, "tenantID")

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	_, err = mgmt.SCIM().RevokeAccessKeys(context.Background(), &descope.RevokeSCIMAccessKeysRequest{TenantID: "T1"})
	require.Error(t, err)
}

func TestSCIMActivateAccessKeysSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/scim/key/activate", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, map[string]any{
			"tenantId": "T1",
			"ssoId":    "sso1",
			"keyIds":   []any{"K1", "K2"},
		}, req)
	}, map[string]any{"activatedKeyIds": []string{"K1", "K2"}}))
	res, err := mgmt.SCIM().ActivateAccessKeys(context.Background(), &descope.ActivateSCIMAccessKeysRequest{
		TenantID: "T1",
		SSOID:    "sso1",
		KeyIDs:   []string{"K1", "K2"},
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"K1", "K2"}, res)
}

func TestSCIMActivateAccessKeysError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, err := mgmt.SCIM().ActivateAccessKeys(context.Background(), nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	_, err = mgmt.SCIM().ActivateAccessKeys(context.Background(), &descope.ActivateSCIMAccessKeysRequest{KeyIDs: []string{"K1"}})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	require.ErrorContains(t, err, "tenantID")
	_, err = mgmt.SCIM().ActivateAccessKeys(context.Background(), &descope.ActivateSCIMAccessKeysRequest{TenantID: "T1"})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	require.ErrorContains(t, err, "keyIDs")
	_, err = mgmt.SCIM().ActivateAccessKeys(context.Background(), &descope.ActivateSCIMAccessKeysRequest{TenantID: "T1", KeyIDs: []string{"K1", ""}})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	require.ErrorContains(t, err, "keyIDs")

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	_, err = mgmt.SCIM().ActivateAccessKeys(context.Background(), &descope.ActivateSCIMAccessKeysRequest{TenantID: "T1", KeyIDs: []string{"K1"}})
	require.Error(t, err)
}

func TestSCIMLoadAccessKeysSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/v1/mgmt/scim/key", r.URL.Path)
		assert.Equal(t, map[string]string{"tenantId": "T1", "ssoId": "sso1"}, helpers.ReadParams(r))
	}, map[string]any{"keys": []map[string]any{{"key": scimAccessKeyJSON, "ssoId": "sso1"}}}))
	res, err := mgmt.SCIM().LoadAccessKeys(context.Background(), "T1", "sso1")
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, "sso1", res[0].SSOID)
	assertSCIMAccessKey(t, res[0].Key)
}

func TestSCIMLoadAccessKeysNoSSOIDSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Equal(t, map[string]string{"tenantId": "T1"}, helpers.ReadParams(r))
	}, map[string]any{"keys": []any{}}))
	res, err := mgmt.SCIM().LoadAccessKeys(context.Background(), "T1", "")
	require.NoError(t, err)
	assert.Empty(t, res)
}

func TestSCIMLoadAccessKeysError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, err := mgmt.SCIM().LoadAccessKeys(context.Background(), "", "")
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	require.ErrorContains(t, err, "tenantID")

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	_, err = mgmt.SCIM().LoadAccessKeys(context.Background(), "T1", "")
	require.Error(t, err)
}
