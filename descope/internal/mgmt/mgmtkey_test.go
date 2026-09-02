package mgmt

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
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
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		ids := req["ids"].([]any)
		require.Len(t, ids, 2)
		require.Equal(t, "mk1", ids[0])
		require.Equal(t, "mk2", ids[1])
	}, map[string]any{"total": 2}))
	total, err := mgmt.ManagementKey().Delete(context.Background(), []string{"mk1", "mk2"})
	require.NoError(t, err)
	require.Equal(t, 2, total)
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
	total, err := mgmt.ManagementKey().Delete(context.Background(), []string{})
	require.Error(t, err)
	require.Equal(t, 0, total)
}

func TestMgmtKeySearch_Error(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.ManagementKey().Search(context.Background(), nil)
	require.Error(t, err)
	require.Nil(t, res)
}

func TestMgmtKeyCreateWithOptions_TrustedIssuer(t *testing.T) {
	response := map[string]any{
		"cleartext": "",
		"key": map[string]any{
			"id":   "mk1",
			"name": "ci-export",
			"trustedIssuer": map[string]any{
				"name":          "github-actions",
				"issuer":        "https://token.actions.githubusercontent.com",
				"maxTtlSeconds": 900,
				"audience":      "https://api.descope.com/mk1",
				"claimFilters":  map[string]any{"sub": []string{"repo:org/app:ref:refs/heads/main"}},
			},
		}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		issuer := req["trustedIssuer"].(map[string]any)
		require.Equal(t, "github-actions", issuer["name"])
		require.Equal(t, "https://token.actions.githubusercontent.com", issuer["issuer"])
		require.EqualValues(t, 900, issuer["maxTtlSeconds"])
		require.NotContains(t, issuer, "audience", "the audience is derived by the server, never sent")
		subs := issuer["claimFilters"].(map[string]any)["sub"].([]any)
		require.Len(t, subs, 1)
		require.Equal(t, "repo:org/app:ref:refs/heads/main", subs[0])
	}, response))

	key, cleartext, err := mgmt.ManagementKey().CreateWithOptions(context.Background(), &descope.MgmtKeyCreateOptions{
		Name: "ci-export",
		TrustedIssuer: &descope.WIFTrustedIssuerRequest{
			Name:          "github-actions",
			Issuer:        "https://token.actions.githubusercontent.com",
			MaxTTLSeconds: 900,
			ClaimFilters:  map[string][]string{"sub": {"repo:org/app:ref:refs/heads/main"}},
		},
	})
	require.NoError(t, err)
	require.Empty(t, cleartext, "a federated key has no secret")
	require.NotNil(t, key.TrustedIssuer)
	require.Equal(t, "https://api.descope.com/mk1", key.TrustedIssuer.Audience)
	require.Equal(t, []string{"repo:org/app:ref:refs/heads/main"}, key.TrustedIssuer.ClaimFilters["sub"])
}

func TestMgmtKeyCreateWithOptions_OmitsTrustedIssuerWhenAbsent(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.NotContains(t, req, "trustedIssuer")
	}, map[string]any{"key": map[string]any{"id": "mk1"}}))

	_, _, err := mgmt.ManagementKey().CreateWithOptions(context.Background(), &descope.MgmtKeyCreateOptions{Name: "plain"})
	require.NoError(t, err)
}

func TestMgmtKeyUpdateWithOptions_TrustedIssuer(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "mk1", req["id"])
		issuer := req["trustedIssuer"].(map[string]any)
		require.EqualValues(t, 600, issuer["maxTtlSeconds"])
	}, map[string]any{"key": map[string]any{"id": "mk1"}}))

	_, err := mgmt.ManagementKey().UpdateWithOptions(context.Background(), &descope.MgmtKeyUpdateOptions{
		ID:            "mk1",
		Name:          "ci-export",
		TrustedIssuer: &descope.WIFTrustedIssuerRequest{MaxTTLSeconds: 600},
	})
	require.NoError(t, err)
}

func TestMgmtKeyWithOptions_BadInput(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, _, err := mgmt.ManagementKey().CreateWithOptions(context.Background(), nil)
	require.Error(t, err)
	_, _, err = mgmt.ManagementKey().CreateWithOptions(context.Background(), &descope.MgmtKeyCreateOptions{})
	require.Error(t, err)
	_, err = mgmt.ManagementKey().UpdateWithOptions(context.Background(), nil)
	require.Error(t, err)
	_, err = mgmt.ManagementKey().UpdateWithOptions(context.Background(), &descope.MgmtKeyUpdateOptions{})
	require.Error(t, err)
}

func TestWorkloadTokenIsSentInsteadOfAManagementKey(t *testing.T) {
	params := &api.ClientParams{
		ProjectID:             "P2abc",
		WorkloadTokenProvider: func(context.Context) (string, error) { return "header.payload.signature", nil },
	}
	mgmt := newTestMgmt(params, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, "Bearer P2abc:header.payload.signature", r.Header.Get("Authorization"))
	}, map[string]any{"key": map[string]any{"id": "mk1"}}))

	_, err := mgmt.ManagementKey().Get(context.Background(), "mk1")
	require.NoError(t, err)
}

func TestWorkloadTokenIsReadPerRequest(t *testing.T) {
	calls := 0
	params := &api.ClientParams{
		ProjectID: "P2abc",
		WorkloadTokenProvider: func(context.Context) (string, error) {
			calls++
			return fmt.Sprintf("token-%d", calls), nil
		},
	}
	seen := []string{}
	mgmt := newTestMgmt(params, helpers.DoOkWithBody(func(r *http.Request) {
		seen = append(seen, r.Header.Get("Authorization"))
	}, map[string]any{"key": map[string]any{"id": "mk1"}}))

	_, err := mgmt.ManagementKey().Get(context.Background(), "mk1")
	require.NoError(t, err)
	_, err = mgmt.ManagementKey().Get(context.Background(), "mk1")
	require.NoError(t, err)
	require.Equal(t, []string{"Bearer P2abc:token-1", "Bearer P2abc:token-2"}, seen, "a short lived token must be refreshed per request")
}

func TestWorkloadTokenProviderFailureFailsTheRequest(t *testing.T) {
	params := &api.ClientParams{
		ProjectID:             "P2abc",
		WorkloadTokenProvider: func(context.Context) (string, error) { return "", errors.New("no token") },
	}
	mgmt := newTestMgmt(params, helpers.DoOk(nil))

	_, err := mgmt.ManagementKey().Get(context.Background(), "mk1")
	require.ErrorContains(t, err, "no token")
}
