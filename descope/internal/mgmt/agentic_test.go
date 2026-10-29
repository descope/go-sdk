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

func TestAgenticSearchIdentitiesSuccess(t *testing.T) {
	response := map[string]any{
		"identities": []map[string]any{{
			"consent": map[string]any{
				"id":           "cn1",
				"appId":        "app1",
				"userId":       "U1",
				"scopes":       []string{"read", "write"},
				"grantedBy":    "U2",
				"createdTime":  1700000000,
				"tenantId":     "T1",
				"ExpireTime":   1700003600,
				"modifiedTime": 1700000100,
			},
			"agentName":  "Demo Agent",
			"resourceId": "res1",
			"clientId":   "client1",
			"createdBy":  "U3",
		}},
		"total": 7,
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, "/v1/mgmt/agentic/identities/search", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "U1", req["userId"])
		assert.Equal(t, "client1", req["clientId"])
		assert.Equal(t, "res1", req["resourceId"])
		assert.Equal(t, "cn1", req["consentId"])
		assert.EqualValues(t, 2, req["page"])
		assert.EqualValues(t, 10, req["limit"])
	}, response))
	res, total, err := mgmt.Agentic().SearchIdentities(context.Background(), &descope.AgenticIdentitySearchOptions{
		UserID:     "U1",
		ClientID:   "client1",
		ResourceID: "res1",
		ConsentID:  "cn1",
		Page:       2,
		Limit:      10,
	})
	require.NoError(t, err)
	assert.Equal(t, 7, total)
	require.Len(t, res, 1)
	assert.Equal(t, "Demo Agent", res[0].AgentName)
	assert.Equal(t, "res1", res[0].ResourceID)
	assert.Equal(t, "client1", res[0].ClientID)
	assert.Equal(t, "U3", res[0].CreatedBy)
	require.NotNil(t, res[0].Consent)
	assert.Equal(t, "cn1", res[0].Consent.ID)
	assert.Equal(t, "app1", res[0].Consent.AppID)
	assert.Equal(t, "U1", res[0].Consent.UserID)
	assert.EqualValues(t, []string{"read", "write"}, res[0].Consent.Scopes)
	assert.Equal(t, "U2", res[0].Consent.GrantedBy)
	assert.EqualValues(t, 1700000000, res[0].Consent.CreatedTime)
	assert.Equal(t, "T1", res[0].Consent.TenantID)
	assert.EqualValues(t, 1700003600, res[0].Consent.ExpireTime)
	assert.EqualValues(t, 1700000100, res[0].Consent.ModifiedTime)
}

func TestAgenticSearchIdentitiesNoOptionsSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, "/v1/mgmt/agentic/identities/search", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "", req["userId"])
		assert.EqualValues(t, 0, req["page"])
	}, map[string]any{"identities": []map[string]any{{"agentName": "Demo Agent", "consent": nil}}, "total": 0}))
	res, total, err := mgmt.Agentic().SearchIdentities(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, 0, total)
	require.Len(t, res, 1)
	assert.Nil(t, res[0].Consent)
}

func TestAgenticSearchIdentitiesError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, total, err := mgmt.Agentic().SearchIdentities(context.Background(), nil)
	require.Error(t, err)
	assert.Nil(t, res)
	assert.Equal(t, 0, total)
}

func TestAgenticRevokeIdentitiesSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, "/v1/mgmt/agentic/identities/revoke", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "U1", req["userId"])
		assert.Equal(t, "client1", req["clientId"])
		assert.Equal(t, "res1", req["resourceId"])
		assert.Equal(t, "cn1", req["consentId"])
	}, map[string]any{"revoked": 3}))
	revoked, err := mgmt.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{
		UserID:     "U1",
		ClientID:   "client1",
		ResourceID: "res1",
		ConsentID:  "cn1",
	})
	require.NoError(t, err)
	assert.Equal(t, 3, revoked)
}

func TestAgenticRevokeIdentitiesUserOnlySuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, "/v1/mgmt/agentic/identities/revoke", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "U1", req["userId"])
		assert.Equal(t, "", req["clientId"])
	}, map[string]any{"revoked": 1}))
	revoked, err := mgmt.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{UserID: "U1"})
	require.NoError(t, err)
	assert.Equal(t, 1, revoked)
}

func TestAgenticRevokeIdentitiesInvalidArgument(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	revoked, err := mgmt.Agentic().RevokeIdentities(context.Background(), nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.Equal(t, 0, revoked)
	revoked, err = mgmt.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.Equal(t, 0, revoked)
}

func TestAgenticRevokeIdentitiesError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	revoked, err := mgmt.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{ConsentID: "cn1"})
	require.Error(t, err)
	assert.Equal(t, 0, revoked)
}
