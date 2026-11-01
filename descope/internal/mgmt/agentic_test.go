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
		"identities": []map[string]any{
			{
				"consent": map[string]any{
					"id":           "consent1",
					"appId":        "app1",
					"userId":       "user1",
					"scopes":       []string{"read", "write"},
					"grantedBy":    "user2",
					"createdTime":  1700000000,
					"tenantId":     "tenant1",
					"ExpireTime":   1700000100,
					"modifiedTime": 1700000050,
					"authMethod":   "idJag",
				},
				"agentName":  "agent1",
				"resourceId": "resource1",
				"clientId":   "client1",
				"createdBy":  "user3",
			},
			{
				"consent":    nil,
				"agentName":  "agent2",
				"resourceId": "",
				"clientId":   "client2",
				"createdBy":  "",
			},
		},
		"total": 2,
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/agentic/identities/search", r.URL.Path)
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "user1", req["userId"])
		assert.Equal(t, "client1", req["clientId"])
		assert.Equal(t, "resource1", req["resourceId"])
		assert.Equal(t, "consent1", req["consentId"])
		assert.EqualValues(t, 2, req["page"])
		assert.EqualValues(t, 50, req["limit"])
	}, response))
	res, total, err := mgmt.Agentic().SearchIdentities(context.Background(), &descope.AgenticIdentitySearchOptions{
		UserID:     "user1",
		ClientID:   "client1",
		ResourceID: "resource1",
		ConsentID:  "consent1",
		Page:       2,
		Limit:      50,
	})
	require.NoError(t, err)
	require.Equal(t, 2, total)
	require.Len(t, res, 2)
	assert.Equal(t, "agent1", res[0].AgentName)
	assert.Equal(t, "resource1", res[0].ResourceID)
	assert.Equal(t, "client1", res[0].ClientID)
	assert.Equal(t, "user3", res[0].CreatedBy)
	require.NotNil(t, res[0].Consent)
	assert.Equal(t, "consent1", res[0].Consent.ID)
	assert.Equal(t, "app1", res[0].Consent.AppID)
	assert.Equal(t, "user1", res[0].Consent.UserID)
	assert.Equal(t, []string{"read", "write"}, res[0].Consent.Scopes)
	assert.Equal(t, "user2", res[0].Consent.GrantedBy)
	assert.EqualValues(t, 1700000000, res[0].Consent.CreatedTime)
	assert.Equal(t, "tenant1", res[0].Consent.TenantID)
	assert.EqualValues(t, 1700000100, res[0].Consent.ExpireTime)
	assert.EqualValues(t, 1700000050, res[0].Consent.ModifiedTime)
	assert.Equal(t, "idJag", res[0].Consent.AuthMethod)
	assert.Nil(t, res[1].Consent)
	assert.Equal(t, "agent2", res[1].AgentName)
	assert.Equal(t, "client2", res[1].ClientID)
}

func TestAgenticSearchIdentitiesEmptyOptions(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "", req["userId"])
		assert.EqualValues(t, 0, req["page"])
	}, map[string]any{"identities": []any{}, "total": 0}))
	res, total, err := mgmt.Agentic().SearchIdentities(context.Background(), &descope.AgenticIdentitySearchOptions{})
	require.NoError(t, err)
	require.Empty(t, res)
	require.Zero(t, total)
}

func TestAgenticSearchIdentitiesMissingOptions(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) { called = true }))
	res, total, err := mgmt.Agentic().SearchIdentities(context.Background(), nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	require.Nil(t, res)
	require.Zero(t, total)
	require.False(t, called)
}

func TestAgenticSearchIdentitiesError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, total, err := mgmt.Agentic().SearchIdentities(context.Background(), &descope.AgenticIdentitySearchOptions{UserID: "user1"})
	require.Error(t, err)
	require.Nil(t, res)
	require.Zero(t, total)
}

func TestAgenticRevokeIdentitiesSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/agentic/identities/revoke", r.URL.Path)
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "user1", req["userId"])
		assert.Equal(t, "client1", req["clientId"])
		assert.Equal(t, "resource1", req["resourceId"])
		assert.Equal(t, "consent1", req["consentId"])
	}, map[string]any{"revoked": 3}))
	revoked, err := mgmt.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{
		UserID:     "user1",
		ClientID:   "client1",
		ResourceID: "resource1",
		ConsentID:  "consent1",
	})
	require.NoError(t, err)
	require.Equal(t, 3, revoked)
}

func TestAgenticRevokeIdentitiesMissingOptions(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) { called = true }))
	revoked, err := mgmt.Agentic().RevokeIdentities(context.Background(), nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	require.Zero(t, revoked)
	require.False(t, called)
}

func TestAgenticRevokeIdentitiesError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	revoked, err := mgmt.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{UserID: "user1"})
	require.Error(t, err)
	require.Zero(t, revoked)
}
