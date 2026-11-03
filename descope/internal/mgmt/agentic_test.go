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
					"scopes":       []any{"scope1"},
					"grantedBy":    "admin1",
					"createdTime":  10,
					"tenantId":     "tenant1",
					"ExpireTime":   20,
					"modifiedTime": 30,
					"authMethod":   "idJag",
					"blocked":      true,
				},
				"agentName":  "agent1",
				"resourceId": "resource1",
				"clientId":   "client1",
				"createdBy":  "creator1",
			},
			{
				"consent":    nil,
				"agentName":  "agent2",
				"resourceId": "",
				"clientId":   "client2",
			},
		},
		"total": 2,
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/v1/mgmt/agentic/identities/search", r.URL.Path)
		assert.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, map[string]any{
			"userId":     "user1",
			"clientId":   "client1",
			"resourceId": "resource1",
			"consentId":  "consent1",
			"page":       float64(1),
			"limit":      float64(10),
		}, req)
	}, response))

	res, total, err := mgmt.Agentic().SearchIdentities(context.Background(), &descope.AgenticIdentitySearchOptions{
		UserID:     "user1",
		ClientID:   "client1",
		ResourceID: "resource1",
		ConsentID:  "consent1",
		Page:       1,
		Limit:      10,
	})
	require.NoError(t, err)
	require.Equal(t, 2, total)
	require.Len(t, res, 2)
	require.NotNil(t, res[0].Consent)
	assert.Equal(t, "consent1", res[0].Consent.ID)
	assert.Equal(t, "app1", res[0].Consent.AppID)
	assert.Equal(t, "user1", res[0].Consent.UserID)
	assert.Equal(t, []string{"scope1"}, res[0].Consent.Scopes)
	assert.Equal(t, "admin1", res[0].Consent.GrantedBy)
	assert.EqualValues(t, 10, res[0].Consent.CreatedTime)
	assert.Equal(t, "tenant1", res[0].Consent.TenantID)
	assert.EqualValues(t, 20, res[0].Consent.ExpireTime)
	assert.EqualValues(t, 30, res[0].Consent.ModifiedTime)
	assert.Equal(t, "idJag", res[0].Consent.AuthMethod)
	assert.True(t, res[0].Consent.Blocked)
	assert.Equal(t, "agent1", res[0].AgentName)
	assert.Equal(t, "resource1", res[0].ResourceID)
	assert.Equal(t, "client1", res[0].ClientID)
	assert.Equal(t, "creator1", res[0].CreatedBy)
	assert.Nil(t, res[1].Consent)
	assert.Equal(t, "agent2", res[1].AgentName)
	assert.Equal(t, "client2", res[1].ClientID)
}

func TestAgenticSearchIdentitiesOmitsUnsetFields(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, map[string]any{"userId": "user1"}, req)
	}, map[string]any{}))

	res, total, err := mgmt.Agentic().SearchIdentities(context.Background(), &descope.AgenticIdentitySearchOptions{UserID: "user1"})
	require.NoError(t, err)
	assert.Empty(t, res)
	assert.Zero(t, total)
}

func TestAgenticSearchIdentitiesNilOptions(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) { called = true }))
	res, total, err := mgmt.Agentic().SearchIdentities(context.Background(), nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.Nil(t, res)
	assert.Zero(t, total)
	assert.False(t, called)
}

func TestAgenticSearchIdentitiesError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, total, err := mgmt.Agentic().SearchIdentities(context.Background(), &descope.AgenticIdentitySearchOptions{})
	require.Error(t, err)
	assert.Nil(t, res)
	assert.Zero(t, total)
}

func TestAgenticRevokeIdentitiesSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/v1/mgmt/agentic/identities/revoke", r.URL.Path)
		assert.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, map[string]any{
			"userId":     "user1",
			"clientId":   "client1",
			"resourceId": "resource1",
			"consentId":  "consent1",
		}, req)
	}, map[string]any{"revoked": 3}))

	revoked, err := mgmt.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{
		UserID:     "user1",
		ClientID:   "client1",
		ResourceID: "resource1",
		ConsentID:  "consent1",
	})
	require.NoError(t, err)
	assert.Equal(t, 3, revoked)
}

func TestAgenticRevokeIdentitiesSingleFilter(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, map[string]any{"consentId": "consent1"}, req)
	}, map[string]any{"revoked": 1}))

	revoked, err := mgmt.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{ConsentID: "consent1"})
	require.NoError(t, err)
	assert.Equal(t, 1, revoked)
}

func TestAgenticRevokeIdentitiesNilOptions(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) { called = true }))
	revoked, err := mgmt.Agentic().RevokeIdentities(context.Background(), nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.Zero(t, revoked)
	assert.False(t, called)
}

func TestAgenticRevokeIdentitiesNoFilter(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) { called = true }))
	revoked, err := mgmt.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.Zero(t, revoked)
	assert.False(t, called)
}

func TestAgenticRevokeIdentitiesError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	revoked, err := mgmt.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{UserID: "user1"})
	require.Error(t, err)
	assert.Zero(t, revoked)
}
