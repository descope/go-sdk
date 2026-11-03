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
				"id":           "consent1",
				"appId":        "app1",
				"userId":       "user1",
				"scopes":       []string{"read", "write"},
				"grantedBy":    "user2",
				"createdTime":  100,
				"tenantId":     "tenant1",
				"ExpireTime":   200,
				"modifiedTime": 300,
				"authMethod":   "idJag",
				"blocked":      true,
			},
			"agentName":  "agent",
			"resourceId": "resource1",
			"clientId":   "client1",
			"createdBy":  "creator",
		}},
		"total": 7,
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, "/v1/mgmt/agentic/identities/search", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{
			"userId":     "user1",
			"clientId":   "client1",
			"resourceId": "resource1",
			"consentId":  "consent1",
			"page":       float64(2),
			"limit":      float64(10),
		}, req)
	}, response))
	identities, total, err := mgmt.Agentic().SearchIdentities(context.Background(), &descope.AgenticIdentitySearchOptions{
		UserID:     "user1",
		ClientID:   "client1",
		ResourceID: "resource1",
		ConsentID:  "consent1",
		Page:       2,
		Limit:      10,
	})
	require.NoError(t, err)
	assert.Equal(t, 7, total)
	require.Len(t, identities, 1)
	identity := identities[0]
	assert.Equal(t, "agent", identity.AgentName)
	assert.Equal(t, "resource1", identity.ResourceID)
	assert.Equal(t, "client1", identity.ClientID)
	assert.Equal(t, "creator", identity.CreatedBy)
	require.NotNil(t, identity.Consent)
	assert.Equal(t, "consent1", identity.Consent.ID)
	assert.Equal(t, "app1", identity.Consent.AppID)
	assert.Equal(t, "user1", identity.Consent.UserID)
	assert.Equal(t, []string{"read", "write"}, identity.Consent.Scopes)
	assert.Equal(t, "user2", identity.Consent.GrantedBy)
	assert.EqualValues(t, 100, identity.Consent.CreatedTime)
	assert.Equal(t, "tenant1", identity.Consent.TenantID)
	assert.EqualValues(t, 200, identity.Consent.ExpireTime)
	assert.EqualValues(t, 300, identity.Consent.ModifiedTime)
	assert.Equal(t, "idJag", identity.Consent.AuthMethod)
	assert.True(t, identity.Consent.Blocked)
}

func TestAgenticSearchIdentitiesOmitsUnsetFields(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Empty(t, req)
	}, map[string]any{"identities": nil}))
	identities, total, err := mgmt.Agentic().SearchIdentities(context.Background(), &descope.AgenticIdentitySearchOptions{})
	require.NoError(t, err)
	assert.Empty(t, identities)
	assert.Zero(t, total)
}

func TestAgenticSearchIdentitiesNilOptions(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) { called = true }))
	identities, total, err := mgmt.Agentic().SearchIdentities(context.Background(), nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.Nil(t, identities)
	assert.Zero(t, total)
	assert.False(t, called)
}

func TestAgenticSearchIdentitiesError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	identities, total, err := mgmt.Agentic().SearchIdentities(context.Background(), &descope.AgenticIdentitySearchOptions{})
	require.Error(t, err)
	assert.Nil(t, identities)
	assert.Zero(t, total)
}

func TestAgenticSearchIdentitiesBadResponse(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(nil, "bad"))
	identities, total, err := mgmt.Agentic().SearchIdentities(context.Background(), &descope.AgenticIdentitySearchOptions{})
	require.Error(t, err)
	assert.Nil(t, identities)
	assert.Zero(t, total)
}

func TestAgenticRevokeIdentitiesSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, "/v1/mgmt/agentic/identities/revoke", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{
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

func TestAgenticRevokeIdentitiesOmitsUnsetFields(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{"userId": "user1"}, req)
	}, map[string]any{}))
	revoked, err := mgmt.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{UserID: "user1"})
	require.NoError(t, err)
	assert.Zero(t, revoked)
}

func TestAgenticRevokeIdentitiesNilOptions(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) { called = true }))
	revoked, err := mgmt.Agentic().RevokeIdentities(context.Background(), nil)
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

func TestAgenticRevokeIdentitiesBadResponse(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(nil, "bad"))
	revoked, err := mgmt.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{UserID: "user1"})
	require.Error(t, err)
	assert.Zero(t, revoked)
}
