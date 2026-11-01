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
				"createdTime":  10,
				"tenantId":     "tenant1",
				"ExpireTime":   20,
				"modifiedTime": 30,
				"authMethod":   "idJag",
			},
			"agentName":  "Demo Agent",
			"resourceId": "res1",
			"clientId":   "client1",
			"createdBy":  "user3",
		}, {
			"consent":   nil,
			"agentName": "Other Agent",
		}},
		"total": 5,
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/agentic/identities/search", r.URL.Path)
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, map[string]any{
			"userId":     "user1",
			"clientId":   "client1",
			"resourceId": "res1",
			"consentId":  "consent1",
			"page":       float64(2),
			"limit":      float64(10),
		}, req)
	}, response))
	res, total, err := mgmt.Agentic().SearchIdentities(context.Background(), &descope.AgenticIdentitySearchOptions{
		UserID:     "user1",
		ClientID:   "client1",
		ResourceID: "res1",
		ConsentID:  "consent1",
		Page:       2,
		Limit:      10,
	})
	require.NoError(t, err)
	assert.Equal(t, 5, total)
	require.Len(t, res, 2)
	assert.Equal(t, "Demo Agent", res[0].AgentName)
	assert.Equal(t, "res1", res[0].ResourceID)
	assert.Equal(t, "client1", res[0].ClientID)
	assert.Equal(t, "user3", res[0].CreatedBy)
	require.NotNil(t, res[0].Consent)
	assert.Equal(t, &descope.ThirdPartyApplicationConsent{
		ID:           "consent1",
		AppID:        "app1",
		UserID:       "user1",
		Scopes:       []string{"read", "write"},
		GrantedBy:    "user2",
		CreatedTime:  10,
		TenantID:     "tenant1",
		ExpireTime:   20,
		ModifiedTime: 30,
		AuthMethod:   "idJag",
	}, res[0].Consent)
	assert.Equal(t, "Other Agent", res[1].AgentName)
	assert.Nil(t, res[1].Consent)
}

func TestAgenticSearchIdentitiesEmptyOptionsSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "", req["userId"])
		assert.EqualValues(t, 0, req["page"])
	}, map[string]any{"identities": []any{}, "total": 0}))
	res, total, err := mgmt.Agentic().SearchIdentities(context.Background(), &descope.AgenticIdentitySearchOptions{})
	require.NoError(t, err)
	assert.Empty(t, res)
	assert.Zero(t, total)
}

func TestAgenticSearchIdentitiesMissingOptions(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		require.Fail(t, "request should not be sent")
	}))
	res, total, err := mgmt.Agentic().SearchIdentities(context.Background(), nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.Contains(t, err.Error(), "options")
	assert.Nil(t, res)
	assert.Zero(t, total)
}

func TestAgenticSearchIdentitiesError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, total, err := mgmt.Agentic().SearchIdentities(context.Background(), &descope.AgenticIdentitySearchOptions{})
	require.Error(t, err)
	assert.Nil(t, res)
	assert.Zero(t, total)
}

func TestAgenticSearchIdentitiesBadResponse(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(nil, "not an object"))
	res, total, err := mgmt.Agentic().SearchIdentities(context.Background(), &descope.AgenticIdentitySearchOptions{})
	require.Error(t, err)
	assert.Nil(t, res)
	assert.Zero(t, total)
}

func TestAgenticRevokeIdentitiesSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/agentic/identities/revoke", r.URL.Path)
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, map[string]any{
			"userId":     "user1",
			"clientId":   "client1",
			"resourceId": "res1",
			"consentId":  "consent1",
		}, req)
	}, map[string]any{"revoked": 3}))
	revoked, err := mgmt.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{
		UserID:     "user1",
		ClientID:   "client1",
		ResourceID: "res1",
		ConsentID:  "consent1",
	})
	require.NoError(t, err)
	assert.Equal(t, 3, revoked)
}

func TestAgenticRevokeIdentitiesMissingOptions(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		require.Fail(t, "request should not be sent")
	}))
	revoked, err := mgmt.Agentic().RevokeIdentities(context.Background(), nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.Contains(t, err.Error(), "options")
	assert.Zero(t, revoked)
}

func TestAgenticRevokeIdentitiesError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	revoked, err := mgmt.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{UserID: "user1"})
	require.Error(t, err)
	assert.Zero(t, revoked)
}

func TestAgenticRevokeIdentitiesBadResponse(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(nil, "not an object"))
	revoked, err := mgmt.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{UserID: "user1"})
	require.Error(t, err)
	assert.Zero(t, revoked)
}
