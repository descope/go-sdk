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

var agenticIdentitiesResponse = map[string]any{
	"identities": []map[string]any{{
		"consent": map[string]any{
			"id":           "consent1",
			"appId":        "app1",
			"userId":       "user1",
			"scopes":       []string{"read"},
			"grantedBy":    "admin1",
			"createdTime":  10,
			"tenantId":     "tenant1",
			"ExpireTime":   20,
			"modifiedTime": 30,
			"authMethod":   "idJag",
		},
		"agentName":  "My Agent",
		"resourceId": "mcp1",
		"clientId":   "client1",
		"createdBy":  "creator1",
	}},
	"total": 7,
}

var governanceAccessRequestResponse = map[string]any{
	"id":              "req1",
	"requestorUserId": "user1",
	"requestorName":   "Jane",
	"clientName":      "my-agent",
	"clientType":      "agent",
	"grantTypes":      []string{"clientCredentials"},
	"targets": []map[string]any{{
		"name":      "api",
		"kind":      "resource",
		"targetId":  "res1",
		"scopes":    []string{"read"},
		"allScopes": true,
	}},
	"scopes":           []string{"s1"},
	"justification":    "need it",
	"status":           "approved",
	"resolvedByUserId": "admin1",
	"resolvedByName":   "Management API",
	"resolutionNote":   "ok",
	"clientId":         "client1",
	"clientAppId":      "app1",
	"createdTime":      "1700000000000",
	"modifiedTime":     "1700000001000",
	"version":          "3",
	"clientDeleted":    true,
}

func assertGovernanceAccessRequest(t *testing.T, req *descope.GovernanceAccessRequest) {
	require.NotNil(t, req)
	assert.Equal(t, "req1", req.ID)
	assert.Equal(t, "user1", req.RequestorUserID)
	assert.Equal(t, "Jane", req.RequestorName)
	assert.Equal(t, "my-agent", req.ClientName)
	assert.Equal(t, "agent", req.ClientType)
	assert.Equal(t, []string{"clientCredentials"}, req.GrantTypes)
	require.Len(t, req.Targets, 1)
	assert.Equal(t, &descope.GovernanceAccessRequestTarget{Name: "api", Kind: "resource", TargetID: "res1", Scopes: []string{"read"}, AllScopes: true}, req.Targets[0])
	assert.Equal(t, []string{"s1"}, req.Scopes)
	assert.Equal(t, "need it", req.Justification)
	assert.Equal(t, descope.GovernanceAccessRequestStatusApproved, req.Status)
	assert.Equal(t, "admin1", req.ResolvedByUserID)
	assert.Equal(t, "Management API", req.ResolvedByName)
	assert.Equal(t, "ok", req.ResolutionNote)
	assert.Equal(t, "client1", req.ClientID)
	assert.Equal(t, "app1", req.ClientAppID)
	assert.EqualValues(t, 1700000000000, req.CreatedTime)
	assert.EqualValues(t, 1700000001000, req.ModifiedTime)
	assert.True(t, req.ClientDeleted)
}

func TestAgenticSearchIdentitiesSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/agentic/identities/search", r.URL.Path)
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{
			"userId":     "user1",
			"clientId":   "client1",
			"resourceId": "mcp1",
			"consentId":  "consent1",
			"page":       float64(1),
			"limit":      float64(10),
		}, req)
	}, agenticIdentitiesResponse))
	identities, total, err := mgmt.Agentic().SearchIdentities(context.Background(), &descope.AgenticIdentitySearchOptions{
		UserID:     "user1",
		ClientID:   "client1",
		ResourceID: "mcp1",
		ConsentID:  "consent1",
		Page:       1,
		Limit:      10,
	})
	require.NoError(t, err)
	assert.Equal(t, 7, total)
	require.Len(t, identities, 1)
	identity := identities[0]
	assert.Equal(t, "My Agent", identity.AgentName)
	assert.Equal(t, "mcp1", identity.ResourceID)
	assert.Equal(t, "client1", identity.ClientID)
	assert.Equal(t, "creator1", identity.CreatedBy)
	require.NotNil(t, identity.Consent)
	assert.Equal(t, &descope.ThirdPartyApplicationConsent{
		ID:           "consent1",
		AppID:        "app1",
		UserID:       "user1",
		Scopes:       []string{"read"},
		GrantedBy:    "admin1",
		CreatedTime:  10,
		TenantID:     "tenant1",
		ExpireTime:   20,
		ModifiedTime: 30,
		AuthMethod:   "idJag",
	}, identity.Consent)
}

func TestAgenticSearchIdentitiesNilOptions(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Empty(t, req)
	}, map[string]any{"identities": nil, "total": 0}))
	identities, total, err := mgmt.Agentic().SearchIdentities(context.Background(), nil)
	require.NoError(t, err)
	assert.Empty(t, identities)
	assert.Zero(t, total)
}

func TestAgenticSearchIdentitiesError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	identities, total, err := mgmt.Agentic().SearchIdentities(context.Background(), nil)
	require.Error(t, err)
	assert.Nil(t, identities)
	assert.Zero(t, total)
}

func TestAgenticRevokeIdentitiesSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/agentic/identities/revoke", r.URL.Path)
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{
			"userId":     "user1",
			"clientId":   "client1",
			"resourceId": "mcp1",
			"consentId":  "consent1",
		}, req)
	}, map[string]any{"revoked": 3}))
	revoked, err := mgmt.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{
		UserID:     "user1",
		ClientID:   "client1",
		ResourceID: "mcp1",
		ConsentID:  "consent1",
	})
	require.NoError(t, err)
	assert.Equal(t, 3, revoked)
}

func TestAgenticRevokeIdentitiesOnlyUser(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{"userId": "user1"}, req)
	}, map[string]any{"revoked": 1}))
	revoked, err := mgmt.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{UserID: "user1"})
	require.NoError(t, err)
	assert.Equal(t, 1, revoked)
}

func TestAgenticRevokeIdentitiesError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) { called = true }))
	revoked, err := mgmt.Agentic().RevokeIdentities(context.Background(), nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.Zero(t, revoked)
	revoked, err = mgmt.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.Zero(t, revoked)
	assert.False(t, called)

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	revoked, err = mgmt.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{ClientID: "client1"})
	require.Error(t, err)
	assert.Zero(t, revoked)
}

func TestAgenticGetGovernanceSettingsSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/v1/mgmt/agentic/governance/settings", r.URL.Path)
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
	}, map[string]any{"configured": true, "autoApproval": false, "suiteDisabled": true}))
	settings, err := mgmt.Agentic().GetGovernanceSettings(context.Background())
	require.NoError(t, err)
	require.NotNil(t, settings)
	require.NotNil(t, settings.Configured)
	assert.True(t, *settings.Configured)
	require.NotNil(t, settings.AutoApproval)
	assert.False(t, *settings.AutoApproval)
	require.NotNil(t, settings.SuiteDisabled)
	assert.True(t, *settings.SuiteDisabled)
}

func TestAgenticGetGovernanceSettingsMissingFields(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(nil, map[string]any{}))
	settings, err := mgmt.Agentic().GetGovernanceSettings(context.Background())
	require.NoError(t, err)
	require.NotNil(t, settings)
	assert.Nil(t, settings.Configured)
	assert.Nil(t, settings.AutoApproval)
	assert.Nil(t, settings.SuiteDisabled)
}

func TestAgenticGetGovernanceSettingsError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	settings, err := mgmt.Agentic().GetGovernanceSettings(context.Background())
	require.Error(t, err)
	assert.Nil(t, settings)
}

func TestAgenticSetGovernanceSettingsSuccess(t *testing.T) {
	enabled := true
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/agentic/governance/settings", r.URL.Path)
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{"autoApproval": true}, req)
	}, map[string]any{"configured": true, "autoApproval": true, "suiteDisabled": false}))
	settings, err := mgmt.Agentic().SetGovernanceSettings(context.Background(), &descope.AgenticGovernanceSettings{AutoApproval: &enabled})
	require.NoError(t, err)
	require.NotNil(t, settings)
	assert.True(t, *settings.Configured)
	assert.True(t, *settings.AutoApproval)
	assert.False(t, *settings.SuiteDisabled)
}

func TestAgenticSetGovernanceSettingsError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) { called = true }))
	settings, err := mgmt.Agentic().SetGovernanceSettings(context.Background(), nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.Nil(t, settings)
	assert.False(t, called)

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	settings, err = mgmt.Agentic().SetGovernanceSettings(context.Background(), &descope.AgenticGovernanceSettings{})
	require.Error(t, err)
	assert.Nil(t, settings)
}

func TestAgenticSearchGovernanceAccessRequestsSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/agentic/governance/requests/search", r.URL.Path)
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{
			"limit": float64(10),
			"page":  float64(1),
			"searchFields": []any{map[string]any{
				"field":    "status",
				"valArr":   []any{"pending"},
				"valStr":   "pend",
				"negative": true,
				"valType":  "string",
			}},
			"sort": []any{map[string]any{"field": "createdTime", "desc": true}},
			"text": "agent",
		}, req)
	}, map[string]any{"requests": []any{governanceAccessRequestResponse}, "total": 5}))
	requests, total, err := mgmt.Agentic().SearchGovernanceAccessRequests(context.Background(), &descope.GovernanceAccessRequestSearchOptions{
		Limit: 10,
		Page:  1,
		SearchFields: []*descope.GovernanceAccessRequestSearchField{{
			Field:    "status",
			ValArr:   []string{"pending"},
			ValStr:   "pend",
			Negative: true,
			ValType:  "string",
		}},
		Sort: []*descope.GovernanceAccessRequestSort{{Field: "createdTime", Desc: true}},
		Text: "agent",
	})
	require.NoError(t, err)
	assert.Equal(t, 5, total)
	require.Len(t, requests, 1)
	assertGovernanceAccessRequest(t, requests[0])
}

func TestAgenticSearchGovernanceAccessRequestsNilOptions(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Empty(t, req)
	}, map[string]any{"requests": []any{}, "total": 0}))
	requests, total, err := mgmt.Agentic().SearchGovernanceAccessRequests(context.Background(), nil)
	require.NoError(t, err)
	assert.Empty(t, requests)
	assert.Zero(t, total)
}

func TestAgenticSearchGovernanceAccessRequestsError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) { called = true }))
	requests, total, err := mgmt.Agentic().SearchGovernanceAccessRequests(context.Background(), &descope.GovernanceAccessRequestSearchOptions{
		Sort: []*descope.GovernanceAccessRequestSort{{Field: ""}},
	})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.Nil(t, requests)
	assert.Zero(t, total)
	_, _, err = mgmt.Agentic().SearchGovernanceAccessRequests(context.Background(), &descope.GovernanceAccessRequestSearchOptions{
		Sort: []*descope.GovernanceAccessRequestSort{nil},
	})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.False(t, called)

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	requests, total, err = mgmt.Agentic().SearchGovernanceAccessRequests(context.Background(), nil)
	require.Error(t, err)
	assert.Nil(t, requests)
	assert.Zero(t, total)
}

func TestAgenticGetGovernanceAccessRequestSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/agentic/governance/requests/get", r.URL.Path)
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{"id": "req1"}, req)
	}, governanceAccessRequestResponse))
	res, err := mgmt.Agentic().GetGovernanceAccessRequest(context.Background(), "req1")
	require.NoError(t, err)
	assertGovernanceAccessRequest(t, res)
}

func TestAgenticGetGovernanceAccessRequestError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) { called = true }))
	res, err := mgmt.Agentic().GetGovernanceAccessRequest(context.Background(), "")
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.Nil(t, res)
	assert.False(t, called)

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err = mgmt.Agentic().GetGovernanceAccessRequest(context.Background(), "req1")
	require.Error(t, err)
	assert.Nil(t, res)
}

func TestAgenticResolveGovernanceAccessRequestSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/agentic/governance/requests/resolve", r.URL.Path)
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{"id": "req1", "action": "approve", "resolutionNote": "ok"}, req)
	}, governanceAccessRequestResponse))
	res, err := mgmt.Agentic().ResolveGovernanceAccessRequest(context.Background(), "req1", descope.GovernanceAccessRequestActionApprove, "ok")
	require.NoError(t, err)
	assertGovernanceAccessRequest(t, res)
}

func TestAgenticResolveGovernanceAccessRequestNoNote(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{"id": "req1", "action": "deny"}, req)
	}, governanceAccessRequestResponse))
	res, err := mgmt.Agentic().ResolveGovernanceAccessRequest(context.Background(), "req1", descope.GovernanceAccessRequestActionDeny, "")
	require.NoError(t, err)
	require.NotNil(t, res)
}

func TestAgenticResolveGovernanceAccessRequestError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) { called = true }))
	res, err := mgmt.Agentic().ResolveGovernanceAccessRequest(context.Background(), "", descope.GovernanceAccessRequestActionApprove, "")
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.Nil(t, res)
	res, err = mgmt.Agentic().ResolveGovernanceAccessRequest(context.Background(), "req1", "", "")
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.Nil(t, res)
	assert.False(t, called)

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err = mgmt.Agentic().ResolveGovernanceAccessRequest(context.Background(), "req1", descope.GovernanceAccessRequestActionApprove, "")
	require.Error(t, err)
	assert.Nil(t, res)
}

func TestAgenticCreateGovernanceAccessRequestSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/agentic/governance/requests/create", r.URL.Path)
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{
			"requestorUserId": "user1",
			"clientName":      "my-agent",
			"clientType":      "agent",
			"grantTypes":      []any{"clientCredentials"},
			"targets": []any{map[string]any{
				"name":      "api",
				"kind":      "resource",
				"scopes":    []any{"read"},
				"allScopes": true,
			}},
			"scopes":        []any{"s1"},
			"justification": "need it",
		}, req)
	}, governanceAccessRequestResponse))
	res, err := mgmt.Agentic().CreateGovernanceAccessRequest(context.Background(), &descope.GovernanceAccessRequestCreateOptions{
		RequestorUserID: "user1",
		ClientName:      "my-agent",
		ClientType:      "agent",
		GrantTypes:      []string{"clientCredentials"},
		Targets:         []*descope.GovernanceAccessRequestTarget{{Name: "api", Kind: "resource", Scopes: []string{"read"}, AllScopes: true}},
		Scopes:          []string{"s1"},
		Justification:   "need it",
	})
	require.NoError(t, err)
	assertGovernanceAccessRequest(t, res)
}

func TestAgenticCreateGovernanceAccessRequestError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) { called = true }))
	res, err := mgmt.Agentic().CreateGovernanceAccessRequest(context.Background(), nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.Nil(t, res)
	res, err = mgmt.Agentic().CreateGovernanceAccessRequest(context.Background(), &descope.GovernanceAccessRequestCreateOptions{})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.Nil(t, res)
	res, err = mgmt.Agentic().CreateGovernanceAccessRequest(context.Background(), &descope.GovernanceAccessRequestCreateOptions{
		RequestorUserID: "user1",
		GrantTypes:      []string{"authCode", ""},
	})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.Nil(t, res)
	assert.False(t, called)

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err = mgmt.Agentic().CreateGovernanceAccessRequest(context.Background(), &descope.GovernanceAccessRequestCreateOptions{RequestorUserID: "user1"})
	require.Error(t, err)
	assert.Nil(t, res)
}
