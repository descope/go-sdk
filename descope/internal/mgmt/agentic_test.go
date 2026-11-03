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

var governanceAccessRequestResponse = map[string]any{
	"id":               "gar1",
	"requestorUserId":  "u1",
	"requestorName":    "User One",
	"clientType":       "agent",
	"grantTypes":       []string{"authCode"},
	"targets":          []map[string]any{{"name": "res1", "kind": "resource", "targetId": "t1", "scopes": []string{"read"}, "allScopes": true}},
	"scopes":           []string{"s1"},
	"justification":    "need it",
	"status":           "approved",
	"resolvedByUserId": "",
	"resolvedByName":   "Management API",
	"resolutionNote":   "ok",
	"clientId":         "c1",
	"clientAppId":      "app1",
	"createdTime":      "100",
	"modifiedTime":     "200",
	"version":          "3",
	"clientName":       "my agent",
	"clientDeleted":    true,
}

func assertGovernanceAccessRequest(t *testing.T, res *descope.GovernanceAccessRequest) {
	require.NotNil(t, res)
	assert.Equal(t, "gar1", res.ID)
	assert.Equal(t, "u1", res.RequestorUserID)
	assert.Equal(t, "User One", res.RequestorName)
	assert.Equal(t, "agent", res.ClientType)
	assert.Equal(t, []string{"authCode"}, res.GrantTypes)
	require.Len(t, res.Targets, 1)
	assert.Equal(t, &descope.GovernanceAccessRequestTarget{Name: "res1", Kind: "resource", TargetID: "t1", Scopes: []string{"read"}, AllScopes: true}, res.Targets[0])
	assert.Equal(t, []string{"s1"}, res.Scopes)
	assert.Equal(t, "need it", res.Justification)
	assert.Equal(t, "approved", res.Status)
	assert.Equal(t, "", res.ResolvedByUserID)
	assert.Equal(t, "Management API", res.ResolvedByName)
	assert.Equal(t, "ok", res.ResolutionNote)
	assert.Equal(t, "c1", res.ClientID)
	assert.Equal(t, "app1", res.ClientAppID)
	assert.EqualValues(t, 100, res.CreatedTime)
	assert.EqualValues(t, 200, res.ModifiedTime)
	assert.Equal(t, "my agent", res.ClientName)
	assert.True(t, res.ClientDeleted)
}

func TestAgenticSearchIdentitiesSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/agentic/identities/search", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{"userId": "u1", "clientId": "c1", "resourceId": "r1", "consentId": "cs1", "page": float64(1), "limit": float64(2)}, req)
	}, map[string]any{
		"identities": []map[string]any{{
			"consent":    map[string]any{"id": "cs1", "appId": "app1", "userId": "u1", "scopes": []string{"s1"}, "grantedBy": "g1", "createdTime": 1, "tenantId": "t1", "ExpireTime": 2, "modifiedTime": 3, "authMethod": "idJag"},
			"agentName":  "agent",
			"resourceId": "r1",
			"clientId":   "c1",
			"createdBy":  "u2",
		}},
		"total": 5,
	}))
	res, total, err := mgmt.Agentic().SearchIdentities(context.Background(), &descope.AgenticIdentitySearchOptions{UserID: "u1", ClientID: "c1", ResourceID: "r1", ConsentID: "cs1", Page: 1, Limit: 2})
	require.NoError(t, err)
	assert.Equal(t, 5, total)
	require.Len(t, res, 1)
	assert.Equal(t, "agent", res[0].AgentName)
	assert.Equal(t, "r1", res[0].ResourceID)
	assert.Equal(t, "c1", res[0].ClientID)
	assert.Equal(t, "u2", res[0].CreatedBy)
	assert.Equal(t, &descope.ThirdPartyApplicationConsent{ID: "cs1", AppID: "app1", UserID: "u1", Scopes: []string{"s1"}, GrantedBy: "g1", CreatedTime: 1, TenantID: "t1", ExpireTime: 2, ModifiedTime: 3, AuthMethod: "idJag"}, res[0].Consent)
}

func TestAgenticSearchIdentitiesNilOptions(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Empty(t, req)
	}, map[string]any{"identities": []any{}, "total": 0}))
	res, total, err := mgmt.Agentic().SearchIdentities(context.Background(), nil)
	require.NoError(t, err)
	assert.Empty(t, res)
	assert.Zero(t, total)
}

func TestAgenticSearchIdentitiesError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, _, err := mgmt.Agentic().SearchIdentities(context.Background(), nil)
	require.Error(t, err)
	require.Nil(t, res)
}

func TestAgenticRevokeIdentitiesSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/agentic/identities/revoke", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{"userId": "u1", "clientId": "c1", "resourceId": "r1", "consentId": "cs1"}, req)
	}, map[string]any{"revoked": 3}))
	revoked, err := mgmt.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{UserID: "u1", ClientID: "c1", ResourceID: "r1", ConsentID: "cs1"})
	require.NoError(t, err)
	assert.Equal(t, 3, revoked)
}

func TestAgenticRevokeIdentitiesError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, err := mgmt.Agentic().RevokeIdentities(context.Background(), nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	_, err = mgmt.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	_, err = mgmt.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{UserID: "u1"})
	require.Error(t, err)
}

func TestAgenticGetGovernanceSettingsSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/v1/mgmt/agentic/governance/settings", r.URL.Path)
	}, map[string]any{"configured": true, "autoApproval": false, "suiteDisabled": true}))
	res, err := mgmt.Agentic().GetGovernanceSettings(context.Background())
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.True(t, *res.Configured)
	assert.False(t, *res.AutoApproval)
	assert.True(t, *res.SuiteDisabled)
}

func TestAgenticGetGovernanceSettingsError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.Agentic().GetGovernanceSettings(context.Background())
	require.Error(t, err)
	require.Nil(t, res)
}

func TestAgenticSetGovernanceSettingsSuccess(t *testing.T) {
	configured, autoApproval, suiteDisabled := true, true, false
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/agentic/governance/settings", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{"configured": true, "autoApproval": true, "suiteDisabled": false}, req)
	}, map[string]any{"configured": true, "autoApproval": true, "suiteDisabled": false}))
	res, err := mgmt.Agentic().SetGovernanceSettings(context.Background(), &descope.AgenticGovernanceSettings{Configured: &configured, AutoApproval: &autoApproval, SuiteDisabled: &suiteDisabled})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.True(t, *res.Configured)
	assert.True(t, *res.AutoApproval)
	assert.False(t, *res.SuiteDisabled)
}

func TestAgenticSetGovernanceSettingsPartial(t *testing.T) {
	autoApproval := true
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{"autoApproval": true}, req)
	}, map[string]any{"autoApproval": true}))
	res, err := mgmt.Agentic().SetGovernanceSettings(context.Background(), &descope.AgenticGovernanceSettings{AutoApproval: &autoApproval})
	require.NoError(t, err)
	assert.True(t, *res.AutoApproval)
	assert.Nil(t, res.Configured)
}

func TestAgenticSetGovernanceSettingsError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.Agentic().SetGovernanceSettings(context.Background(), nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	require.Nil(t, res)

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err = mgmt.Agentic().SetGovernanceSettings(context.Background(), &descope.AgenticGovernanceSettings{})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestAgenticSearchGovernanceAccessRequestsSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/agentic/governance/requests/search", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{
			"limit":        float64(10),
			"page":         float64(1),
			"searchFields": []any{map[string]any{"field": "status", "valArr": []any{"pending"}, "valStr": "x", "negative": true, "valType": "string"}},
			"sort":         []any{map[string]any{"field": "createdTime", "desc": true}},
			"text":         "agent",
		}, req)
	}, map[string]any{"requests": []any{governanceAccessRequestResponse}, "total": 7}))
	res, total, err := mgmt.Agentic().SearchGovernanceAccessRequests(context.Background(), &descope.GovernanceAccessRequestSearchOptions{
		Limit:        10,
		Page:         1,
		SearchFields: []*descope.GovernanceSearchField{{Field: "status", ValArr: []string{"pending"}, ValStr: "x", Negative: true, ValType: "string"}},
		Sort:         []*descope.GovernanceSort{{Field: "createdTime", Desc: true}},
		Text:         "agent",
	})
	require.NoError(t, err)
	assert.Equal(t, 7, total)
	require.Len(t, res, 1)
	assertGovernanceAccessRequest(t, res[0])
}

func TestAgenticSearchGovernanceAccessRequestsNilOptions(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Empty(t, req)
	}, map[string]any{"requests": []any{}, "total": 0}))
	res, total, err := mgmt.Agentic().SearchGovernanceAccessRequests(context.Background(), nil)
	require.NoError(t, err)
	assert.Empty(t, res)
	assert.Zero(t, total)
}

func TestAgenticSearchGovernanceAccessRequestsError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, _, err := mgmt.Agentic().SearchGovernanceAccessRequests(context.Background(), &descope.GovernanceAccessRequestSearchOptions{Sort: []*descope.GovernanceSort{{Desc: true}}})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	_, _, err = mgmt.Agentic().SearchGovernanceAccessRequests(context.Background(), &descope.GovernanceAccessRequestSearchOptions{Sort: []*descope.GovernanceSort{nil}})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, _, err := mgmt.Agentic().SearchGovernanceAccessRequests(context.Background(), nil)
	require.Error(t, err)
	require.Nil(t, res)
}

func TestAgenticGetGovernanceAccessRequestSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/agentic/governance/requests/get", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{"id": "gar1"}, req)
	}, governanceAccessRequestResponse))
	res, err := mgmt.Agentic().GetGovernanceAccessRequest(context.Background(), "gar1")
	require.NoError(t, err)
	assertGovernanceAccessRequest(t, res)
}

func TestAgenticGetGovernanceAccessRequestError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.Agentic().GetGovernanceAccessRequest(context.Background(), "")
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	require.Nil(t, res)

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err = mgmt.Agentic().GetGovernanceAccessRequest(context.Background(), "gar1")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestAgenticResolveGovernanceAccessRequestSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/agentic/governance/requests/resolve", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{"id": "gar1", "action": "approve", "resolutionNote": "ok"}, req)
	}, governanceAccessRequestResponse))
	res, err := mgmt.Agentic().ResolveGovernanceAccessRequest(context.Background(), "gar1", "approve", "ok")
	require.NoError(t, err)
	assertGovernanceAccessRequest(t, res)
}

func TestAgenticResolveGovernanceAccessRequestNoNote(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{"id": "gar1", "action": "deny"}, req)
	}, governanceAccessRequestResponse))
	_, err := mgmt.Agentic().ResolveGovernanceAccessRequest(context.Background(), "gar1", "deny", "")
	require.NoError(t, err)
}

func TestAgenticResolveGovernanceAccessRequestError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, err := mgmt.Agentic().ResolveGovernanceAccessRequest(context.Background(), "", "approve", "")
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	_, err = mgmt.Agentic().ResolveGovernanceAccessRequest(context.Background(), "gar1", "", "")
	require.ErrorIs(t, err, descope.ErrInvalidArguments)

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.Agentic().ResolveGovernanceAccessRequest(context.Background(), "gar1", "approve", "")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestAgenticCreateGovernanceAccessRequestSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/agentic/governance/requests/create", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{
			"requestorUserId": "u1",
			"clientName":      "my agent",
			"clientType":      "agent",
			"grantTypes":      []any{"authCode"},
			"targets":         []any{map[string]any{"name": "res1", "kind": "resource", "scopes": []any{"read"}, "allScopes": true}},
			"scopes":          []any{"s1"},
			"justification":   "need it",
		}, req)
	}, governanceAccessRequestResponse))
	res, err := mgmt.Agentic().CreateGovernanceAccessRequest(context.Background(), &descope.GovernanceAccessRequestCreate{
		RequestorUserID: "u1",
		ClientName:      "my agent",
		ClientType:      "agent",
		GrantTypes:      []string{"authCode"},
		Targets:         []*descope.GovernanceAccessRequestTarget{{Name: "res1", Kind: "resource", Scopes: []string{"read"}, AllScopes: true}},
		Scopes:          []string{"s1"},
		Justification:   "need it",
	})
	require.NoError(t, err)
	assertGovernanceAccessRequest(t, res)
}

func TestAgenticCreateGovernanceAccessRequestError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, err := mgmt.Agentic().CreateGovernanceAccessRequest(context.Background(), nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	_, err = mgmt.Agentic().CreateGovernanceAccessRequest(context.Background(), &descope.GovernanceAccessRequestCreate{})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	_, err = mgmt.Agentic().CreateGovernanceAccessRequest(context.Background(), &descope.GovernanceAccessRequestCreate{RequestorUserID: "u1", GrantTypes: []string{"authCode", ""}})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.Agentic().CreateGovernanceAccessRequest(context.Background(), &descope.GovernanceAccessRequestCreate{RequestorUserID: "u1"})
	require.Error(t, err)
	require.Nil(t, res)
}
