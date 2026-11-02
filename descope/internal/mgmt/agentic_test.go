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

var testGovernanceAccessRequestResponse = map[string]any{
	"id":              "req1",
	"requestorUserId": "U1",
	"requestorName":   "Dev",
	"clientType":      "agent",
	"grantTypes":      []string{"clientCredentials"},
	"targets": []map[string]any{
		{"name": "billing", "kind": "resource", "targetId": "res1", "scopes": []string{"read"}, "allScopes": true},
	},
	"scopes":           []string{"read"},
	"justification":    "needed",
	"status":           "approved",
	"resolvedByUserId": "",
	"resolvedByName":   "Management API",
	"resolutionNote":   "ok",
	"clientId":         "client1",
	"clientAppId":      "app1",
	"createdTime":      "1700000000000",
	"modifiedTime":     "1700000001000",
	"version":          "3",
	"clientName":       "My Agent",
	"clientDeleted":    true,
}

func requireGovernanceAccessRequest(t *testing.T, res *descope.GovernanceAccessRequest) {
	require.NotNil(t, res)
	assert.Equal(t, "req1", res.ID)
	assert.Equal(t, "U1", res.RequestorUserID)
	assert.Equal(t, "Dev", res.RequestorName)
	assert.Equal(t, "agent", res.ClientType)
	assert.Equal(t, []string{"clientCredentials"}, res.GrantTypes)
	require.Len(t, res.Targets, 1)
	assert.Equal(t, &descope.GovernanceAccessRequestTarget{Name: "billing", Kind: "resource", TargetID: "res1", Scopes: []string{"read"}, AllScopes: true}, res.Targets[0])
	assert.Equal(t, []string{"read"}, res.Scopes)
	assert.Equal(t, "needed", res.Justification)
	assert.Equal(t, descope.GovernanceAccessRequestStatusApproved, res.Status)
	assert.Equal(t, "", res.ResolvedByUserID)
	assert.Equal(t, "Management API", res.ResolvedByName)
	assert.Equal(t, "ok", res.ResolutionNote)
	assert.Equal(t, "client1", res.ClientID)
	assert.Equal(t, "app1", res.ClientAppID)
	assert.EqualValues(t, 1700000000000, res.CreatedTime)
	assert.EqualValues(t, 1700000001000, res.ModifiedTime)
	assert.EqualValues(t, 3, res.Version)
	assert.Equal(t, "My Agent", res.ClientName)
	assert.True(t, res.ClientDeleted)
}

func TestAgenticSearchIdentitiesSuccess(t *testing.T) {
	response := map[string]any{
		"identities": []map[string]any{{
			"consent": map[string]any{
				"id": "c1", "appId": "app1", "userId": "U1", "scopes": []string{"read"}, "grantedBy": "U2",
				"createdTime": 10, "tenantId": "t1", "ExpireTime": 20, "modifiedTime": 30, "authMethod": "idJag",
			},
			"agentName":  "agent",
			"resourceId": "res1",
			"clientId":   "client1",
			"createdBy":  "U2",
		}},
		"total": 7,
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/agentic/identities/search", r.URL.Path)
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{
			"userId": "U1", "clientId": "client1", "resourceId": "res1", "consentId": "c1", "page": float64(1), "limit": float64(10),
		}, req)
	}, response))
	res, total, err := mgmt.Agentic().SearchIdentities(context.Background(), &descope.AgenticIdentitySearchOptions{
		UserID: "U1", ClientID: "client1", ResourceID: "res1", ConsentID: "c1", Page: 1, Limit: 10,
	})
	require.NoError(t, err)
	assert.Equal(t, 7, total)
	require.Len(t, res, 1)
	assert.Equal(t, "agent", res[0].AgentName)
	assert.Equal(t, "res1", res[0].ResourceID)
	assert.Equal(t, "client1", res[0].ClientID)
	assert.Equal(t, "U2", res[0].CreatedBy)
	require.NotNil(t, res[0].Consent)
	assert.Equal(t, &descope.ThirdPartyApplicationConsent{
		ID: "c1", AppID: "app1", UserID: "U1", Scopes: []string{"read"}, GrantedBy: "U2",
		CreatedTime: 10, TenantID: "t1", ExpireTime: 20, ModifiedTime: 30, AuthMethod: "idJag",
	}, res[0].Consent)
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
	assert.Equal(t, 0, total)
}

func TestAgenticSearchIdentitiesError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	_, _, err := mgmt.Agentic().SearchIdentities(context.Background(), nil)
	require.Error(t, err)

	mgmt = newTestMgmt(nil, helpers.DoOkWithBody(nil, "invalid"))
	_, _, err = mgmt.Agentic().SearchIdentities(context.Background(), nil)
	require.Error(t, err)
}

func TestAgenticRevokeIdentitiesSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/agentic/identities/revoke", r.URL.Path)
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{"userId": "U1", "clientId": "client1", "resourceId": "res1", "consentId": "c1"}, req)
	}, map[string]any{"revoked": 3}))
	revoked, err := mgmt.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{
		UserID: "U1", ClientID: "client1", ResourceID: "res1", ConsentID: "c1",
	})
	require.NoError(t, err)
	assert.Equal(t, 3, revoked)
}

func TestAgenticRevokeIdentitiesError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) { called = true }))
	_, err := mgmt.Agentic().RevokeIdentities(context.Background(), nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.False(t, called)

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	_, err = mgmt.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{UserID: "U1"})
	require.Error(t, err)

	mgmt = newTestMgmt(nil, helpers.DoOkWithBody(nil, "invalid"))
	_, err = mgmt.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{UserID: "U1"})
	require.Error(t, err)
}

func TestAgenticGetGovernanceSettingsSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/v1/mgmt/agentic/governance/settings", r.URL.Path)
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
	}, map[string]any{"configured": true, "autoApproval": false, "suiteDisabled": true}))
	res, err := mgmt.Agentic().GetGovernanceSettings(context.Background())
	require.NoError(t, err)
	require.NotNil(t, res.Configured)
	assert.True(t, *res.Configured)
	require.NotNil(t, res.AutoApproval)
	assert.False(t, *res.AutoApproval)
	require.NotNil(t, res.SuiteDisabled)
	assert.True(t, *res.SuiteDisabled)
}

func TestAgenticGetGovernanceSettingsError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	_, err := mgmt.Agentic().GetGovernanceSettings(context.Background())
	require.Error(t, err)

	mgmt = newTestMgmt(nil, helpers.DoOkWithBody(nil, "invalid"))
	_, err = mgmt.Agentic().GetGovernanceSettings(context.Background())
	require.Error(t, err)
}

func TestAgenticSetGovernanceSettingsSuccess(t *testing.T) {
	enabled := true
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/agentic/governance/settings", r.URL.Path)
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		// only the set field is sent
		assert.EqualValues(t, map[string]any{"autoApproval": true}, req)
	}, map[string]any{"configured": true, "autoApproval": true, "suiteDisabled": false}))
	res, err := mgmt.Agentic().SetGovernanceSettings(context.Background(), &descope.AgenticGovernanceSettings{AutoApproval: &enabled})
	require.NoError(t, err)
	require.NotNil(t, res.Configured)
	assert.True(t, *res.Configured)
	require.NotNil(t, res.AutoApproval)
	assert.True(t, *res.AutoApproval)
	require.NotNil(t, res.SuiteDisabled)
	assert.False(t, *res.SuiteDisabled)
}

func TestAgenticSetGovernanceSettingsError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) { called = true }))
	_, err := mgmt.Agentic().SetGovernanceSettings(context.Background(), nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.False(t, called)

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	_, err = mgmt.Agentic().SetGovernanceSettings(context.Background(), &descope.AgenticGovernanceSettings{})
	require.Error(t, err)
}

func TestAgenticSearchGovernanceAccessRequestsSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/agentic/governance/requests/search", r.URL.Path)
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{
			"searchFields": []any{map[string]any{"field": "status", "valArr": []any{"pending"}, "valStr": "x", "negative": true, "valType": "string"}},
			"sort":         []any{map[string]any{"field": "createdTime", "desc": true}},
			"text":         "billing",
			"page":         float64(1),
			"limit":        float64(5),
		}, req)
	}, map[string]any{"requests": []any{testGovernanceAccessRequestResponse}, "total": 9}))
	res, total, err := mgmt.Agentic().SearchGovernanceAccessRequests(context.Background(), &descope.GovernanceAccessRequestSearchOptions{
		SearchFields: []*descope.GovernanceAccessRequestSearchField{{Field: "status", ValArr: []string{"pending"}, ValStr: "x", Negative: true, ValType: "string"}},
		Sort:         []*descope.GovernanceAccessRequestSort{{Field: "createdTime", Desc: true}},
		Text:         "billing",
		Page:         1,
		Limit:        5,
	})
	require.NoError(t, err)
	assert.Equal(t, 9, total)
	require.Len(t, res, 1)
	requireGovernanceAccessRequest(t, res[0])
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
	assert.Equal(t, 0, total)
}

func TestAgenticSearchGovernanceAccessRequestsError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) { called = true }))
	_, _, err := mgmt.Agentic().SearchGovernanceAccessRequests(context.Background(), &descope.GovernanceAccessRequestSearchOptions{
		Sort: []*descope.GovernanceAccessRequestSort{{Field: "createdTime"}, {Desc: true}},
	})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	_, _, err = mgmt.Agentic().SearchGovernanceAccessRequests(context.Background(), &descope.GovernanceAccessRequestSearchOptions{
		Sort: []*descope.GovernanceAccessRequestSort{nil},
	})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.False(t, called)

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	_, _, err = mgmt.Agentic().SearchGovernanceAccessRequests(context.Background(), nil)
	require.Error(t, err)

	mgmt = newTestMgmt(nil, helpers.DoOkWithBody(nil, "invalid"))
	_, _, err = mgmt.Agentic().SearchGovernanceAccessRequests(context.Background(), nil)
	require.Error(t, err)
}

func TestAgenticGetGovernanceAccessRequestSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/agentic/governance/requests/get", r.URL.Path)
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{"id": "req1"}, req)
	}, testGovernanceAccessRequestResponse))
	res, err := mgmt.Agentic().GetGovernanceAccessRequest(context.Background(), "req1")
	require.NoError(t, err)
	requireGovernanceAccessRequest(t, res)
}

func TestAgenticGetGovernanceAccessRequestError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) { called = true }))
	_, err := mgmt.Agentic().GetGovernanceAccessRequest(context.Background(), "")
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.False(t, called)

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	_, err = mgmt.Agentic().GetGovernanceAccessRequest(context.Background(), "req1")
	require.Error(t, err)

	mgmt = newTestMgmt(nil, helpers.DoOkWithBody(nil, "invalid"))
	_, err = mgmt.Agentic().GetGovernanceAccessRequest(context.Background(), "req1")
	require.Error(t, err)
}

func TestAgenticResolveGovernanceAccessRequestSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/agentic/governance/requests/resolve", r.URL.Path)
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{"id": "req1", "action": "approve", "resolutionNote": "ok"}, req)
	}, testGovernanceAccessRequestResponse))
	res, err := mgmt.Agentic().ResolveGovernanceAccessRequest(context.Background(), "req1", descope.GovernanceAccessRequestActionApprove, "ok")
	require.NoError(t, err)
	requireGovernanceAccessRequest(t, res)
}

func TestAgenticResolveGovernanceAccessRequestNoNote(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{"id": "req1", "action": "deny"}, req)
	}, testGovernanceAccessRequestResponse))
	_, err := mgmt.Agentic().ResolveGovernanceAccessRequest(context.Background(), "req1", descope.GovernanceAccessRequestActionDeny, "")
	require.NoError(t, err)
}

func TestAgenticResolveGovernanceAccessRequestError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) { called = true }))
	_, err := mgmt.Agentic().ResolveGovernanceAccessRequest(context.Background(), "", descope.GovernanceAccessRequestActionApprove, "")
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	_, err = mgmt.Agentic().ResolveGovernanceAccessRequest(context.Background(), "req1", "", "")
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.False(t, called)

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	_, err = mgmt.Agentic().ResolveGovernanceAccessRequest(context.Background(), "req1", descope.GovernanceAccessRequestActionApprove, "")
	require.Error(t, err)
}

func TestAgenticCreateGovernanceAccessRequestSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/agentic/governance/requests/create", r.URL.Path)
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{
			"requestorUserId": "U1",
			"clientName":      "My Agent",
			"clientType":      "agent",
			"grantTypes":      []any{"clientCredentials"},
			"targets":         []any{map[string]any{"name": "billing", "kind": "resource", "scopes": []any{"read"}, "allScopes": true}},
			"scopes":          []any{"read"},
			"justification":   "needed",
		}, req)
	}, testGovernanceAccessRequestResponse))
	res, err := mgmt.Agentic().CreateGovernanceAccessRequest(context.Background(), &descope.GovernanceAccessRequestCreate{
		RequestorUserID: "U1",
		ClientName:      "My Agent",
		ClientType:      "agent",
		GrantTypes:      []string{descope.GovernanceAccessRequestGrantTypeClientCredentials},
		Targets: []*descope.GovernanceAccessRequestTarget{
			{Name: "billing", Kind: descope.GovernanceAccessRequestTargetKindResource, Scopes: []string{"read"}, AllScopes: true},
		},
		Scopes:        []string{"read"},
		Justification: "needed",
	})
	require.NoError(t, err)
	requireGovernanceAccessRequest(t, res)
}

func TestAgenticCreateGovernanceAccessRequestError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) { called = true }))
	_, err := mgmt.Agentic().CreateGovernanceAccessRequest(context.Background(), nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	_, err = mgmt.Agentic().CreateGovernanceAccessRequest(context.Background(), &descope.GovernanceAccessRequestCreate{})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	_, err = mgmt.Agentic().CreateGovernanceAccessRequest(context.Background(), &descope.GovernanceAccessRequestCreate{
		RequestorUserID: "U1", GrantTypes: []string{descope.GovernanceAccessRequestGrantTypeAuthCode, ""},
	})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.False(t, called)

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	_, err = mgmt.Agentic().CreateGovernanceAccessRequest(context.Background(), &descope.GovernanceAccessRequestCreate{RequestorUserID: "U1"})
	require.Error(t, err)
}
