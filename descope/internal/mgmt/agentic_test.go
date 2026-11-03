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
	"id":               "req1",
	"requestorUserId":  "U1",
	"requestorName":    "Dev",
	"clientType":       "agent",
	"clientName":       "My Agent",
	"grantTypes":       []string{"authCode"},
	"targets":          []map[string]any{{"name": "api", "kind": "resource", "targetId": "res1", "scopes": []string{"read"}, "allScopes": true}},
	"scopes":           []string{"openid"},
	"justification":    "need it",
	"status":           "approved",
	"resolvedByUserId": "",
	"resolvedByName":   "Management API",
	"resolutionNote":   "ok",
	"clientId":         "client1",
	"clientAppId":      "app1",
	"clientDeleted":    true,
	"createdTime":      "1700000000",
	"modifiedTime":     "1700000001",
	"version":          "3",
}

func assertGovernanceAccessRequestResponse(t *testing.T, res *descope.GovernanceAccessRequest) {
	require.NotNil(t, res)
	assert.Equal(t, "req1", res.ID)
	assert.Equal(t, "U1", res.RequestorUserID)
	assert.Equal(t, "Dev", res.RequestorName)
	assert.Equal(t, "agent", res.ClientType)
	assert.Equal(t, "My Agent", res.ClientName)
	assert.Equal(t, []string{"authCode"}, res.GrantTypes)
	require.Len(t, res.Targets, 1)
	assert.Equal(t, &descope.GovernanceAccessRequestTarget{Name: "api", Kind: "resource", TargetID: "res1", Scopes: []string{"read"}, AllScopes: true}, res.Targets[0])
	assert.Equal(t, []string{"openid"}, res.Scopes)
	assert.Equal(t, "need it", res.Justification)
	assert.Equal(t, "approved", res.Status)
	assert.Equal(t, "", res.ResolvedByUserID)
	assert.Equal(t, "Management API", res.ResolvedByName)
	assert.Equal(t, "ok", res.ResolutionNote)
	assert.Equal(t, "client1", res.ClientID)
	assert.Equal(t, "app1", res.ClientAppID)
	assert.True(t, res.ClientDeleted)
	assert.EqualValues(t, 1700000000, res.CreatedTime)
	assert.EqualValues(t, 1700000000, res.GetCreatedTime().Unix())
	assert.EqualValues(t, 1700000001, res.ModifiedTime)
	assert.EqualValues(t, 3, res.Version)
}

func TestAgenticSearchIdentitiesSuccess(t *testing.T) {
	response := map[string]any{
		"identities": []map[string]any{{
			"consent": map[string]any{
				"id": "cons1", "appId": "app1", "userId": "U1", "scopes": []string{"read"}, "grantedBy": "U2",
				"createdTime": 10, "tenantId": "t1", "ExpireTime": 20, "modifiedTime": 30, "authMethod": "idJag",
			},
			"agentName":  "agent",
			"resourceId": "res1",
			"clientId":   "client1",
			"createdBy":  "U3",
		}},
		"total": 7,
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/agentic/identities/search", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{"userId": "U1", "clientId": "client1", "resourceId": "res1", "consentId": "cons1", "page": float64(1), "limit": float64(5)}, req)
	}, response))
	res, total, err := mgmt.Agentic().SearchIdentities(context.Background(), &descope.AgenticIdentitySearchOptions{
		UserID: "U1", ClientID: "client1", ResourceID: "res1", ConsentID: "cons1", Page: 1, Limit: 5,
	})
	require.NoError(t, err)
	assert.Equal(t, 7, total)
	require.Len(t, res, 1)
	assert.Equal(t, "agent", res[0].AgentName)
	assert.Equal(t, "res1", res[0].ResourceID)
	assert.Equal(t, "client1", res[0].ClientID)
	assert.Equal(t, "U3", res[0].CreatedBy)
	assert.Equal(t, &descope.ThirdPartyApplicationConsent{
		ID: "cons1", AppID: "app1", UserID: "U1", Scopes: []string{"read"}, GrantedBy: "U2",
		CreatedTime: 10, TenantID: "t1", ExpireTime: 20, ModifiedTime: 30, AuthMethod: "idJag",
	}, res[0].Consent)
}

func TestAgenticSearchIdentitiesNilOptionsSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{"userId": "", "clientId": "", "resourceId": "", "consentId": "", "page": float64(0), "limit": float64(0)}, req)
	}, map[string]any{"identities": []any{map[string]any{"consent": nil}}, "total": 1}))
	res, total, err := mgmt.Agentic().SearchIdentities(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	require.Len(t, res, 1)
	assert.Nil(t, res[0].Consent)
}

func TestAgenticSearchIdentitiesError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, total, err := mgmt.Agentic().SearchIdentities(context.Background(), nil)
	require.Error(t, err)
	assert.Nil(t, res)
	assert.Zero(t, total)
}

func TestAgenticSearchIdentitiesBadResponse(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(nil, map[string]any{"total": "x"}))
	_, _, err := mgmt.Agentic().SearchIdentities(context.Background(), nil)
	require.Error(t, err)
}

func TestAgenticRevokeIdentitiesSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/agentic/identities/revoke", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{"userId": "U1", "clientId": "client1", "resourceId": "res1", "consentId": "cons1"}, req)
	}, map[string]any{"revoked": 3}))
	revoked, err := mgmt.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{
		UserID: "U1", ClientID: "client1", ResourceID: "res1", ConsentID: "cons1",
	})
	require.NoError(t, err)
	assert.Equal(t, 3, revoked)
}

func TestAgenticRevokeIdentitiesMissingArguments(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		assert.Fail(t, "should not send a request")
	}))
	_, err := mgmt.Agentic().RevokeIdentities(context.Background(), nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	_, err = mgmt.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
}

func TestAgenticRevokeIdentitiesError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	revoked, err := mgmt.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{UserID: "U1"})
	require.Error(t, err)
	assert.Zero(t, revoked)
}

func TestAgenticRevokeIdentitiesBadResponse(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(nil, map[string]any{"revoked": "x"}))
	_, err := mgmt.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{UserID: "U1"})
	require.Error(t, err)
}

func TestAgenticGetGovernanceSettingsSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/v1/mgmt/agentic/governance/settings", r.URL.Path)
	}, map[string]any{"configured": true, "autoApproval": true, "suiteDisabled": true}))
	res, err := mgmt.Agentic().GetGovernanceSettings(context.Background())
	require.NoError(t, err)
	assert.Equal(t, &descope.AgenticGovernanceSettings{Configured: true, AutoApproval: true, SuiteDisabled: true}, res)
}

func TestAgenticGetGovernanceSettingsError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.Agentic().GetGovernanceSettings(context.Background())
	require.Error(t, err)
	assert.Nil(t, res)
}

func TestAgenticGetGovernanceSettingsBadResponse(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(nil, map[string]any{"configured": "x"}))
	res, err := mgmt.Agentic().GetGovernanceSettings(context.Background())
	require.Error(t, err)
	assert.Nil(t, res)
}

func TestAgenticConfigureGovernanceSettingsSuccess(t *testing.T) {
	configured := true
	autoApproval := false
	suiteDisabled := true
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/agentic/governance/settings", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{"configured": true, "autoApproval": false, "suiteDisabled": true}, req)
	}, map[string]any{"configured": true, "autoApproval": false, "suiteDisabled": true}))
	res, err := mgmt.Agentic().ConfigureGovernanceSettings(context.Background(), &descope.AgenticGovernanceSettingsRequest{
		Configured: &configured, AutoApproval: &autoApproval, SuiteDisabled: &suiteDisabled,
	})
	require.NoError(t, err)
	assert.Equal(t, &descope.AgenticGovernanceSettings{Configured: true, SuiteDisabled: true}, res)
}

func TestAgenticConfigureGovernanceSettingsPartialSuccess(t *testing.T) {
	autoApproval := true
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{"autoApproval": true}, req)
	}, map[string]any{"autoApproval": true}))
	res, err := mgmt.Agentic().ConfigureGovernanceSettings(context.Background(), &descope.AgenticGovernanceSettingsRequest{AutoApproval: &autoApproval})
	require.NoError(t, err)
	assert.Equal(t, &descope.AgenticGovernanceSettings{AutoApproval: true}, res)
}

func TestAgenticConfigureGovernanceSettingsMissingArguments(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		assert.Fail(t, "should not send a request")
	}))
	res, err := mgmt.Agentic().ConfigureGovernanceSettings(context.Background(), nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.Nil(t, res)
}

func TestAgenticConfigureGovernanceSettingsError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.Agentic().ConfigureGovernanceSettings(context.Background(), &descope.AgenticGovernanceSettingsRequest{})
	require.Error(t, err)
	assert.Nil(t, res)
}

func TestAgenticSearchGovernanceAccessRequestsSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/agentic/governance/requests/search", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{
			"text":         "agent",
			"searchFields": []any{map[string]any{"field": "status", "valArr": []any{"pending"}, "valStr": "x", "negative": true, "valType": "string"}},
			"sort":         []any{map[string]any{"field": "createdTime", "desc": true}},
			"page":         float64(1),
			"limit":        float64(5),
		}, req)
	}, map[string]any{"requests": []any{governanceAccessRequestResponse}, "total": 9}))
	res, total, err := mgmt.Agentic().SearchGovernanceAccessRequests(context.Background(), &descope.GovernanceAccessRequestSearchOptions{
		Text:         "agent",
		SearchFields: []descope.GovernanceAccessRequestSearchField{{Field: "status", ValArr: []string{"pending"}, ValStr: "x", Negative: true, ValType: "string"}},
		Sort:         []descope.GovernanceAccessRequestSort{{Field: "createdTime", Desc: true}},
		Page:         1,
		Limit:        5,
	})
	require.NoError(t, err)
	assert.Equal(t, 9, total)
	require.Len(t, res, 1)
	assertGovernanceAccessRequestResponse(t, res[0])
}

func TestAgenticSearchGovernanceAccessRequestsNilOptionsSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{"page": float64(0), "limit": float64(0)}, req)
	}, map[string]any{"requests": []any{}, "total": 0}))
	res, total, err := mgmt.Agentic().SearchGovernanceAccessRequests(context.Background(), nil)
	require.NoError(t, err)
	assert.Zero(t, total)
	assert.Empty(t, res)
}

func TestAgenticSearchGovernanceAccessRequestsMissingArguments(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		assert.Fail(t, "should not send a request")
	}))
	res, _, err := mgmt.Agentic().SearchGovernanceAccessRequests(context.Background(), &descope.GovernanceAccessRequestSearchOptions{
		Sort: []descope.GovernanceAccessRequestSort{{Field: "status"}, {Desc: true}},
	})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.Nil(t, res)
}

func TestAgenticSearchGovernanceAccessRequestsError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, total, err := mgmt.Agentic().SearchGovernanceAccessRequests(context.Background(), nil)
	require.Error(t, err)
	assert.Nil(t, res)
	assert.Zero(t, total)
}

func TestAgenticSearchGovernanceAccessRequestsBadResponse(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(nil, map[string]any{"total": "x"}))
	_, _, err := mgmt.Agentic().SearchGovernanceAccessRequests(context.Background(), nil)
	require.Error(t, err)
}

func TestAgenticGetGovernanceAccessRequestSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/agentic/governance/requests/get", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{"id": "req1"}, req)
	}, governanceAccessRequestResponse))
	res, err := mgmt.Agentic().GetGovernanceAccessRequest(context.Background(), "req1")
	require.NoError(t, err)
	assertGovernanceAccessRequestResponse(t, res)
}

func TestAgenticGetGovernanceAccessRequestNumericTimesSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(nil, map[string]any{"id": "req1", "createdTime": 5, "modifiedTime": 6, "version": 7}))
	res, err := mgmt.Agentic().GetGovernanceAccessRequest(context.Background(), "req1")
	require.NoError(t, err)
	assert.EqualValues(t, 5, res.CreatedTime)
	assert.EqualValues(t, 6, res.ModifiedTime)
	assert.EqualValues(t, 7, res.Version)
}

func TestAgenticGetGovernanceAccessRequestMissingFieldsSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(nil, map[string]any{"id": "req1", "targets": nil}))
	res, err := mgmt.Agentic().GetGovernanceAccessRequest(context.Background(), "req1")
	require.NoError(t, err)
	assert.Equal(t, &descope.GovernanceAccessRequest{ID: "req1"}, res)
}

func TestAgenticGetGovernanceAccessRequestMissingArguments(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		assert.Fail(t, "should not send a request")
	}))
	res, err := mgmt.Agentic().GetGovernanceAccessRequest(context.Background(), "")
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.Nil(t, res)
}

func TestAgenticGetGovernanceAccessRequestError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.Agentic().GetGovernanceAccessRequest(context.Background(), "req1")
	require.Error(t, err)
	assert.Nil(t, res)
}

func TestAgenticGetGovernanceAccessRequestBadResponse(t *testing.T) {
	for _, body := range []map[string]any{
		{"id": 1},
		{"createdTime": "x"},
		{"createdTime": 1.5},
		{"modifiedTime": 1.5},
		{"version": 1.5},
	} {
		mgmt := newTestMgmt(nil, helpers.DoOkWithBody(nil, body))
		res, err := mgmt.Agentic().GetGovernanceAccessRequest(context.Background(), "req1")
		require.Error(t, err, body)
		assert.Nil(t, res)
	}
}

func TestAgenticResolveGovernanceAccessRequestSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/agentic/governance/requests/resolve", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{"id": "req1", "action": "approve", "resolutionNote": "ok"}, req)
	}, governanceAccessRequestResponse))
	res, err := mgmt.Agentic().ResolveGovernanceAccessRequest(context.Background(), "req1", descope.GovernanceAccessRequestActionApprove, "ok")
	require.NoError(t, err)
	assertGovernanceAccessRequestResponse(t, res)
}

func TestAgenticResolveGovernanceAccessRequestNoNoteSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{"id": "req1", "action": "deny"}, req)
	}, governanceAccessRequestResponse))
	res, err := mgmt.Agentic().ResolveGovernanceAccessRequest(context.Background(), "req1", descope.GovernanceAccessRequestActionDeny, "")
	require.NoError(t, err)
	require.NotNil(t, res)
}

func TestAgenticResolveGovernanceAccessRequestMissingArguments(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		assert.Fail(t, "should not send a request")
	}))
	res, err := mgmt.Agentic().ResolveGovernanceAccessRequest(context.Background(), "", descope.GovernanceAccessRequestActionApprove, "")
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.Nil(t, res)
	res, err = mgmt.Agentic().ResolveGovernanceAccessRequest(context.Background(), "req1", "", "")
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.Nil(t, res)
}

func TestAgenticResolveGovernanceAccessRequestError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.Agentic().ResolveGovernanceAccessRequest(context.Background(), "req1", descope.GovernanceAccessRequestActionApprove, "")
	require.Error(t, err)
	assert.Nil(t, res)
}

func TestAgenticCreateGovernanceAccessRequestSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/agentic/governance/requests/create", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{
			"requestorUserId": "U1",
			"clientName":      "My Agent",
			"clientType":      "agent",
			"grantTypes":      []any{"authCode", "clientCredentials"},
			"targets":         []any{map[string]any{"name": "api", "kind": "resource", "scopes": []any{"read"}}},
			"scopes":          []any{"openid"},
			"justification":   "need it",
		}, req)
	}, governanceAccessRequestResponse))
	res, err := mgmt.Agentic().CreateGovernanceAccessRequest(context.Background(), &descope.GovernanceAccessRequestCreateRequest{
		RequestorUserID: "U1",
		ClientName:      "My Agent",
		ClientType:      "agent",
		GrantTypes:      []string{"authCode", "clientCredentials"},
		Targets:         []*descope.GovernanceAccessRequestTarget{{Name: "api", Kind: "resource", Scopes: []string{"read"}}},
		Scopes:          []string{"openid"},
		Justification:   "need it",
	})
	require.NoError(t, err)
	assertGovernanceAccessRequestResponse(t, res)
}

func TestAgenticCreateGovernanceAccessRequestMinimalSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{"requestorUserId": "U1"}, req)
	}, governanceAccessRequestResponse))
	res, err := mgmt.Agentic().CreateGovernanceAccessRequest(context.Background(), &descope.GovernanceAccessRequestCreateRequest{RequestorUserID: "U1"})
	require.NoError(t, err)
	require.NotNil(t, res)
}

func TestAgenticCreateGovernanceAccessRequestMissingArguments(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		assert.Fail(t, "should not send a request")
	}))
	res, err := mgmt.Agentic().CreateGovernanceAccessRequest(context.Background(), nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.Nil(t, res)
	res, err = mgmt.Agentic().CreateGovernanceAccessRequest(context.Background(), &descope.GovernanceAccessRequestCreateRequest{})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.Nil(t, res)
	res, err = mgmt.Agentic().CreateGovernanceAccessRequest(context.Background(), &descope.GovernanceAccessRequestCreateRequest{
		RequestorUserID: "U1",
		GrantTypes:      []string{"authCode", ""},
	})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.Nil(t, res)
}

func TestAgenticCreateGovernanceAccessRequestError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.Agentic().CreateGovernanceAccessRequest(context.Background(), &descope.GovernanceAccessRequestCreateRequest{RequestorUserID: "U1"})
	require.Error(t, err)
	assert.Nil(t, res)
}
