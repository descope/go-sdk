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

func boolPtr(b bool) *bool {
	return &b
}

var governanceAccessRequestResponse = map[string]any{
	"id":              "req1",
	"requestorUserId": "U1",
	"requestorName":   "Dev",
	"clientType":      "agent",
	"grantTypes":      []string{"authCode"},
	"targets": []map[string]any{{
		"name":      "api",
		"kind":      "resource",
		"targetId":  "res1",
		"scopes":    []string{"read"},
		"allScopes": true,
	}},
	"scopes":           []string{"read"},
	"justification":    "need it",
	"status":           "approved",
	"resolvedByUserId": "U2",
	"resolvedByName":   "Admin",
	"resolutionNote":   "ok",
	"clientId":         "client1",
	"clientAppId":      "app1",
	"createdTime":      "1700000000000",
	"modifiedTime":     1700000001000,
	"version":          "4",
	"clientName":       "My Agent",
	"clientDeleted":    true,
}

func assertGovernanceAccessRequest(t *testing.T, r *descope.GovernanceAccessRequest) {
	require.NotNil(t, r)
	assert.Equal(t, "req1", r.ID)
	assert.Equal(t, "U1", r.RequestorUserID)
	assert.Equal(t, "Dev", r.RequestorName)
	assert.Equal(t, "agent", r.ClientType)
	assert.Equal(t, []string{"authCode"}, r.GrantTypes)
	require.Len(t, r.Targets, 1)
	assert.Equal(t, &descope.GovernanceAccessRequestTarget{Name: "api", Kind: "resource", TargetID: "res1", Scopes: []string{"read"}, AllScopes: true}, r.Targets[0])
	assert.Equal(t, []string{"read"}, r.Scopes)
	assert.Equal(t, "need it", r.Justification)
	assert.Equal(t, "approved", r.Status)
	assert.Equal(t, "U2", r.ResolvedByUserID)
	assert.Equal(t, "Admin", r.ResolvedByName)
	assert.Equal(t, "ok", r.ResolutionNote)
	assert.Equal(t, "client1", r.ClientID)
	assert.Equal(t, "app1", r.ClientAppID)
	assert.EqualValues(t, 1700000000000, r.CreatedTime)
	assert.EqualValues(t, 1700000001000, r.ModifiedTime)
	assert.EqualValues(t, 4, r.Version)
	assert.Equal(t, "My Agent", r.ClientName)
	assert.True(t, r.ClientDeleted)
}

func TestAgenticSearchIdentitiesSuccess(t *testing.T) {
	response := map[string]any{
		"identities": []map[string]any{{
			"consent": map[string]any{
				"id":           "c1",
				"appId":        "app1",
				"userId":       "U1",
				"scopes":       []string{"read"},
				"grantedBy":    "U1",
				"createdTime":  10,
				"tenantId":     "t1",
				"ExpireTime":   20,
				"modifiedTime": 30,
				"authMethod":   "idJag",
			},
			"agentName":  "agent",
			"resourceId": "res1",
			"clientId":   "client1",
			"createdBy":  "U1",
		}},
		"total": 1,
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, "/v1/mgmt/agentic/identities/search", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, map[string]any{
			"userId":     "U1",
			"clientId":   "client1",
			"resourceId": "res1",
			"consentId":  "c1",
			"page":       float64(1),
			"limit":      float64(10),
		}, req)
	}, response))
	res, total, err := mgmt.Agentic().SearchIdentities(context.Background(), &descope.AgenticIdentitySearchOptions{
		UserID: "U1", ClientID: "client1", ResourceID: "res1", ConsentID: "c1", Page: 1, Limit: 10,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	require.Len(t, res, 1)
	assert.Equal(t, &descope.AgenticIdentity{
		Consent: &descope.ThirdPartyApplicationConsent{
			ID: "c1", AppID: "app1", UserID: "U1", Scopes: []string{"read"}, GrantedBy: "U1",
			CreatedTime: 10, TenantID: "t1", ExpireTime: 20, ModifiedTime: 30, AuthMethod: "idJag",
		},
		AgentName:  "agent",
		ResourceID: "res1",
		ClientID:   "client1",
		CreatedBy:  "U1",
	}, res[0])
}

func TestAgenticSearchIdentitiesMinimal(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, map[string]any{"page": float64(0), "limit": float64(0)}, req)
	}, map[string]any{"identities": []any{map[string]any{"consent": nil}}, "total": 1}))
	res, total, err := mgmt.Agentic().SearchIdentities(context.Background(), &descope.AgenticIdentitySearchOptions{})
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	require.Len(t, res, 1)
	assert.Nil(t, res[0].Consent)
}

func TestAgenticSearchIdentitiesError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		require.Fail(t, "request should not be sent")
	}))
	_, _, err := mgmt.Agentic().SearchIdentities(context.Background(), nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, _, err := mgmt.Agentic().SearchIdentities(context.Background(), &descope.AgenticIdentitySearchOptions{})
	require.Error(t, err)
	assert.Nil(t, res)
}

func TestAgenticRevokeIdentitiesSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, "/v1/mgmt/agentic/identities/revoke", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, map[string]any{
			"userId":     "U1",
			"clientId":   "client1",
			"resourceId": "res1",
			"consentId":  "c1",
		}, req)
	}, map[string]any{"revoked": 3}))
	revoked, err := mgmt.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{
		UserID: "U1", ClientID: "client1", ResourceID: "res1", ConsentID: "c1",
	})
	require.NoError(t, err)
	assert.Equal(t, 3, revoked)
}

func TestAgenticRevokeIdentitiesOnlyUser(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, map[string]any{"userId": "U1"}, req)
	}, map[string]any{"revoked": 1}))
	revoked, err := mgmt.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{UserID: "U1"})
	require.NoError(t, err)
	assert.Equal(t, 1, revoked)
}

func TestAgenticRevokeIdentitiesError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		require.Fail(t, "request should not be sent")
	}))
	_, err := mgmt.Agentic().RevokeIdentities(context.Background(), nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	_, err = mgmt.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{UserID: "U1"})
	require.Error(t, err)
}

func TestAgenticGetGovernanceSettingsSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, "/v1/mgmt/agentic/governance/settings", r.URL.Path)
		assert.Empty(t, r.URL.RawQuery)
	}, map[string]any{"configured": true, "autoApproval": false, "suiteDisabled": true}))
	res, err := mgmt.Agentic().GetGovernanceSettings(context.Background())
	require.NoError(t, err)
	assert.Equal(t, &descope.AgenticGovernanceSettings{
		Configured:    boolPtr(true),
		AutoApproval:  boolPtr(false),
		SuiteDisabled: boolPtr(true),
	}, res)
}

func TestAgenticGetGovernanceSettingsEmpty(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.Agentic().GetGovernanceSettings(context.Background())
	require.NoError(t, err)
	assert.Equal(t, &descope.AgenticGovernanceSettings{}, res)
}

func TestAgenticGetGovernanceSettingsError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.Agentic().GetGovernanceSettings(context.Background())
	require.Error(t, err)
	assert.Nil(t, res)
}

func TestAgenticSetGovernanceSettingsSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, "/v1/mgmt/agentic/governance/settings", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, map[string]any{"configured": true, "autoApproval": false, "suiteDisabled": true}, req)
	}, map[string]any{"configured": true, "autoApproval": false, "suiteDisabled": true}))
	res, err := mgmt.Agentic().SetGovernanceSettings(context.Background(), &descope.AgenticGovernanceSettings{
		Configured:    boolPtr(true),
		AutoApproval:  boolPtr(false),
		SuiteDisabled: boolPtr(true),
	})
	require.NoError(t, err)
	assert.Equal(t, &descope.AgenticGovernanceSettings{
		Configured:    boolPtr(true),
		AutoApproval:  boolPtr(false),
		SuiteDisabled: boolPtr(true),
	}, res)
}

func TestAgenticSetGovernanceSettingsPartial(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, map[string]any{"autoApproval": false}, req)
	}, map[string]any{"configured": true, "autoApproval": false, "suiteDisabled": false}))
	res, err := mgmt.Agentic().SetGovernanceSettings(context.Background(), &descope.AgenticGovernanceSettings{AutoApproval: boolPtr(false)})
	require.NoError(t, err)
	assert.False(t, *res.AutoApproval)
}

func TestAgenticSetGovernanceSettingsError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		require.Fail(t, "request should not be sent")
	}))
	_, err := mgmt.Agentic().SetGovernanceSettings(context.Background(), nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.Agentic().SetGovernanceSettings(context.Background(), &descope.AgenticGovernanceSettings{})
	require.Error(t, err)
	assert.Nil(t, res)
}

func TestAgenticSearchGovernanceAccessRequestsSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, "/v1/mgmt/agentic/governance/requests/search", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, map[string]any{
			"limit": float64(10),
			"page":  float64(1),
			"searchFields": []any{map[string]any{
				"field":    "status",
				"valArr":   []any{"pending"},
				"valStr":   "x",
				"negative": true,
				"valType":  "multiselect",
			}},
			"sort": []any{map[string]any{"field": "createdTime", "desc": true}},
			"text": "abc",
		}, req)
	}, map[string]any{"requests": []any{governanceAccessRequestResponse}, "total": 5}))
	res, total, err := mgmt.Agentic().SearchGovernanceAccessRequests(context.Background(), &descope.GovernanceAccessRequestSearchOptions{
		Limit: 10,
		Page:  1,
		SearchFields: []*descope.GovernanceAccessRequestSearchField{{
			Field: "status", ValArr: []string{"pending"}, ValStr: "x", Negative: true, ValType: "multiselect",
		}},
		Sort: []*descope.GovernanceAccessRequestSort{{Field: "createdTime", Desc: true}},
		Text: "abc",
	})
	require.NoError(t, err)
	assert.Equal(t, 5, total)
	require.Len(t, res, 1)
	assertGovernanceAccessRequest(t, res[0])
}

func TestAgenticSearchGovernanceAccessRequestsMinimal(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, map[string]any{"limit": float64(0), "page": float64(0)}, req)
	}, map[string]any{"requests": []any{map[string]any{"id": "req1"}}, "total": 1}))
	res, total, err := mgmt.Agentic().SearchGovernanceAccessRequests(context.Background(), &descope.GovernanceAccessRequestSearchOptions{})
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	require.Len(t, res, 1)
	assert.Equal(t, "req1", res[0].ID)
	assert.Zero(t, res[0].CreatedTime)
}

func TestAgenticSearchGovernanceAccessRequestsError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		require.Fail(t, "request should not be sent")
	}))
	_, _, err := mgmt.Agentic().SearchGovernanceAccessRequests(context.Background(), nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	_, _, err = mgmt.Agentic().SearchGovernanceAccessRequests(context.Background(), &descope.GovernanceAccessRequestSearchOptions{
		Sort: []*descope.GovernanceAccessRequestSort{{Field: ""}},
	})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	_, _, err = mgmt.Agentic().SearchGovernanceAccessRequests(context.Background(), &descope.GovernanceAccessRequestSearchOptions{
		Sort: []*descope.GovernanceAccessRequestSort{{Field: "createdTime"}, nil},
	})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	_, _, err = mgmt.Agentic().SearchGovernanceAccessRequests(context.Background(), &descope.GovernanceAccessRequestSearchOptions{})
	require.Error(t, err)

	mgmt = newTestMgmt(nil, helpers.DoOkWithBody(nil, map[string]any{"requests": []any{map[string]any{"createdTime": true}}}))
	_, _, err = mgmt.Agentic().SearchGovernanceAccessRequests(context.Background(), &descope.GovernanceAccessRequestSearchOptions{})
	require.Error(t, err)
}

func TestAgenticGetGovernanceAccessRequestSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, "/v1/mgmt/agentic/governance/requests/get", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, map[string]any{"id": "req1"}, req)
	}, governanceAccessRequestResponse))
	res, err := mgmt.Agentic().GetGovernanceAccessRequest(context.Background(), "req1")
	require.NoError(t, err)
	assertGovernanceAccessRequest(t, res)
}

func TestAgenticGetGovernanceAccessRequestError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		require.Fail(t, "request should not be sent")
	}))
	_, err := mgmt.Agentic().GetGovernanceAccessRequest(context.Background(), "")
	require.ErrorIs(t, err, descope.ErrInvalidArguments)

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.Agentic().GetGovernanceAccessRequest(context.Background(), "req1")
	require.Error(t, err)
	assert.Nil(t, res)
}

func TestAgenticGovernanceAccessRequestInvalidTimes(t *testing.T) {
	for _, body := range []map[string]any{
		{"createdTime": true},
		{"createdTime": 1.5},
		{"modifiedTime": "1.5"},
		{"version": "1.5"},
	} {
		mgmt := newTestMgmt(nil, helpers.DoOkWithBody(nil, body))
		res, err := mgmt.Agentic().GetGovernanceAccessRequest(context.Background(), "req1")
		require.Error(t, err)
		assert.Nil(t, res)
	}
}

func TestAgenticResolveGovernanceAccessRequestSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, "/v1/mgmt/agentic/governance/requests/resolve", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, map[string]any{"id": "req1", "action": "approve", "resolutionNote": "ok"}, req)
	}, governanceAccessRequestResponse))
	res, err := mgmt.Agentic().ResolveGovernanceAccessRequest(context.Background(), "req1", descope.GovernanceAccessRequestActionApprove, "ok")
	require.NoError(t, err)
	assertGovernanceAccessRequest(t, res)
}

func TestAgenticResolveGovernanceAccessRequestNoNote(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, map[string]any{"id": "req1", "action": "deny"}, req)
	}, governanceAccessRequestResponse))
	_, err := mgmt.Agentic().ResolveGovernanceAccessRequest(context.Background(), "req1", descope.GovernanceAccessRequestActionDeny, "")
	require.NoError(t, err)
}

func TestAgenticResolveGovernanceAccessRequestError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		require.Fail(t, "request should not be sent")
	}))
	_, err := mgmt.Agentic().ResolveGovernanceAccessRequest(context.Background(), "", descope.GovernanceAccessRequestActionApprove, "")
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	_, err = mgmt.Agentic().ResolveGovernanceAccessRequest(context.Background(), "req1", "", "")
	require.ErrorIs(t, err, descope.ErrInvalidArguments)

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.Agentic().ResolveGovernanceAccessRequest(context.Background(), "req1", descope.GovernanceAccessRequestActionApprove, "")
	require.Error(t, err)
	assert.Nil(t, res)
}

func TestAgenticCreateGovernanceAccessRequestSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, "/v1/mgmt/agentic/governance/requests/create", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, map[string]any{
			"requestorUserId": "U1",
			"clientName":      "My Agent",
			"clientType":      "agent",
			"grantTypes":      []any{"authCode"},
			"targets": []any{map[string]any{
				"name":      "api",
				"kind":      "resource",
				"scopes":    []any{"read"},
				"allScopes": true,
			}},
			"scopes":        []any{"read"},
			"justification": "need it",
		}, req)
	}, governanceAccessRequestResponse))
	res, err := mgmt.Agentic().CreateGovernanceAccessRequest(context.Background(), &descope.GovernanceAccessRequestCreateRequest{
		RequestorUserID: "U1",
		ClientName:      "My Agent",
		ClientType:      "agent",
		GrantTypes:      []string{"authCode"},
		Targets:         []*descope.GovernanceAccessRequestTarget{{Name: "api", Kind: "resource", Scopes: []string{"read"}, AllScopes: true}},
		Scopes:          []string{"read"},
		Justification:   "need it",
	})
	require.NoError(t, err)
	assertGovernanceAccessRequest(t, res)
}

func TestAgenticCreateGovernanceAccessRequestMinimal(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, map[string]any{"requestorUserId": "U1"}, req)
	}, governanceAccessRequestResponse))
	_, err := mgmt.Agentic().CreateGovernanceAccessRequest(context.Background(), &descope.GovernanceAccessRequestCreateRequest{RequestorUserID: "U1"})
	require.NoError(t, err)
}

func TestAgenticCreateGovernanceAccessRequestError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		require.Fail(t, "request should not be sent")
	}))
	_, err := mgmt.Agentic().CreateGovernanceAccessRequest(context.Background(), nil)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	_, err = mgmt.Agentic().CreateGovernanceAccessRequest(context.Background(), &descope.GovernanceAccessRequestCreateRequest{})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	_, err = mgmt.Agentic().CreateGovernanceAccessRequest(context.Background(), &descope.GovernanceAccessRequestCreateRequest{
		RequestorUserID: "U1",
		GrantTypes:      []string{"authCode", ""},
	})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.Agentic().CreateGovernanceAccessRequest(context.Background(), &descope.GovernanceAccessRequestCreateRequest{RequestorUserID: "U1"})
	require.Error(t, err)
	assert.Nil(t, res)
}
