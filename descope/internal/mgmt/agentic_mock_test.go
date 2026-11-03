package mgmt

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newMockBackendMgmt(t *testing.T) (*managementService, string) {
	url := os.Getenv("DESCOPE_MOCK_URL")
	if url == "" {
		t.Skip("DESCOPE_MOCK_URL is not set")
	}
	client := api.NewClient(api.ClientParams{ProjectID: "a", ManagementKey: "key", BaseURL: url})
	return NewManagement(ManagementParams{ProjectID: "a"}, auth.NewProvider(client, &auth.AuthParams{ProjectID: "a"}), client), url
}

type mockLastCall struct {
	Request      map[string]any `json:"request"`
	ResponseBody map[string]any `json:"responseBody"`
}

func mockLast(t *testing.T, url string) *mockLastCall {
	res, err := http.Get(url + "/__mock/last") // #nosec G107 test-only mock URL
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	last := &mockLastCall{}
	require.NoError(t, json.NewDecoder(res.Body).Decode(last))
	return last
}

func requireGovernanceAccessRequestFromMock(t *testing.T, body map[string]any, res *descope.GovernanceAccessRequest) {
	require.NotNil(t, res)
	assert.Equal(t, body["id"], res.ID)
	assert.Equal(t, body["requestorUserId"], res.RequestorUserID)
	assert.Equal(t, body["requestorName"], res.RequestorName)
	assert.Equal(t, body["clientType"], res.ClientType)
	assert.Len(t, res.GrantTypes, len(body["grantTypes"].([]any)))
	assert.Equal(t, body["grantTypes"].([]any)[0], res.GrantTypes[0])
	targets := body["targets"].([]any)
	require.Len(t, res.Targets, len(targets))
	target := targets[0].(map[string]any)
	assert.Equal(t, target["name"], res.Targets[0].Name)
	assert.Equal(t, target["kind"], res.Targets[0].Kind)
	assert.Equal(t, target["targetId"], res.Targets[0].TargetID)
	assert.Equal(t, target["scopes"].([]any)[0], res.Targets[0].Scopes[0])
	assert.Equal(t, target["allScopes"], res.Targets[0].AllScopes)
	assert.Equal(t, body["scopes"].([]any)[0], res.Scopes[0])
	assert.Equal(t, body["justification"], res.Justification)
	assert.Equal(t, body["status"], res.Status)
	assert.Equal(t, body["resolvedByUserId"], res.ResolvedByUserID)
	assert.Equal(t, body["resolvedByName"], res.ResolvedByName)
	assert.Equal(t, body["resolutionNote"], res.ResolutionNote)
	assert.Equal(t, body["clientId"], res.ClientID)
	assert.Equal(t, body["clientAppId"], res.ClientAppID)
	assert.NotZero(t, res.CreatedTime)
	assert.NotZero(t, res.ModifiedTime)
	assert.Equal(t, body["clientName"], res.ClientName)
	assert.Equal(t, body["clientDeleted"], res.ClientDeleted)
}

func TestMockAgenticSearchIdentities(t *testing.T) {
	m, url := newMockBackendMgmt(t)
	res, total, err := m.Agentic().SearchIdentities(context.Background(), &descope.AgenticIdentitySearchOptions{UserID: "U2abcdefghijklmnopqrstuvwxyz", ClientID: "c1", ResourceID: "r1", ConsentID: "cs1", Page: 1, Limit: 2})
	require.NoError(t, err)
	last := mockLast(t, url)
	assert.Equal(t, map[string]any{"userId": "U2abcdefghijklmnopqrstuvwxyz", "clientId": "c1", "resourceId": "r1", "consentId": "cs1", "page": float64(1), "limit": float64(2)}, last.Request)
	assert.EqualValues(t, last.ResponseBody["total"], total)
	identities := last.ResponseBody["identities"].([]any)
	require.Len(t, res, len(identities))
	identity := identities[0].(map[string]any)
	assert.Equal(t, identity["agentName"], res[0].AgentName)
	assert.Equal(t, identity["resourceId"], res[0].ResourceID)
	assert.Equal(t, identity["clientId"], res[0].ClientID)
	assert.Equal(t, identity["createdBy"], res[0].CreatedBy)
	consent := identity["consent"].(map[string]any)
	require.NotNil(t, res[0].Consent)
	assert.Equal(t, consent["id"], res[0].Consent.ID)
	assert.Equal(t, consent["appId"], res[0].Consent.AppID)
	assert.Equal(t, consent["userId"], res[0].Consent.UserID)
	assert.Equal(t, consent["scopes"].([]any)[0], res[0].Consent.Scopes[0])
	assert.Equal(t, consent["grantedBy"], res[0].Consent.GrantedBy)
	assert.EqualValues(t, consent["createdTime"], res[0].Consent.CreatedTime)
	assert.Equal(t, consent["tenantId"], res[0].Consent.TenantID)
	assert.EqualValues(t, consent["ExpireTime"], res[0].Consent.ExpireTime)
	assert.EqualValues(t, consent["modifiedTime"], res[0].Consent.ModifiedTime)
	assert.Equal(t, consent["authMethod"], res[0].Consent.AuthMethod)
}

func TestMockAgenticRevokeIdentities(t *testing.T) {
	m, url := newMockBackendMgmt(t)
	revoked, err := m.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{UserID: "U2abcdefghijklmnopqrstuvwxyz", ClientID: "c1", ResourceID: "r1", ConsentID: "cs1"})
	require.NoError(t, err)
	last := mockLast(t, url)
	assert.Equal(t, map[string]any{"userId": "U2abcdefghijklmnopqrstuvwxyz", "clientId": "c1", "resourceId": "r1", "consentId": "cs1"}, last.Request)
	assert.EqualValues(t, last.ResponseBody["revoked"], revoked)
}

func TestMockAgenticGetGovernanceSettings(t *testing.T) {
	m, url := newMockBackendMgmt(t)
	res, err := m.Agentic().GetGovernanceSettings(context.Background())
	require.NoError(t, err)
	last := mockLast(t, url)
	require.NotNil(t, res.Configured)
	require.NotNil(t, res.AutoApproval)
	require.NotNil(t, res.SuiteDisabled)
	assert.Equal(t, last.ResponseBody["configured"], *res.Configured)
	assert.Equal(t, last.ResponseBody["autoApproval"], *res.AutoApproval)
	assert.Equal(t, last.ResponseBody["suiteDisabled"], *res.SuiteDisabled)
}

func TestMockAgenticSetGovernanceSettings(t *testing.T) {
	m, url := newMockBackendMgmt(t)
	configured, autoApproval, suiteDisabled := true, true, true
	res, err := m.Agentic().SetGovernanceSettings(context.Background(), &descope.AgenticGovernanceSettings{Configured: &configured, AutoApproval: &autoApproval, SuiteDisabled: &suiteDisabled})
	require.NoError(t, err)
	last := mockLast(t, url)
	assert.Equal(t, map[string]any{"configured": true, "autoApproval": true, "suiteDisabled": true}, last.Request)
	require.NotNil(t, res.Configured)
	require.NotNil(t, res.AutoApproval)
	require.NotNil(t, res.SuiteDisabled)
	assert.Equal(t, last.ResponseBody["configured"], *res.Configured)
	assert.Equal(t, last.ResponseBody["autoApproval"], *res.AutoApproval)
	assert.Equal(t, last.ResponseBody["suiteDisabled"], *res.SuiteDisabled)
}

func TestMockAgenticSearchGovernanceAccessRequests(t *testing.T) {
	m, url := newMockBackendMgmt(t)
	res, total, err := m.Agentic().SearchGovernanceAccessRequests(context.Background(), &descope.GovernanceAccessRequestSearchOptions{
		Limit:        10,
		Page:         1,
		SearchFields: []*descope.GovernanceSearchField{{Field: "status", ValArr: []string{"pending"}, ValStr: "x", Negative: true, ValType: "string"}},
		Sort:         []*descope.GovernanceSort{{Field: "createdTime", Desc: true}},
		Text:         "agent",
	})
	require.NoError(t, err)
	last := mockLast(t, url)
	assert.Equal(t, map[string]any{
		"limit":        float64(10),
		"page":         float64(1),
		"searchFields": []any{map[string]any{"field": "status", "valArr": []any{"pending"}, "valStr": "x", "negative": true, "valType": "string"}},
		"sort":         []any{map[string]any{"field": "createdTime", "desc": true}},
		"text":         "agent",
	}, last.Request)
	assert.EqualValues(t, last.ResponseBody["total"], total)
	requests := last.ResponseBody["requests"].([]any)
	require.Len(t, res, len(requests))
	requireGovernanceAccessRequestFromMock(t, requests[0].(map[string]any), res[0])
}

func TestMockAgenticGetGovernanceAccessRequest(t *testing.T) {
	m, url := newMockBackendMgmt(t)
	res, err := m.Agentic().GetGovernanceAccessRequest(context.Background(), "gar1")
	require.NoError(t, err)
	last := mockLast(t, url)
	assert.Equal(t, map[string]any{"id": "gar1"}, last.Request)
	requireGovernanceAccessRequestFromMock(t, last.ResponseBody, res)
}

func TestMockAgenticResolveGovernanceAccessRequest(t *testing.T) {
	m, url := newMockBackendMgmt(t)
	res, err := m.Agentic().ResolveGovernanceAccessRequest(context.Background(), "gar1", "approve", "ok")
	require.NoError(t, err)
	last := mockLast(t, url)
	assert.Equal(t, map[string]any{"id": "gar1", "action": "approve", "resolutionNote": "ok"}, last.Request)
	requireGovernanceAccessRequestFromMock(t, last.ResponseBody, res)
}

func TestMockAgenticCreateGovernanceAccessRequest(t *testing.T) {
	m, url := newMockBackendMgmt(t)
	res, err := m.Agentic().CreateGovernanceAccessRequest(context.Background(), &descope.GovernanceAccessRequestCreate{
		RequestorUserID: "u1",
		ClientName:      "my agent",
		ClientType:      "agent",
		GrantTypes:      []string{"authCode"},
		Targets:         []*descope.GovernanceAccessRequestTarget{{Name: "res1", Kind: "resource", Scopes: []string{"read"}, AllScopes: true}},
		Scopes:          []string{"s1"},
		Justification:   "need it",
	})
	require.NoError(t, err)
	last := mockLast(t, url)
	assert.Equal(t, map[string]any{
		"requestorUserId": "u1",
		"clientName":      "my agent",
		"clientType":      "agent",
		"grantTypes":      []any{"authCode"},
		"targets":         []any{map[string]any{"name": "res1", "kind": "resource", "scopes": []any{"read"}, "allScopes": true}},
		"scopes":          []any{"s1"},
		"justification":   "need it",
	}, last.Request)
	requireGovernanceAccessRequestFromMock(t, last.ResponseBody, res)
}
