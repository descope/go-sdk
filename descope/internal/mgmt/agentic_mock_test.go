package mgmt

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockLastCall struct {
	Method       string         `json:"method"`
	Path         string         `json:"path"`
	Request      map[string]any `json:"request"`
	ResponseBody map[string]any `json:"responseBody"`
}

func newMockBackendMgmt(t *testing.T) (*managementService, string) {
	url := os.Getenv("DESCOPE_MOCK_URL")
	if url == "" {
		t.Skip("DESCOPE_MOCK_URL is not set")
	}
	client := api.NewClient(api.ClientParams{ProjectID: "project-ID", ManagementKey: "management-key", BaseURL: url})
	provider := auth.NewProvider(client, &auth.AuthParams{ProjectID: "project-ID", PublicKey: publicKey})
	return NewManagement(ManagementParams{ProjectID: "project-ID"}, provider, client), url
}

func mockLast(t *testing.T, url string) *mockLastCall {
	resp, err := http.Get(url + "/__mock/last") // #nosec G107 -- test-only mock URL
	require.NoError(t, err)
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	last := &mockLastCall{}
	require.NoError(t, json.Unmarshal(b, last))
	return last
}

func mockInt64(t *testing.T, v any) int64 {
	s, ok := v.(string)
	require.True(t, ok, "expected a 64-bit integer encoded as a string, got %v", v)
	n, err := strconv.ParseInt(s, 10, 64)
	require.NoError(t, err)
	return n
}

func mockStrings(v any) []string {
	res := []string{}
	for _, s := range v.([]any) {
		res = append(res, s.(string))
	}
	return res
}

func requireMockGovernanceAccessRequest(t *testing.T, body map[string]any, res *descope.GovernanceAccessRequest) {
	require.NotNil(t, res)
	assert.Equal(t, body["id"], res.ID)
	assert.Equal(t, body["requestorUserId"], res.RequestorUserID)
	assert.Equal(t, body["requestorName"], res.RequestorName)
	assert.Equal(t, body["clientType"], res.ClientType)
	assert.Equal(t, mockStrings(body["grantTypes"]), res.GrantTypes)
	targets := body["targets"].([]any)
	require.Len(t, res.Targets, len(targets))
	for i, tv := range targets {
		target := tv.(map[string]any)
		assert.Equal(t, target["name"], res.Targets[i].Name)
		assert.Equal(t, target["kind"], res.Targets[i].Kind)
		assert.Equal(t, target["targetId"], res.Targets[i].TargetID)
		assert.Equal(t, mockStrings(target["scopes"]), res.Targets[i].Scopes)
		assert.Equal(t, target["allScopes"], res.Targets[i].AllScopes)
	}
	assert.Equal(t, mockStrings(body["scopes"]), res.Scopes)
	assert.Equal(t, body["justification"], res.Justification)
	assert.Equal(t, body["status"], res.Status)
	assert.Equal(t, body["resolvedByUserId"], res.ResolvedByUserID)
	assert.Equal(t, body["resolvedByName"], res.ResolvedByName)
	assert.Equal(t, body["resolutionNote"], res.ResolutionNote)
	assert.Equal(t, body["clientId"], res.ClientID)
	assert.Equal(t, body["clientAppId"], res.ClientAppID)
	assert.Equal(t, mockInt64(t, body["createdTime"]), res.CreatedTime)
	assert.Equal(t, mockInt64(t, body["modifiedTime"]), res.ModifiedTime)
	assert.Equal(t, mockInt64(t, body["version"]), res.Version)
	assert.Equal(t, body["clientName"], res.ClientName)
	assert.Equal(t, body["clientDeleted"], res.ClientDeleted)
}

func TestMockAgenticSearchIdentities(t *testing.T) {
	mgmt, url := newMockBackendMgmt(t)
	res, total, err := mgmt.Agentic().SearchIdentities(context.Background(), &descope.AgenticIdentitySearchOptions{
		UserID:     "U2aaaaaaaaaaaaaaaaaaaaaaaaa",
		ClientID:   "client1",
		ResourceID: "res1",
		ConsentID:  "consent1",
		Page:       1,
		Limit:      10,
	})
	require.NoError(t, err)

	last := mockLast(t, url)
	assert.Equal(t, http.MethodPost, last.Method)
	assert.Equal(t, "/v1/mgmt/agentic/identities/search", last.Path)
	assert.Equal(t, map[string]any{
		"userId": "U2aaaaaaaaaaaaaaaaaaaaaaaaa", "clientId": "client1", "resourceId": "res1", "consentId": "consent1",
		"page": float64(1), "limit": float64(10),
	}, last.Request)

	assert.EqualValues(t, last.ResponseBody["total"], total)
	identities := last.ResponseBody["identities"].([]any)
	require.Len(t, res, len(identities))
	for i, iv := range identities {
		identity := iv.(map[string]any)
		assert.Equal(t, identity["agentName"], res[i].AgentName)
		assert.Equal(t, identity["resourceId"], res[i].ResourceID)
		assert.Equal(t, identity["clientId"], res[i].ClientID)
		assert.Equal(t, identity["createdBy"], res[i].CreatedBy)
		consent := identity["consent"].(map[string]any)
		require.NotNil(t, res[i].Consent)
		assert.Equal(t, consent["id"], res[i].Consent.ID)
		assert.Equal(t, consent["appId"], res[i].Consent.AppID)
		assert.Equal(t, consent["userId"], res[i].Consent.UserID)
		assert.Equal(t, mockStrings(consent["scopes"]), res[i].Consent.Scopes)
		assert.Equal(t, consent["grantedBy"], res[i].Consent.GrantedBy)
		assert.EqualValues(t, consent["createdTime"], res[i].Consent.CreatedTime)
		assert.Equal(t, consent["tenantId"], res[i].Consent.TenantID)
		assert.EqualValues(t, consent["ExpireTime"], res[i].Consent.ExpireTime)
		assert.EqualValues(t, consent["modifiedTime"], res[i].Consent.ModifiedTime)
		assert.Equal(t, consent["authMethod"], res[i].Consent.AuthMethod)
	}
}

func TestMockAgenticRevokeIdentities(t *testing.T) {
	mgmt, url := newMockBackendMgmt(t)
	revoked, err := mgmt.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{
		UserID:     "U2aaaaaaaaaaaaaaaaaaaaaaaaa",
		ClientID:   "client1",
		ResourceID: "res1",
		ConsentID:  "consent1",
	})
	require.NoError(t, err)

	last := mockLast(t, url)
	assert.Equal(t, http.MethodPost, last.Method)
	assert.Equal(t, "/v1/mgmt/agentic/identities/revoke", last.Path)
	assert.Equal(t, map[string]any{
		"userId": "U2aaaaaaaaaaaaaaaaaaaaaaaaa", "clientId": "client1", "resourceId": "res1", "consentId": "consent1",
	}, last.Request)
	assert.EqualValues(t, last.ResponseBody["revoked"], revoked)
}

func requireMockGovernanceSettings(t *testing.T, body map[string]any, res *descope.AgenticGovernanceSettings) {
	require.NotNil(t, res)
	require.NotNil(t, res.Configured)
	assert.Equal(t, body["configured"], *res.Configured)
	require.NotNil(t, res.AutoApproval)
	assert.Equal(t, body["autoApproval"], *res.AutoApproval)
	require.NotNil(t, res.SuiteDisabled)
	assert.Equal(t, body["suiteDisabled"], *res.SuiteDisabled)
}

func TestMockAgenticGetGovernanceSettings(t *testing.T) {
	mgmt, url := newMockBackendMgmt(t)
	res, err := mgmt.Agentic().GetGovernanceSettings(context.Background())
	require.NoError(t, err)

	last := mockLast(t, url)
	assert.Equal(t, http.MethodGet, last.Method)
	assert.Equal(t, "/v1/mgmt/agentic/governance/settings", last.Path)
	requireMockGovernanceSettings(t, last.ResponseBody, res)
}

func TestMockAgenticSetGovernanceSettings(t *testing.T) {
	mgmt, url := newMockBackendMgmt(t)
	configured, autoApproval, suiteDisabled := true, true, true
	res, err := mgmt.Agentic().SetGovernanceSettings(context.Background(), &descope.AgenticGovernanceSettings{
		Configured:    &configured,
		AutoApproval:  &autoApproval,
		SuiteDisabled: &suiteDisabled,
	})
	require.NoError(t, err)

	last := mockLast(t, url)
	assert.Equal(t, http.MethodPost, last.Method)
	assert.Equal(t, "/v1/mgmt/agentic/governance/settings", last.Path)
	assert.Equal(t, map[string]any{"configured": true, "autoApproval": true, "suiteDisabled": true}, last.Request)
	requireMockGovernanceSettings(t, last.ResponseBody, res)
}

func TestMockAgenticSearchGovernanceAccessRequests(t *testing.T) {
	mgmt, url := newMockBackendMgmt(t)
	res, total, err := mgmt.Agentic().SearchGovernanceAccessRequests(context.Background(), &descope.GovernanceAccessRequestSearchOptions{
		SearchFields: []*descope.GovernanceAccessRequestSearchField{
			{Field: "status", ValArr: []string{"pending"}, ValStr: "pending", Negative: true, ValType: "string"},
		},
		Sort:  []*descope.GovernanceAccessRequestSort{{Field: "createdTime", Desc: true}},
		Text:  "billing",
		Page:  1,
		Limit: 5,
	})
	require.NoError(t, err)

	last := mockLast(t, url)
	assert.Equal(t, http.MethodPost, last.Method)
	assert.Equal(t, "/v1/mgmt/agentic/governance/requests/search", last.Path)
	assert.Equal(t, map[string]any{
		"searchFields": []any{map[string]any{"field": "status", "valArr": []any{"pending"}, "valStr": "pending", "negative": true, "valType": "string"}},
		"sort":         []any{map[string]any{"field": "createdTime", "desc": true}},
		"text":         "billing",
		"page":         float64(1),
		"limit":        float64(5),
	}, last.Request)

	assert.EqualValues(t, last.ResponseBody["total"], total)
	requests := last.ResponseBody["requests"].([]any)
	require.Len(t, res, len(requests))
	for i, rv := range requests {
		requireMockGovernanceAccessRequest(t, rv.(map[string]any), res[i])
	}
}

func TestMockAgenticGetGovernanceAccessRequest(t *testing.T) {
	mgmt, url := newMockBackendMgmt(t)
	res, err := mgmt.Agentic().GetGovernanceAccessRequest(context.Background(), "req1")
	require.NoError(t, err)

	last := mockLast(t, url)
	assert.Equal(t, http.MethodPost, last.Method)
	assert.Equal(t, "/v1/mgmt/agentic/governance/requests/get", last.Path)
	assert.Equal(t, map[string]any{"id": "req1"}, last.Request)
	requireMockGovernanceAccessRequest(t, last.ResponseBody, res)
}

func TestMockAgenticResolveGovernanceAccessRequest(t *testing.T) {
	mgmt, url := newMockBackendMgmt(t)
	res, err := mgmt.Agentic().ResolveGovernanceAccessRequest(context.Background(), "req1", descope.GovernanceAccessRequestActionApprove, "looks good")
	require.NoError(t, err)

	last := mockLast(t, url)
	assert.Equal(t, http.MethodPost, last.Method)
	assert.Equal(t, "/v1/mgmt/agentic/governance/requests/resolve", last.Path)
	assert.Equal(t, map[string]any{"id": "req1", "action": "approve", "resolutionNote": "looks good"}, last.Request)
	requireMockGovernanceAccessRequest(t, last.ResponseBody, res)
}

func TestMockAgenticCreateGovernanceAccessRequest(t *testing.T) {
	mgmt, url := newMockBackendMgmt(t)
	res, err := mgmt.Agentic().CreateGovernanceAccessRequest(context.Background(), &descope.GovernanceAccessRequestCreate{
		RequestorUserID: "U2aaaaaaaaaaaaaaaaaaaaaaaaa",
		ClientName:      "My Agent",
		ClientType:      "agent",
		GrantTypes:      []string{descope.GovernanceAccessRequestGrantTypeClientCredentials},
		Targets: []*descope.GovernanceAccessRequestTarget{
			{Name: "billing", Kind: descope.GovernanceAccessRequestTargetKindResource, TargetID: "res1", Scopes: []string{"read"}, AllScopes: true},
		},
		Scopes:        []string{"read"},
		Justification: "needed",
	})
	require.NoError(t, err)

	last := mockLast(t, url)
	assert.Equal(t, http.MethodPost, last.Method)
	assert.Equal(t, "/v1/mgmt/agentic/governance/requests/create", last.Path)
	assert.Equal(t, map[string]any{
		"requestorUserId": "U2aaaaaaaaaaaaaaaaaaaaaaaaa",
		"clientName":      "My Agent",
		"clientType":      "agent",
		"grantTypes":      []any{"clientCredentials"},
		"targets":         []any{map[string]any{"name": "billing", "kind": "resource", "targetId": "res1", "scopes": []any{"read"}, "allScopes": true}},
		"scopes":          []any{"read"},
		"justification":   "needed",
	}, last.Request)
	requireMockGovernanceAccessRequest(t, last.ResponseBody, res)
}
