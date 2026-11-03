package mgmt_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type agenticMockCall struct {
	Method       string         `json:"method"`
	Path         string         `json:"path"`
	Request      map[string]any `json:"request"`
	ResponseBody map[string]any `json:"responseBody"`
}

func newAgenticMockClient(t *testing.T) (*client.DescopeClient, string) {
	url := os.Getenv("DESCOPE_MOCK_URL")
	if url == "" {
		t.Skip("DESCOPE_MOCK_URL is not set")
	}
	c, err := client.NewWithConfig(&client.Config{
		ProjectID:      "project-ID",
		ManagementKey:  "management-key",
		DescopeBaseURL: url,
	})
	require.NoError(t, err)
	return c, url
}

func lastAgenticMockCall(t *testing.T, url string) *agenticMockCall {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url+"/__mock/last", nil)
	require.NoError(t, err)
	res, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())
	call := &agenticMockCall{}
	require.NoError(t, json.Unmarshal(body, call))
	return call
}

func mockInt64(t *testing.T, v any) int64 {
	switch n := v.(type) {
	case string:
		i, err := strconv.ParseInt(n, 10, 64)
		require.NoError(t, err)
		return i
	case float64:
		return int64(n)
	}
	require.Failf(t, "unexpected number", "%v", v)
	return 0
}

func mockStrings(v any) []string {
	res := []string{}
	for _, s := range v.([]any) {
		res = append(res, s.(string))
	}
	return res
}

func assertMockGovernanceAccessRequest(t *testing.T, expected map[string]any, r *descope.GovernanceAccessRequest) {
	require.NotNil(t, r)
	assert.Len(t, expected, 19)
	assert.Equal(t, expected["id"], r.ID)
	assert.Equal(t, expected["requestorUserId"], r.RequestorUserID)
	assert.Equal(t, expected["requestorName"], r.RequestorName)
	assert.Equal(t, expected["clientType"], r.ClientType)
	assert.Equal(t, mockStrings(expected["grantTypes"]), r.GrantTypes)
	targets := expected["targets"].([]any)
	require.Len(t, r.Targets, len(targets))
	for i, ti := range targets {
		target := ti.(map[string]any)
		assert.Len(t, target, 5)
		assert.Equal(t, target["name"], r.Targets[i].Name)
		assert.Equal(t, target["kind"], r.Targets[i].Kind)
		assert.Equal(t, target["targetId"], r.Targets[i].TargetID)
		assert.Equal(t, mockStrings(target["scopes"]), r.Targets[i].Scopes)
		assert.Equal(t, target["allScopes"], r.Targets[i].AllScopes)
	}
	assert.Equal(t, mockStrings(expected["scopes"]), r.Scopes)
	assert.Equal(t, expected["justification"], r.Justification)
	assert.Equal(t, expected["status"], r.Status)
	assert.Equal(t, expected["resolvedByUserId"], r.ResolvedByUserID)
	assert.Equal(t, expected["resolvedByName"], r.ResolvedByName)
	assert.Equal(t, expected["resolutionNote"], r.ResolutionNote)
	assert.Equal(t, expected["clientId"], r.ClientID)
	assert.Equal(t, expected["clientAppId"], r.ClientAppID)
	assert.Equal(t, mockInt64(t, expected["createdTime"]), r.CreatedTime)
	assert.Equal(t, mockInt64(t, expected["modifiedTime"]), r.ModifiedTime)
	assert.Equal(t, mockInt64(t, expected["version"]), r.Version)
	assert.Equal(t, expected["clientName"], r.ClientName)
	assert.Equal(t, expected["clientDeleted"], r.ClientDeleted)
}

func assertMockGovernanceSettings(t *testing.T, expected map[string]any, s *descope.AgenticGovernanceSettings) {
	require.NotNil(t, s)
	assert.Len(t, expected, 3)
	require.NotNil(t, s.Configured)
	require.NotNil(t, s.AutoApproval)
	require.NotNil(t, s.SuiteDisabled)
	assert.Equal(t, expected["configured"], *s.Configured)
	assert.Equal(t, expected["autoApproval"], *s.AutoApproval)
	assert.Equal(t, expected["suiteDisabled"], *s.SuiteDisabled)
}

func TestMockAgenticSearchIdentities(t *testing.T) {
	c, url := newAgenticMockClient(t)
	res, total, err := c.Management.Agentic().SearchIdentities(context.Background(), &descope.AgenticIdentitySearchOptions{
		UserID:     "U2abcdefghijklmnopqrstuvwxyz",
		ClientID:   "client1",
		ResourceID: "res1",
		ConsentID:  "consent1",
		Page:       1,
		Limit:      10,
	})
	require.NoError(t, err)

	call := lastAgenticMockCall(t, url)
	assert.Equal(t, http.MethodPost, call.Method)
	assert.Equal(t, "/v1/mgmt/agentic/identities/search", call.Path)
	assert.Equal(t, map[string]any{
		"userId":     "U2abcdefghijklmnopqrstuvwxyz",
		"clientId":   "client1",
		"resourceId": "res1",
		"consentId":  "consent1",
		"page":       float64(1),
		"limit":      float64(10),
	}, call.Request)

	assert.Len(t, call.ResponseBody, 2)
	assert.Equal(t, mockInt64(t, call.ResponseBody["total"]), int64(total))
	identities := call.ResponseBody["identities"].([]any)
	require.Len(t, res, len(identities))
	for i, ii := range identities {
		identity := ii.(map[string]any)
		assert.Len(t, identity, 5)
		assert.Equal(t, identity["agentName"], res[i].AgentName)
		assert.Equal(t, identity["resourceId"], res[i].ResourceID)
		assert.Equal(t, identity["clientId"], res[i].ClientID)
		assert.Equal(t, identity["createdBy"], res[i].CreatedBy)
		consent := identity["consent"].(map[string]any)
		require.NotNil(t, res[i].Consent)
		assert.Len(t, consent, 10)
		assert.Equal(t, consent["id"], res[i].Consent.ID)
		assert.Equal(t, consent["appId"], res[i].Consent.AppID)
		assert.Equal(t, consent["userId"], res[i].Consent.UserID)
		assert.Equal(t, mockStrings(consent["scopes"]), res[i].Consent.Scopes)
		assert.Equal(t, consent["grantedBy"], res[i].Consent.GrantedBy)
		assert.Equal(t, mockInt64(t, consent["createdTime"]), int64(res[i].Consent.CreatedTime))
		assert.Equal(t, consent["tenantId"], res[i].Consent.TenantID)
		assert.Equal(t, mockInt64(t, consent["ExpireTime"]), int64(res[i].Consent.ExpireTime))
		assert.Equal(t, mockInt64(t, consent["modifiedTime"]), int64(res[i].Consent.ModifiedTime))
		assert.Equal(t, consent["authMethod"], res[i].Consent.AuthMethod)
	}
}

func TestMockAgenticRevokeIdentities(t *testing.T) {
	c, url := newAgenticMockClient(t)
	revoked, err := c.Management.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{
		UserID:     "U2abcdefghijklmnopqrstuvwxyz",
		ClientID:   "client1",
		ResourceID: "res1",
		ConsentID:  "consent1",
	})
	require.NoError(t, err)

	call := lastAgenticMockCall(t, url)
	assert.Equal(t, http.MethodPost, call.Method)
	assert.Equal(t, "/v1/mgmt/agentic/identities/revoke", call.Path)
	assert.Equal(t, map[string]any{
		"userId":     "U2abcdefghijklmnopqrstuvwxyz",
		"clientId":   "client1",
		"resourceId": "res1",
		"consentId":  "consent1",
	}, call.Request)
	assert.Len(t, call.ResponseBody, 1)
	assert.Equal(t, mockInt64(t, call.ResponseBody["revoked"]), int64(revoked))
}

func TestMockAgenticGetGovernanceSettings(t *testing.T) {
	c, url := newAgenticMockClient(t)
	res, err := c.Management.Agentic().GetGovernanceSettings(context.Background())
	require.NoError(t, err)

	call := lastAgenticMockCall(t, url)
	assert.Equal(t, http.MethodGet, call.Method)
	assert.Equal(t, "/v1/mgmt/agentic/governance/settings", call.Path)
	assertMockGovernanceSettings(t, call.ResponseBody, res)
}

func TestMockAgenticSetGovernanceSettings(t *testing.T) {
	c, url := newAgenticMockClient(t)
	configured, autoApproval, suiteDisabled := true, true, true
	res, err := c.Management.Agentic().SetGovernanceSettings(context.Background(), &descope.AgenticGovernanceSettings{
		Configured:    &configured,
		AutoApproval:  &autoApproval,
		SuiteDisabled: &suiteDisabled,
	})
	require.NoError(t, err)

	call := lastAgenticMockCall(t, url)
	assert.Equal(t, http.MethodPost, call.Method)
	assert.Equal(t, "/v1/mgmt/agentic/governance/settings", call.Path)
	assert.Equal(t, map[string]any{
		"configured":    true,
		"autoApproval":  true,
		"suiteDisabled": true,
	}, call.Request)
	assertMockGovernanceSettings(t, call.ResponseBody, res)
}

func TestMockAgenticSearchGovernanceAccessRequests(t *testing.T) {
	c, url := newAgenticMockClient(t)
	res, total, err := c.Management.Agentic().SearchGovernanceAccessRequests(context.Background(), &descope.GovernanceAccessRequestSearchOptions{
		Limit: 10,
		Page:  1,
		SearchFields: []*descope.GovernanceAccessRequestSearchField{{
			Field:    "status",
			ValArr:   []string{"pending"},
			ValStr:   "pending",
			Negative: true,
			ValType:  "multiselect",
		}},
		Sort: []*descope.GovernanceAccessRequestSort{{Field: "createdTime", Desc: true}},
		Text: "agent",
	})
	require.NoError(t, err)

	call := lastAgenticMockCall(t, url)
	assert.Equal(t, http.MethodPost, call.Method)
	assert.Equal(t, "/v1/mgmt/agentic/governance/requests/search", call.Path)
	assert.Equal(t, map[string]any{
		"limit": float64(10),
		"page":  float64(1),
		"searchFields": []any{map[string]any{
			"field":    "status",
			"valArr":   []any{"pending"},
			"valStr":   "pending",
			"negative": true,
			"valType":  "multiselect",
		}},
		"sort": []any{map[string]any{"field": "createdTime", "desc": true}},
		"text": "agent",
	}, call.Request)

	assert.Len(t, call.ResponseBody, 2)
	assert.Equal(t, mockInt64(t, call.ResponseBody["total"]), int64(total))
	requests := call.ResponseBody["requests"].([]any)
	require.Len(t, res, len(requests))
	for i, r := range requests {
		assertMockGovernanceAccessRequest(t, r.(map[string]any), res[i])
	}
}

func TestMockAgenticGetGovernanceAccessRequest(t *testing.T) {
	c, url := newAgenticMockClient(t)
	res, err := c.Management.Agentic().GetGovernanceAccessRequest(context.Background(), "req1")
	require.NoError(t, err)

	call := lastAgenticMockCall(t, url)
	assert.Equal(t, http.MethodPost, call.Method)
	assert.Equal(t, "/v1/mgmt/agentic/governance/requests/get", call.Path)
	assert.Equal(t, map[string]any{"id": "req1"}, call.Request)
	assertMockGovernanceAccessRequest(t, call.ResponseBody, res)
}

func TestMockAgenticResolveGovernanceAccessRequest(t *testing.T) {
	c, url := newAgenticMockClient(t)
	res, err := c.Management.Agentic().ResolveGovernanceAccessRequest(context.Background(), "req1", descope.GovernanceAccessRequestActionApprove, "approved")
	require.NoError(t, err)

	call := lastAgenticMockCall(t, url)
	assert.Equal(t, http.MethodPost, call.Method)
	assert.Equal(t, "/v1/mgmt/agentic/governance/requests/resolve", call.Path)
	assert.Equal(t, map[string]any{
		"id":             "req1",
		"action":         "approve",
		"resolutionNote": "approved",
	}, call.Request)
	assertMockGovernanceAccessRequest(t, call.ResponseBody, res)
}

func TestMockAgenticCreateGovernanceAccessRequest(t *testing.T) {
	c, url := newAgenticMockClient(t)
	res, err := c.Management.Agentic().CreateGovernanceAccessRequest(context.Background(), &descope.GovernanceAccessRequestCreateRequest{
		RequestorUserID: "U1",
		ClientName:      "My Agent",
		ClientType:      "agent",
		GrantTypes:      []string{"authCode"},
		Targets: []*descope.GovernanceAccessRequestTarget{{
			Name:      "api",
			Kind:      "resource",
			TargetID:  "res1",
			Scopes:    []string{"read"},
			AllScopes: true,
		}},
		Scopes:        []string{"read"},
		Justification: "need it",
	})
	require.NoError(t, err)

	call := lastAgenticMockCall(t, url)
	assert.Equal(t, http.MethodPost, call.Method)
	assert.Equal(t, "/v1/mgmt/agentic/governance/requests/create", call.Path)
	assert.Equal(t, map[string]any{
		"requestorUserId": "U1",
		"clientName":      "My Agent",
		"clientType":      "agent",
		"grantTypes":      []any{"authCode"},
		"targets": []any{map[string]any{
			"name":      "api",
			"kind":      "resource",
			"targetId":  "res1",
			"scopes":    []any{"read"},
			"allScopes": true,
		}},
		"scopes":        []any{"read"},
		"justification": "need it",
	}, call.Request)
	assertMockGovernanceAccessRequest(t, call.ResponseBody, res)
}
