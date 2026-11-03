package mgmt_test

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/client"
	"github.com/descope/go-sdk/descope/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Fields the backend returns that are internal and not exposed by the SDK.
var agenticMockHiddenResponseFields = map[string]bool{"version": true}

type agenticMockCall struct {
	Method       string         `json:"method"`
	Path         string         `json:"path"`
	Request      map[string]any `json:"request"`
	ResponseBody map[string]any `json:"responseBody"`
}

func newAgenticMockClient(t *testing.T) (sdk.Agentic, string) {
	url := os.Getenv("DESCOPE_MOCK_URL")
	if url == "" {
		t.Skip("DESCOPE_MOCK_URL is not set")
	}
	descopeClient, err := client.NewWithConfig(&client.Config{
		ProjectID:      "P2AAAAAAAAAAAAAAAAAAAAAAAAAA",
		ManagementKey:  "management-key",
		DescopeBaseURL: url,
	})
	require.NoError(t, err)
	return descopeClient.Management.Agentic(), url
}

func agenticMockLastCall(t *testing.T, url string) *agenticMockCall {
	res, err := http.Get(url + "/__mock/last") // #nosec G107 -- test-only mock URL
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	require.Equal(t, http.StatusOK, res.StatusCode)
	call := &agenticMockCall{}
	require.NoError(t, json.NewDecoder(res.Body).Decode(call))
	return call
}

// assertAgenticMockResponse checks that every field of the mock's response body came through in the
// parsed result. Keys are matched case-insensitively, as encoding/json does when parsing.
func assertAgenticMockResponse(t *testing.T, expected any, parsed any, path string) {
	switch exp := expected.(type) {
	case map[string]any:
		actual := map[string]any{}
		bs, err := json.Marshal(parsed)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(bs, &actual), path)
		for key, value := range exp {
			if agenticMockHiddenResponseFields[key] {
				continue
			}
			var found any
			ok := false
			for actualKey, actualValue := range actual {
				if strings.EqualFold(actualKey, key) {
					found, ok = actualValue, true
					break
				}
			}
			require.True(t, ok, "missing response field %s.%s", path, key)
			assertAgenticMockResponse(t, value, found, path+"."+key)
		}
	case []any:
		actual := []any{}
		bs, err := json.Marshal(parsed)
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(bs, &actual), path)
		require.Len(t, actual, len(exp), path)
		for i := range exp {
			assertAgenticMockResponse(t, exp[i], actual[i], path+"[]")
		}
	default:
		assert.EqualValues(t, expected, parsed, path)
	}
}

func TestMockAgenticSearchIdentities(t *testing.T) {
	agentic, url := newAgenticMockClient(t)
	identities, total, err := agentic.SearchIdentities(context.Background(), &descope.AgenticIdentitySearchOptions{
		UserID:     "U2AAAAAAAAAAAAAAAAAAAAAAAAAA",
		ClientID:   "client1",
		ResourceID: "mcp1",
		ConsentID:  "consent1",
		Page:       1,
		Limit:      10,
	})
	require.NoError(t, err)

	call := agenticMockLastCall(t, url)
	assert.Equal(t, http.MethodPost, call.Method)
	assert.Equal(t, "/v1/mgmt/agentic/identities/search", call.Path)
	assert.EqualValues(t, map[string]any{
		"userId":     "U2AAAAAAAAAAAAAAAAAAAAAAAAAA",
		"clientId":   "client1",
		"resourceId": "mcp1",
		"consentId":  "consent1",
		"page":       float64(1),
		"limit":      float64(10),
	}, call.Request)
	assertAgenticMockResponse(t, call.ResponseBody, map[string]any{"identities": identities, "total": total}, "")
}

func TestMockAgenticRevokeIdentities(t *testing.T) {
	agentic, url := newAgenticMockClient(t)
	revoked, err := agentic.RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{
		UserID:     "U2AAAAAAAAAAAAAAAAAAAAAAAAAA",
		ClientID:   "client1",
		ResourceID: "mcp1",
		ConsentID:  "consent1",
	})
	require.NoError(t, err)

	call := agenticMockLastCall(t, url)
	assert.Equal(t, http.MethodPost, call.Method)
	assert.Equal(t, "/v1/mgmt/agentic/identities/revoke", call.Path)
	assert.EqualValues(t, map[string]any{
		"userId":     "U2AAAAAAAAAAAAAAAAAAAAAAAAAA",
		"clientId":   "client1",
		"resourceId": "mcp1",
		"consentId":  "consent1",
	}, call.Request)
	assertAgenticMockResponse(t, call.ResponseBody, map[string]any{"revoked": revoked}, "")
}

func TestMockAgenticGetGovernanceSettings(t *testing.T) {
	agentic, url := newAgenticMockClient(t)
	settings, err := agentic.GetGovernanceSettings(context.Background())
	require.NoError(t, err)

	call := agenticMockLastCall(t, url)
	assert.Equal(t, http.MethodGet, call.Method)
	assert.Equal(t, "/v1/mgmt/agentic/governance/settings", call.Path)
	assertAgenticMockResponse(t, call.ResponseBody, settings, "")
}

func TestMockAgenticSetGovernanceSettings(t *testing.T) {
	agentic, url := newAgenticMockClient(t)
	configured, autoApproval, suiteDisabled := true, true, false
	settings, err := agentic.SetGovernanceSettings(context.Background(), &descope.AgenticGovernanceSettings{
		Configured:    &configured,
		AutoApproval:  &autoApproval,
		SuiteDisabled: &suiteDisabled,
	})
	require.NoError(t, err)

	call := agenticMockLastCall(t, url)
	assert.Equal(t, http.MethodPost, call.Method)
	assert.Equal(t, "/v1/mgmt/agentic/governance/settings", call.Path)
	assert.EqualValues(t, map[string]any{
		"configured":    true,
		"autoApproval":  true,
		"suiteDisabled": false,
	}, call.Request)
	assertAgenticMockResponse(t, call.ResponseBody, settings, "")
}

func TestMockAgenticSearchGovernanceAccessRequests(t *testing.T) {
	agentic, url := newAgenticMockClient(t)
	requests, total, err := agentic.SearchGovernanceAccessRequests(context.Background(), &descope.GovernanceAccessRequestSearchOptions{
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

	call := agenticMockLastCall(t, url)
	assert.Equal(t, http.MethodPost, call.Method)
	assert.Equal(t, "/v1/mgmt/agentic/governance/requests/search", call.Path)
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
	}, call.Request)
	assertAgenticMockResponse(t, call.ResponseBody, map[string]any{"requests": requests, "total": total}, "")
}

func TestMockAgenticGetGovernanceAccessRequest(t *testing.T) {
	agentic, url := newAgenticMockClient(t)
	request, err := agentic.GetGovernanceAccessRequest(context.Background(), "req1")
	require.NoError(t, err)

	call := agenticMockLastCall(t, url)
	assert.Equal(t, http.MethodPost, call.Method)
	assert.Equal(t, "/v1/mgmt/agentic/governance/requests/get", call.Path)
	assert.EqualValues(t, map[string]any{"id": "req1"}, call.Request)
	assertAgenticMockResponse(t, call.ResponseBody, request, "")
}

func TestMockAgenticResolveGovernanceAccessRequest(t *testing.T) {
	agentic, url := newAgenticMockClient(t)
	request, err := agentic.ResolveGovernanceAccessRequest(context.Background(), "req1", descope.GovernanceAccessRequestActionApprove, "looks good")
	require.NoError(t, err)

	call := agenticMockLastCall(t, url)
	assert.Equal(t, http.MethodPost, call.Method)
	assert.Equal(t, "/v1/mgmt/agentic/governance/requests/resolve", call.Path)
	assert.EqualValues(t, map[string]any{
		"id":             "req1",
		"action":         "approve",
		"resolutionNote": "looks good",
	}, call.Request)
	assertAgenticMockResponse(t, call.ResponseBody, request, "")
}

func TestMockAgenticCreateGovernanceAccessRequest(t *testing.T) {
	agentic, url := newAgenticMockClient(t)
	request, err := agentic.CreateGovernanceAccessRequest(context.Background(), &descope.GovernanceAccessRequestCreateOptions{
		RequestorUserID: "U2AAAAAAAAAAAAAAAAAAAAAAAAAA",
		ClientName:      "my-agent",
		ClientType:      "agent",
		GrantTypes:      []string{"clientCredentials"},
		Targets:         []*descope.GovernanceAccessRequestTarget{{Name: "api", Kind: "resource", Scopes: []string{"read"}, AllScopes: true}},
		Scopes:          []string{"s1"},
		Justification:   "need it",
	})
	require.NoError(t, err)

	call := agenticMockLastCall(t, url)
	assert.Equal(t, http.MethodPost, call.Method)
	assert.Equal(t, "/v1/mgmt/agentic/governance/requests/create", call.Path)
	assert.EqualValues(t, map[string]any{
		"requestorUserId": "U2AAAAAAAAAAAAAAAAAAAAAAAAAA",
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
	}, call.Request)
	assertAgenticMockResponse(t, call.ResponseBody, request, "")
}
