package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock tests run against the backend mock at DESCOPE_MOCK_URL and are skipped when it is unset.
// They never run in parallel, since the mock only keeps the last call.

const mockTestUserID = "U2aaaaaaaaaaaaaaaaaaaaaaaaaa"

type mockLastCall struct {
	Method       string `json:"method"`
	Path         string `json:"path"`
	Request      any    `json:"request"`
	ResponseBody any    `json:"responseBody"`
}

func newMockTestClient(t *testing.T) (*DescopeClient, string) {
	url := os.Getenv("DESCOPE_MOCK_URL")
	if url == "" {
		t.Skip("DESCOPE_MOCK_URL is not set")
	}
	c, err := NewWithConfig(&Config{ProjectID: "a", ManagementKey: "key", DescopeBaseURL: url})
	require.NoError(t, err)
	return c, url
}

func getMockLastCall(t *testing.T, url string) *mockLastCall {
	res, err := http.Get(strings.TrimSuffix(url, "/") + "/__mock/last") // #nosec G107 -- test-only mock URL
	require.NoError(t, err)
	body, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())
	last := &mockLastCall{}
	require.NoError(t, decodeJSONUseNumber(body, last))
	return last
}

func decodeJSONUseNumber(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	return dec.Decode(v)
}

// toJSONValue converts v into its generic JSON representation, with numbers kept as json.Number.
func toJSONValue(t *testing.T, v any) any {
	data, err := json.Marshal(v)
	require.NoError(t, err)
	var res any
	require.NoError(t, decodeJSONUseNumber(data, &res))
	return res
}

// assertJSONContains checks that every field of expected is present in actual with the same value.
// Keys are matched case-insensitively and numbers sent as strings match the same number.
func assertJSONContains(t *testing.T, expected, actual any, path string) {
	switch exp := expected.(type) {
	case map[string]any:
		act, ok := actual.(map[string]any)
		if !assert.True(t, ok, "%s: expected an object, got %v", path, actual) {
			return
		}
		for k, v := range exp {
			found := false
			for ak, av := range act {
				if strings.EqualFold(k, ak) {
					found = true
					assertJSONContains(t, v, av, path+"."+k)
					break
				}
			}
			assert.True(t, found, "%s.%s: missing", path, k)
		}
	case []any:
		act, ok := actual.([]any)
		if !assert.True(t, ok, "%s: expected a list, got %v", path, actual) {
			return
		}
		if !assert.Len(t, act, len(exp), path) {
			return
		}
		for i := range exp {
			assertJSONContains(t, exp[i], act[i], fmt.Sprintf("%s[%d]", path, i))
		}
	default:
		assert.Equal(t, fmt.Sprint(expected), fmt.Sprint(actual), path)
	}
}

func assertMockCall(t *testing.T, url string, method string, path string, sent any, parsed any) {
	last := getMockLastCall(t, url)
	assert.Equal(t, method, last.Method)
	assert.Equal(t, path, last.Path)
	if sent != nil {
		assertJSONContains(t, toJSONValue(t, sent), last.Request, "request")
	}
	assertJSONContains(t, last.ResponseBody, toJSONValue(t, parsed), "response")
}

var mockTestGovernanceAccessRequestTarget = &descope.GovernanceAccessRequestTarget{
	Name:      "api",
	Kind:      "resource",
	TargetID:  "res1",
	Scopes:    []string{"read"},
	AllScopes: true,
}

func TestMockAgenticSearchIdentities(t *testing.T) {
	c, url := newMockTestClient(t)
	options := &descope.AgenticIdentitySearchOptions{
		UserID:     mockTestUserID,
		ClientID:   "client1",
		ResourceID: "res1",
		ConsentID:  "cons1",
		Page:       1,
		Limit:      5,
	}
	identities, total, err := c.Management.Agentic().SearchIdentities(context.Background(), options)
	require.NoError(t, err)
	parsed := map[string]any{"identities": identities, "total": total}
	assertMockCall(t, url, http.MethodPost, "/v1/mgmt/agentic/identities/search", options, parsed)
}

func TestMockAgenticRevokeIdentities(t *testing.T) {
	c, url := newMockTestClient(t)
	options := &descope.AgenticIdentityRevokeOptions{
		UserID:     mockTestUserID,
		ClientID:   "client1",
		ResourceID: "res1",
		ConsentID:  "cons1",
	}
	revoked, err := c.Management.Agentic().RevokeIdentities(context.Background(), options)
	require.NoError(t, err)
	assertMockCall(t, url, http.MethodPost, "/v1/mgmt/agentic/identities/revoke", options, map[string]any{"revoked": revoked})
}

func TestMockAgenticGetGovernanceSettings(t *testing.T) {
	c, url := newMockTestClient(t)
	settings, err := c.Management.Agentic().GetGovernanceSettings(context.Background())
	require.NoError(t, err)
	assertMockCall(t, url, http.MethodGet, "/v1/mgmt/agentic/governance/settings", nil, settings)
}

func TestMockAgenticConfigureGovernanceSettings(t *testing.T) {
	c, url := newMockTestClient(t)
	configured := true
	autoApproval := true
	suiteDisabled := true
	request := &descope.AgenticGovernanceSettingsRequest{Configured: &configured, AutoApproval: &autoApproval, SuiteDisabled: &suiteDisabled}
	settings, err := c.Management.Agentic().ConfigureGovernanceSettings(context.Background(), request)
	require.NoError(t, err)
	assertMockCall(t, url, http.MethodPost, "/v1/mgmt/agentic/governance/settings", request, settings)
}

func TestMockAgenticSearchGovernanceAccessRequests(t *testing.T) {
	c, url := newMockTestClient(t)
	options := &descope.GovernanceAccessRequestSearchOptions{
		Text:         "agent",
		SearchFields: []descope.GovernanceAccessRequestSearchField{{Field: "status", ValArr: []string{"pending"}, ValStr: "pending", Negative: true, ValType: "string"}},
		Sort:         []descope.GovernanceAccessRequestSort{{Field: "createdTime", Desc: true}},
		Page:         1,
		Limit:        5,
	}
	requests, total, err := c.Management.Agentic().SearchGovernanceAccessRequests(context.Background(), options)
	require.NoError(t, err)
	parsed := map[string]any{"requests": requests, "total": total}
	assertMockCall(t, url, http.MethodPost, "/v1/mgmt/agentic/governance/requests/search", options, parsed)
}

func TestMockAgenticGetGovernanceAccessRequest(t *testing.T) {
	c, url := newMockTestClient(t)
	request, err := c.Management.Agentic().GetGovernanceAccessRequest(context.Background(), "req1")
	require.NoError(t, err)
	assertMockCall(t, url, http.MethodPost, "/v1/mgmt/agentic/governance/requests/get", map[string]any{"id": "req1"}, request)
}

func TestMockAgenticResolveGovernanceAccessRequest(t *testing.T) {
	c, url := newMockTestClient(t)
	request, err := c.Management.Agentic().ResolveGovernanceAccessRequest(context.Background(), "req1", descope.GovernanceAccessRequestActionApprove, "ok")
	require.NoError(t, err)
	sent := map[string]any{"id": "req1", "action": "approve", "resolutionNote": "ok"}
	assertMockCall(t, url, http.MethodPost, "/v1/mgmt/agentic/governance/requests/resolve", sent, request)
}

func TestMockAgenticCreateGovernanceAccessRequest(t *testing.T) {
	c, url := newMockTestClient(t)
	create := &descope.GovernanceAccessRequestCreateRequest{
		RequestorUserID: mockTestUserID,
		ClientName:      "My Agent",
		ClientType:      "agent",
		GrantTypes:      []string{"authCode"},
		Targets:         []*descope.GovernanceAccessRequestTarget{mockTestGovernanceAccessRequestTarget},
		Scopes:          []string{"openid"},
		Justification:   "need it",
	}
	request, err := c.Management.Agentic().CreateGovernanceAccessRequest(context.Background(), create)
	require.NoError(t, err)
	assertMockCall(t, url, http.MethodPost, "/v1/mgmt/agentic/governance/requests/create", create, request)
}
