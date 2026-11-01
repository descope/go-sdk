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

// mockLastCall is the last call the mock backend received, from GET /__mock/last.
type mockLastCall struct {
	Method       string         `json:"method"`
	Path         string         `json:"path"`
	Request      map[string]any `json:"request"`
	ResponseBody map[string]any `json:"responseBody"`
}

func newMockBackendMgmt(url string) *managementService {
	client := api.NewClient(api.ClientParams{ProjectID: "P2AAAAAAAAAAAAAAAAAAAAAAAAAA", ManagementKey: "mock-management-key", BaseURL: url})
	return NewManagement(ManagementParams{ProjectID: "P2AAAAAAAAAAAAAAAAAAAAAAAAAA"}, auth.NewProvider(client, &auth.AuthParams{ProjectID: "P2AAAAAAAAAAAAAAAAAAAAAAAAAA"}), client)
}

func getMockLastCall(t *testing.T, url string) *mockLastCall {
	res, err := http.Get(url + "/__mock/last") // #nosec G107 -- test-only URL from the environment
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	last := &mockLastCall{}
	require.NoError(t, json.NewDecoder(res.Body).Decode(last))
	return last
}

func TestMockAgenticSearchIdentities(t *testing.T) {
	url := os.Getenv("DESCOPE_MOCK_URL")
	if url == "" {
		t.Skip("DESCOPE_MOCK_URL is not set")
	}
	mgmt := newMockBackendMgmt(url)
	res, total, err := mgmt.Agentic().SearchIdentities(context.Background(), &descope.AgenticIdentitySearchOptions{
		UserID:     "U2AAAAAAAAAAAAAAAAAAAAAAAAAA",
		ClientID:   "client1",
		ResourceID: "res1",
		ConsentID:  "consent1",
		Page:       1,
		Limit:      10,
	})
	require.NoError(t, err)

	last := getMockLastCall(t, url)
	assert.Equal(t, http.MethodPost, last.Method)
	assert.Equal(t, "/v1/mgmt/agentic/identities/search", last.Path)
	assert.Equal(t, map[string]any{
		"userId":     "U2AAAAAAAAAAAAAAAAAAAAAAAAAA",
		"clientId":   "client1",
		"resourceId": "res1",
		"consentId":  "consent1",
		"page":       float64(1),
		"limit":      float64(10),
	}, last.Request)

	assert.EqualValues(t, last.ResponseBody["total"], total)
	identities, ok := last.ResponseBody["identities"].([]any)
	require.True(t, ok)
	require.Len(t, res, len(identities))
	require.NotEmpty(t, res)
	expected := identities[0].(map[string]any)
	got := res[0]
	assert.Equal(t, expected["agentName"], got.AgentName)
	assert.Equal(t, expected["resourceId"], got.ResourceID)
	assert.Equal(t, expected["clientId"], got.ClientID)
	assert.Equal(t, expected["createdBy"], got.CreatedBy)
	consent := expected["consent"].(map[string]any)
	require.NotNil(t, got.Consent)
	assert.Equal(t, consent["id"], got.Consent.ID)
	assert.Equal(t, consent["appId"], got.Consent.AppID)
	assert.Equal(t, consent["userId"], got.Consent.UserID)
	assert.ElementsMatch(t, consent["scopes"], got.Consent.Scopes)
	assert.Equal(t, consent["grantedBy"], got.Consent.GrantedBy)
	assert.EqualValues(t, consent["createdTime"], got.Consent.CreatedTime)
	assert.Equal(t, consent["tenantId"], got.Consent.TenantID)
	assert.EqualValues(t, consent["ExpireTime"], got.Consent.ExpireTime)
	assert.EqualValues(t, consent["modifiedTime"], got.Consent.ModifiedTime)
	assert.Equal(t, consent["authMethod"], got.Consent.AuthMethod)
	assert.Len(t, expected, 5, "unexpected identity fields in the response")
	assert.Len(t, consent, 10, "unexpected consent fields in the response")
}

func TestMockAgenticRevokeIdentities(t *testing.T) {
	url := os.Getenv("DESCOPE_MOCK_URL")
	if url == "" {
		t.Skip("DESCOPE_MOCK_URL is not set")
	}
	mgmt := newMockBackendMgmt(url)
	revoked, err := mgmt.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{
		UserID:     "U2AAAAAAAAAAAAAAAAAAAAAAAAAA",
		ClientID:   "client1",
		ResourceID: "res1",
		ConsentID:  "consent1",
	})
	require.NoError(t, err)

	last := getMockLastCall(t, url)
	assert.Equal(t, http.MethodPost, last.Method)
	assert.Equal(t, "/v1/mgmt/agentic/identities/revoke", last.Path)
	assert.Equal(t, map[string]any{
		"userId":     "U2AAAAAAAAAAAAAAAAAAAAAAAAAA",
		"clientId":   "client1",
		"resourceId": "res1",
		"consentId":  "consent1",
	}, last.Request)
	assert.EqualValues(t, last.ResponseBody["revoked"], revoked)
	assert.Len(t, last.ResponseBody, 1, "unexpected fields in the response")
}
