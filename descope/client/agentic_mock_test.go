package client

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockLastCall struct {
	Method       string         `json:"method"`
	Path         string         `json:"path"`
	Status       int            `json:"status"`
	Request      map[string]any `json:"request"`
	ResponseBody map[string]any `json:"responseBody"`
}

func newMockBackendClient(t *testing.T, url string) *DescopeClient {
	c, err := NewWithConfig(&Config{ProjectID: "test", ManagementKey: "test", DescopeBaseURL: url})
	require.NoError(t, err)
	return c
}

func readMockLastCall(t *testing.T, url string) *mockLastCall {
	res, err := http.Get(url + "/__mock/last") // #nosec G107 -- test-only mock URL
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	require.Equal(t, http.StatusOK, res.StatusCode)
	last := &mockLastCall{}
	require.NoError(t, json.NewDecoder(res.Body).Decode(last))
	return last
}

func TestMockAgenticSearchIdentities(t *testing.T) {
	url := os.Getenv("DESCOPE_MOCK_URL")
	if url == "" {
		t.Skip("DESCOPE_MOCK_URL is not set")
	}
	c := newMockBackendClient(t, url)
	identities, total, err := c.Management.Agentic().SearchIdentities(context.Background(), &descope.AgenticIdentitySearchOptions{
		UserID:     "U2abcdefghijklmnopqrstuvwxyz",
		ClientID:   "client1",
		ResourceID: "resource1",
		ConsentID:  "consent1",
		Page:       1,
		Limit:      10,
	})
	require.NoError(t, err)

	last := readMockLastCall(t, url)
	require.Equal(t, http.MethodPost, last.Method)
	require.Equal(t, "/v1/mgmt/agentic/identities/search", last.Path)
	require.Equal(t, http.StatusOK, last.Status)
	assert.Equal(t, map[string]any{
		"userId":     "U2abcdefghijklmnopqrstuvwxyz",
		"clientId":   "client1",
		"resourceId": "resource1",
		"consentId":  "consent1",
		"page":       float64(1),
		"limit":      float64(10),
	}, last.Request)

	assert.EqualValues(t, last.ResponseBody["total"], total)
	expected, ok := last.ResponseBody["identities"].([]any)
	require.True(t, ok)
	require.Len(t, identities, len(expected))
	for i, e := range expected {
		ei := e.(map[string]any)
		got := identities[i]
		assert.Equal(t, ei["agentName"], got.AgentName)
		assert.Equal(t, ei["resourceId"], got.ResourceID)
		assert.Equal(t, ei["clientId"], got.ClientID)
		assert.Equal(t, ei["createdBy"], got.CreatedBy)
		ec := ei["consent"].(map[string]any)
		require.NotNil(t, got.Consent)
		assert.Equal(t, ec["id"], got.Consent.ID)
		assert.Equal(t, ec["appId"], got.Consent.AppID)
		assert.Equal(t, ec["userId"], got.Consent.UserID)
		scopes := []string{}
		for _, s := range ec["scopes"].([]any) {
			scopes = append(scopes, s.(string))
		}
		assert.Equal(t, scopes, got.Consent.Scopes)
		assert.Equal(t, ec["grantedBy"], got.Consent.GrantedBy)
		assert.EqualValues(t, ec["createdTime"], got.Consent.CreatedTime)
		assert.Equal(t, ec["tenantId"], got.Consent.TenantID)
		assert.EqualValues(t, ec["ExpireTime"], got.Consent.ExpireTime)
		assert.EqualValues(t, ec["modifiedTime"], got.Consent.ModifiedTime)
		assert.Equal(t, ec["authMethod"], got.Consent.AuthMethod)
		assert.Len(t, ec, 10)
		assert.Len(t, ei, 5)
	}
	assert.Len(t, last.ResponseBody, 2)
}

func TestMockAgenticRevokeIdentities(t *testing.T) {
	url := os.Getenv("DESCOPE_MOCK_URL")
	if url == "" {
		t.Skip("DESCOPE_MOCK_URL is not set")
	}
	c := newMockBackendClient(t, url)
	revoked, err := c.Management.Agentic().RevokeIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{
		UserID:     "U2abcdefghijklmnopqrstuvwxyz",
		ClientID:   "client1",
		ResourceID: "resource1",
		ConsentID:  "consent1",
	})
	require.NoError(t, err)

	last := readMockLastCall(t, url)
	require.Equal(t, http.MethodPost, last.Method)
	require.Equal(t, "/v1/mgmt/agentic/identities/revoke", last.Path)
	require.Equal(t, http.StatusOK, last.Status)
	assert.Equal(t, map[string]any{
		"userId":     "U2abcdefghijklmnopqrstuvwxyz",
		"clientId":   "client1",
		"resourceId": "resource1",
		"consentId":  "consent1",
	}, last.Request)

	assert.EqualValues(t, last.ResponseBody["revoked"], revoked)
	assert.Len(t, last.ResponseBody, 1)
}
