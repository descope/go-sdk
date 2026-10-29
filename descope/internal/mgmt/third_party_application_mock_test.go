package mgmt_test

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockLastCall struct {
	Method       string         `json:"method"`
	Path         string         `json:"path"`
	Request      map[string]any `json:"request"`
	ResponseBody map[string]any `json:"responseBody"`
}

func newMockClient(t *testing.T, url string) *client.DescopeClient {
	descopeClient, err := client.NewWithConfig(&client.Config{
		ProjectID:      "P2AAAAAAAAAAAAAAAAAAAAAAAAAA",
		ManagementKey:  "mgmt-key",
		DescopeBaseURL: url,
	})
	require.NoError(t, err)
	return descopeClient
}

func readMockLastCall(t *testing.T, url string) *mockLastCall {
	res, err := http.Get(url + "/__mock/last") // #nosec G107 -- test-only mock URL
	require.NoError(t, err)
	defer res.Body.Close()
	last := &mockLastCall{}
	require.NoError(t, json.NewDecoder(res.Body).Decode(last))
	return last
}

func TestMockSearchAgenticIdentities(t *testing.T) {
	url := os.Getenv("DESCOPE_MOCK_URL")
	if url == "" {
		t.Skip("DESCOPE_MOCK_URL is not set")
	}
	descopeClient := newMockClient(t, url)

	identities, total, err := descopeClient.Management.ThirdPartyApplication().SearchAgenticIdentities(context.Background(), &descope.AgenticIdentitySearchOptions{
		UserID:     "U2AAAAAAAAAAAAAAAAAAAAAAAAAA",
		ClientID:   "client1",
		ResourceID: "resource1",
		ConsentID:  "consent1",
		Page:       1,
		Limit:      10,
	})
	require.NoError(t, err)

	last := readMockLastCall(t, url)
	assert.Equal(t, http.MethodPost, last.Method)
	assert.Equal(t, "/v1/mgmt/agentic/identities/search", last.Path)
	assert.Equal(t, map[string]any{
		"userId":     "U2AAAAAAAAAAAAAAAAAAAAAAAAAA",
		"clientId":   "client1",
		"resourceId": "resource1",
		"consentId":  "consent1",
		"page":       float64(1),
		"limit":      float64(10),
	}, last.Request)

	expected := struct {
		Identities []*descope.AgenticIdentity `json:"identities"`
		Total      int                        `json:"total"`
	}{}
	b, err := json.Marshal(last.ResponseBody)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(b, &expected))
	require.NotEmpty(t, expected.Identities)
	require.NotZero(t, expected.Total)
	assert.Equal(t, expected.Total, total)
	assert.Equal(t, expected.Identities, identities)
	for _, identity := range identities {
		require.NotNil(t, identity.Consent)
		assert.NotEmpty(t, identity.Consent.ID)
		assert.NotEmpty(t, identity.Consent.AppID)
		assert.NotEmpty(t, identity.Consent.UserID)
		assert.NotEmpty(t, identity.Consent.Scopes)
		assert.NotEmpty(t, identity.Consent.GrantedBy)
		assert.NotZero(t, identity.Consent.CreatedTime)
		assert.NotEmpty(t, identity.Consent.TenantID)
		assert.NotZero(t, identity.Consent.ExpireTime)
		assert.NotZero(t, identity.Consent.ModifiedTime)
		assert.NotEmpty(t, identity.AgentName)
		assert.NotEmpty(t, identity.ResourceID)
		assert.NotEmpty(t, identity.ClientID)
		assert.NotEmpty(t, identity.CreatedBy)
	}
}

func TestMockRevokeAgenticIdentities(t *testing.T) {
	url := os.Getenv("DESCOPE_MOCK_URL")
	if url == "" {
		t.Skip("DESCOPE_MOCK_URL is not set")
	}
	descopeClient := newMockClient(t, url)

	revoked, err := descopeClient.Management.ThirdPartyApplication().RevokeAgenticIdentities(context.Background(), &descope.AgenticIdentityRevokeOptions{
		UserID:     "U2AAAAAAAAAAAAAAAAAAAAAAAAAA",
		ClientID:   "client1",
		ResourceID: "resource1",
		ConsentID:  "consent1",
	})
	require.NoError(t, err)

	last := readMockLastCall(t, url)
	assert.Equal(t, http.MethodPost, last.Method)
	assert.Equal(t, "/v1/mgmt/agentic/identities/revoke", last.Path)
	assert.Equal(t, map[string]any{
		"userId":     "U2AAAAAAAAAAAAAAAAAAAAAAAAAA",
		"clientId":   "client1",
		"resourceId": "resource1",
		"consentId":  "consent1",
	}, last.Request)

	require.NotNil(t, last.ResponseBody["revoked"])
	assert.NotZero(t, revoked)
	assert.EqualValues(t, last.ResponseBody["revoked"], revoked)
}
