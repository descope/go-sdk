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
	c, err := client.NewWithConfig(&client.Config{
		ProjectID:      "P2AAAAAAAAAAAAAAAAAAAAAAAAAA",
		ManagementKey:  "mgmt-key",
		DescopeBaseURL: url,
	})
	require.NoError(t, err)
	return c
}

func readMockLastCall(t *testing.T, url string) *mockLastCall {
	res, err := http.Get(url + "/__mock/last") // #nosec G107 -- test URL from env
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
	c := newMockClient(t, url)
	options := &descope.AgenticIdentitySearchOptions{
		UserID:     "U2AAAAAAAAAAAAAAAAAAAAAAAAAA",
		ClientID:   "client1",
		ResourceID: "res1",
		ConsentID:  "cn1",
		Page:       2,
		Limit:      10,
	}
	res, total, err := c.Management.Agentic().SearchIdentities(context.Background(), options)
	require.NoError(t, err)

	last := readMockLastCall(t, url)
	assert.Equal(t, http.MethodPost, last.Method)
	assert.Equal(t, "/v1/mgmt/agentic/identities/search", last.Path)
	assert.Equal(t, options.UserID, last.Request["userId"])
	assert.Equal(t, options.ClientID, last.Request["clientId"])
	assert.Equal(t, options.ResourceID, last.Request["resourceId"])
	assert.Equal(t, options.ConsentID, last.Request["consentId"])
	assert.EqualValues(t, options.Page, last.Request["page"])
	assert.EqualValues(t, options.Limit, last.Request["limit"])

	assert.EqualValues(t, last.ResponseBody["total"], total)
	identities, ok := last.ResponseBody["identities"].([]any)
	require.True(t, ok)
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
	assert.Equal(t, consent["scopes"], toAnySlice(res[0].Consent.Scopes))
	assert.Equal(t, consent["grantedBy"], res[0].Consent.GrantedBy)
	assert.EqualValues(t, consent["createdTime"], res[0].Consent.CreatedTime)
	assert.Equal(t, consent["tenantId"], res[0].Consent.TenantID)
	assert.EqualValues(t, consent["ExpireTime"], res[0].Consent.ExpireTime)
	assert.EqualValues(t, consent["modifiedTime"], res[0].Consent.ModifiedTime)
}

func TestMockAgenticRevokeIdentities(t *testing.T) {
	url := os.Getenv("DESCOPE_MOCK_URL")
	if url == "" {
		t.Skip("DESCOPE_MOCK_URL is not set")
	}
	c := newMockClient(t, url)
	options := &descope.AgenticIdentityRevokeOptions{
		UserID:     "U2AAAAAAAAAAAAAAAAAAAAAAAAAA",
		ClientID:   "client1",
		ResourceID: "res1",
		ConsentID:  "cn1",
	}
	revoked, err := c.Management.Agentic().RevokeIdentities(context.Background(), options)
	require.NoError(t, err)

	last := readMockLastCall(t, url)
	assert.Equal(t, http.MethodPost, last.Method)
	assert.Equal(t, "/v1/mgmt/agentic/identities/revoke", last.Path)
	assert.Equal(t, options.UserID, last.Request["userId"])
	assert.Equal(t, options.ClientID, last.Request["clientId"])
	assert.Equal(t, options.ResourceID, last.Request["resourceId"])
	assert.Equal(t, options.ConsentID, last.Request["consentId"])

	assert.EqualValues(t, last.ResponseBody["revoked"], revoked)
}

func toAnySlice(s []string) []any {
	res := make([]any, len(s))
	for i, v := range s {
		res[i] = v
	}
	return res
}
