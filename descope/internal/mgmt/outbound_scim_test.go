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

func TestOutboundSCIMCreateSuccess(t *testing.T) {
	// Version arrives as a JSON string in proto3 — verify the SDK unmarshals it back into int64.
	response := map[string]any{"configuration": map[string]any{
		"appId": "app-1",
		"configuration": map[string]any{
			"baseUrl":                "https://scim.example.com",
			"ignoreUnverifiedPhones": true,
			"authentication":         map[string]any{"method": "bearerToken", "bearerToken": "sekret"},
		},
		"enabled": true,
		"version": "42",
	}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/outbound/scim/create", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "app-1", req["appId"])
		cfg, ok := req["configuration"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "https://scim.example.com", cfg["baseUrl"])
		assert.Equal(t, true, cfg["ignoreUnverifiedPhones"])
		auth, ok := cfg["authentication"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "bearerToken", auth["method"])
		assert.Equal(t, "sekret", auth["bearerToken"])
		// id/name/version/enabled must NOT be sent on create (unknown-field-rejecting gateway).
		for _, k := range []string{"id", "name", "version", "enabled"} {
			_, has := req[k]
			assert.False(t, has, "unexpected key %q on create body", k)
		}
	}, response))

	cfg, err := mgmt.OutboundSCIM().CreateConfiguration(context.Background(), &descope.CreateOutboundSCIMConfigurationRequest{
		AppID: "app-1",
		Configuration: &descope.OutboundSCIMConfigurationData{
			BaseURL:                "https://scim.example.com",
			IgnoreUnverifiedPhones: true,
			Authentication: &descope.OutboundSCIMHTTPAuth{
				Method:      descope.OutboundSCIMAuthMethodBearerToken,
				BearerToken: "sekret",
			},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, "app-1", cfg.AppID)
	assert.True(t, cfg.Enabled)
	assert.Equal(t, int64(42), cfg.Version)
	require.NotNil(t, cfg.Configuration)
	assert.Equal(t, "https://scim.example.com", cfg.Configuration.BaseURL)
	assert.True(t, cfg.Configuration.IgnoreUnverifiedPhones)
	require.NotNil(t, cfg.Configuration.Authentication)
	assert.Equal(t, descope.OutboundSCIMAuthMethodBearerToken, cfg.Configuration.Authentication.Method)
	assert.Equal(t, "sekret", cfg.Configuration.Authentication.BearerToken)
}

func TestOutboundSCIMCreateError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		called = true
	}))

	// nil request
	cfg, err := mgmt.OutboundSCIM().CreateConfiguration(context.Background(), nil)
	require.Error(t, err)
	require.Nil(t, cfg)

	// missing AppID
	cfg, err = mgmt.OutboundSCIM().CreateConfiguration(context.Background(), &descope.CreateOutboundSCIMConfigurationRequest{})
	require.Error(t, err)
	require.Nil(t, cfg)
	require.False(t, called)
}

func TestOutboundSCIMUpdateSuccess(t *testing.T) {
	response := map[string]any{"configuration": map[string]any{
		"appId":   "app-1",
		"version": "43",
	}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/outbound/scim/update", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "app-1", req["appId"])
		// Version int64 must serialize as a JSON string.
		assert.Equal(t, "42", req["version"])
		cfg, ok := req["configuration"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "https://scim.example.com/v2", cfg["baseUrl"])
	}, response))

	cfg, err := mgmt.OutboundSCIM().UpdateConfiguration(context.Background(), &descope.UpdateOutboundSCIMConfigurationRequest{
		AppID:         "app-1",
		Configuration: &descope.OutboundSCIMConfigurationData{BaseURL: "https://scim.example.com/v2"},
		Version:       42,
	})
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, "app-1", cfg.AppID)
	assert.Equal(t, int64(43), cfg.Version)
}

func TestOutboundSCIMUpdateError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		called = true
	}))

	// nil request
	cfg, err := mgmt.OutboundSCIM().UpdateConfiguration(context.Background(), nil)
	require.Error(t, err)
	require.Nil(t, cfg)

	// missing AppID
	cfg, err = mgmt.OutboundSCIM().UpdateConfiguration(context.Background(), &descope.UpdateOutboundSCIMConfigurationRequest{})
	require.Error(t, err)
	require.Nil(t, cfg)
	require.False(t, called)
}

func TestOutboundSCIMDeleteSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/outbound/scim/delete", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "app-1", req["appId"])
	}))
	err := mgmt.OutboundSCIM().DeleteConfiguration(context.Background(), "app-1")
	require.NoError(t, err)
}

func TestOutboundSCIMDeleteError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		called = true
	}))

	err := mgmt.OutboundSCIM().DeleteConfiguration(context.Background(), "")
	require.Error(t, err)
	require.False(t, called)
}

func TestOutboundSCIMLoadSuccess(t *testing.T) {
	// Load exercises the concrete configuration shape end-to-end — baseUrl,
	// ignoreUnverifiedEmails, userMapping, authentication, headers, and awsAuthType
	// all round-trip into the typed struct.
	response := map[string]any{"configuration": map[string]any{
		"appId": "app-1",
		"configuration": map[string]any{
			"baseUrl":                "https://scim.example.com",
			"ignoreUnverifiedEmails": true,
			"userMapping": []map[string]any{
				{"srcKey": "customAttributes.foo", "namespace": "urn:lulu", "destKey": "cstm"},
			},
			"authentication": map[string]any{
				"method":    "basicAuth",
				"basicAuth": map[string]any{"username": "u", "password": "p"},
			},
			"headers":     []map[string]any{{"key": "X-Trace", "value": "1", "secret": false}},
			"awsAuthType": "none",
		},
		"lastExportTime":     1720000000,
		"lastProcessingTime": 1720000500,
		"failures":           3,
		"version":            "7",
	}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Contains(t, r.URL.Path, "/v1/mgmt/outbound/scim/app-1")
	}, response))

	cfg, err := mgmt.OutboundSCIM().LoadConfiguration(context.Background(), "app-1")
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, "app-1", cfg.AppID)
	assert.Equal(t, int32(1720000000), cfg.LastExportTime)
	assert.Equal(t, int32(1720000500), cfg.LastProcessingTime)
	assert.Equal(t, int32(3), cfg.Failures)
	assert.Equal(t, int64(7), cfg.Version)
	require.NotNil(t, cfg.Configuration)
	assert.Equal(t, "https://scim.example.com", cfg.Configuration.BaseURL)
	assert.True(t, cfg.Configuration.IgnoreUnverifiedEmails)
	assert.Equal(t, "none", cfg.Configuration.AWSAuthType)
	require.Len(t, cfg.Configuration.UserMapping, 1)
	assert.Equal(t, "customAttributes.foo", cfg.Configuration.UserMapping[0].SrcKey)
	assert.Equal(t, "urn:lulu", cfg.Configuration.UserMapping[0].Namespace)
	assert.Equal(t, "cstm", cfg.Configuration.UserMapping[0].DestKey)
	require.NotNil(t, cfg.Configuration.Authentication)
	assert.Equal(t, descope.OutboundSCIMAuthMethodBasic, cfg.Configuration.Authentication.Method)
	require.NotNil(t, cfg.Configuration.Authentication.BasicAuth)
	assert.Equal(t, "u", cfg.Configuration.Authentication.BasicAuth.Username)
	assert.Equal(t, "p", cfg.Configuration.Authentication.BasicAuth.Password)
	require.Len(t, cfg.Configuration.Headers, 1)
	assert.Equal(t, "X-Trace", cfg.Configuration.Headers[0].Key)
	assert.Equal(t, "1", cfg.Configuration.Headers[0].Value)
	assert.False(t, cfg.Configuration.Headers[0].Secret)
}

func TestOutboundSCIMLoadError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		called = true
	}))

	cfg, err := mgmt.OutboundSCIM().LoadConfiguration(context.Background(), "")
	require.Error(t, err)
	require.Nil(t, cfg)
	require.False(t, called)
}

func TestOutboundSCIMSetEnabledSuccess(t *testing.T) {
	response := map[string]any{"configuration": map[string]any{
		"appId":   "app-1",
		"enabled": true,
		"version": "8",
	}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/outbound/scim/enabled/set", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "app-1", req["appId"])
		assert.Equal(t, true, req["enabled"])
	}, response))

	cfg, err := mgmt.OutboundSCIM().SetEnabled(context.Background(), "app-1", true)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, "app-1", cfg.AppID)
	assert.True(t, cfg.Enabled)
	assert.Equal(t, int64(8), cfg.Version)
}

func TestOutboundSCIMSetEnabledFalse(t *testing.T) {
	// Disable — verify enabled:false is transmitted.
	response := map[string]any{"configuration": map[string]any{"appId": "app-1"}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, false, req["enabled"])
	}, response))

	cfg, err := mgmt.OutboundSCIM().SetEnabled(context.Background(), "app-1", false)
	require.NoError(t, err)
	require.NotNil(t, cfg)
}

func TestOutboundSCIMSetEnabledError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		called = true
	}))

	cfg, err := mgmt.OutboundSCIM().SetEnabled(context.Background(), "", true)
	require.Error(t, err)
	require.Nil(t, cfg)
	require.False(t, called)
}
