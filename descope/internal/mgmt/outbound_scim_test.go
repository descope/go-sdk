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
		"appId":         "app-1",
		"configuration": map[string]any{"target": "https://scim.example.com"},
		"enabled":       true,
		"version":       "42",
	}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/outbound/scim/create", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "app-1", req["appId"])
		cfg, ok := req["configuration"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "https://scim.example.com", cfg["target"])
		// id/name/version/enabled must NOT be sent on create (unknown-field-rejecting gateway).
		for _, k := range []string{"id", "name", "version", "enabled"} {
			_, has := req[k]
			assert.False(t, has, "unexpected key %q on create body", k)
		}
	}, response))

	cfg, err := mgmt.OutboundSCIM().CreateConfiguration(context.Background(), &descope.CreateOutboundSCIMConfigurationRequest{
		AppID:         "app-1",
		Configuration: map[string]any{"target": "https://scim.example.com"},
	})
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, "app-1", cfg.AppID)
	assert.True(t, cfg.Enabled)
	assert.Equal(t, int64(42), cfg.Version)
	assert.Equal(t, "https://scim.example.com", cfg.Configuration["target"])
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
		assert.Equal(t, "https://scim.example.com/v2", cfg["target"])
	}, response))

	cfg, err := mgmt.OutboundSCIM().UpdateConfiguration(context.Background(), &descope.UpdateOutboundSCIMConfigurationRequest{
		AppID:         "app-1",
		Configuration: map[string]any{"target": "https://scim.example.com/v2"},
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
	response := map[string]any{"configuration": map[string]any{
		"appId":              "app-1",
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
