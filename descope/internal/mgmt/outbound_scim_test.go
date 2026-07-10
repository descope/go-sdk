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
		"id":            "scim-1",
		"name":          "cfg1",
		"appId":         "app-1",
		"configuration": map[string]any{"target": "https://scim.example.com"},
		"enabled":       true,
		"version":       "42",
	}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/outbound/scim/create", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "cfg1", req["name"])
		assert.Equal(t, "app-1", req["appId"])
		cfg, ok := req["configuration"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "https://scim.example.com", cfg["target"])
		// id/version/enabled must NOT be sent on create (unknown-field-rejecting gateway).
		_, hasID := req["id"]
		_, hasVersion := req["version"]
		_, hasEnabled := req["enabled"]
		assert.False(t, hasID)
		assert.False(t, hasVersion)
		assert.False(t, hasEnabled)
	}, response))

	cfg, err := mgmt.OutboundSCIM().CreateConfiguration(context.Background(), &descope.CreateOutboundSCIMConfigurationRequest{
		Name:          "cfg1",
		AppID:         "app-1",
		Configuration: map[string]any{"target": "https://scim.example.com"},
	})
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, "scim-1", cfg.ID)
	assert.Equal(t, "cfg1", cfg.Name)
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

	// missing Name
	cfg, err = mgmt.OutboundSCIM().CreateConfiguration(context.Background(), &descope.CreateOutboundSCIMConfigurationRequest{AppID: "app-1"})
	require.Error(t, err)
	require.Nil(t, cfg)

	// missing AppID
	cfg, err = mgmt.OutboundSCIM().CreateConfiguration(context.Background(), &descope.CreateOutboundSCIMConfigurationRequest{Name: "cfg1"})
	require.Error(t, err)
	require.Nil(t, cfg)
	require.False(t, called)
}

func TestOutboundSCIMUpdateSuccess(t *testing.T) {
	response := map[string]any{"configuration": map[string]any{
		"id":      "scim-1",
		"name":    "cfg1-renamed",
		"appId":   "app-1",
		"version": "43",
	}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/outbound/scim/update", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "scim-1", req["id"])
		assert.Equal(t, "cfg1-renamed", req["name"])
		// Version int64 must serialize as a JSON string.
		assert.Equal(t, "42", req["version"])
		cfg, ok := req["configuration"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "https://scim.example.com/v2", cfg["target"])
	}, response))

	cfg, err := mgmt.OutboundSCIM().UpdateConfiguration(context.Background(), &descope.UpdateOutboundSCIMConfigurationRequest{
		ID:            "scim-1",
		Name:          "cfg1-renamed",
		Configuration: map[string]any{"target": "https://scim.example.com/v2"},
		Version:       42,
	})
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, "scim-1", cfg.ID)
	assert.Equal(t, "cfg1-renamed", cfg.Name)
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

	// missing ID
	cfg, err = mgmt.OutboundSCIM().UpdateConfiguration(context.Background(), &descope.UpdateOutboundSCIMConfigurationRequest{Name: "cfg"})
	require.Error(t, err)
	require.Nil(t, cfg)
	require.False(t, called)
}

func TestOutboundSCIMDeleteSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/outbound/scim/delete", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "scim-1", req["id"])
	}))
	err := mgmt.OutboundSCIM().DeleteConfiguration(context.Background(), "scim-1")
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
		"id":                 "scim-1",
		"name":               "cfg1",
		"appId":              "app-1",
		"lastExportTime":     1720000000,
		"lastProcessingTime": 1720000500,
		"failures":           3,
		"version":            "7",
	}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Contains(t, r.URL.Path, "/v1/mgmt/outbound/scim/scim-1")
	}, response))

	cfg, err := mgmt.OutboundSCIM().LoadConfiguration(context.Background(), "scim-1")
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, "scim-1", cfg.ID)
	assert.Equal(t, "cfg1", cfg.Name)
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

func TestOutboundSCIMLoadAllSuccess(t *testing.T) {
	response := map[string]any{"configurations": []map[string]any{
		{"id": "scim-1", "name": "cfg1", "version": "1"},
		{"id": "scim-2", "name": "cfg2", "version": "2"},
	}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/outbound/scim", r.URL.Path)
	}, response))

	cfgs, err := mgmt.OutboundSCIM().LoadAllConfigurations(context.Background())
	require.NoError(t, err)
	require.Len(t, cfgs, 2)
	assert.Equal(t, "scim-1", cfgs[0].ID)
	assert.Equal(t, "cfg2", cfgs[1].Name)
	assert.Equal(t, int64(2), cfgs[1].Version)
}

func TestOutboundSCIMLoadAllError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	cfgs, err := mgmt.OutboundSCIM().LoadAllConfigurations(context.Background())
	require.Error(t, err)
	require.Nil(t, cfgs)
}

func TestOutboundSCIMSetEnabledSuccess(t *testing.T) {
	response := map[string]any{"configuration": map[string]any{
		"id":      "scim-1",
		"enabled": true,
		"version": "8",
	}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/outbound/scim/enabled/set", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "scim-1", req["id"])
		assert.Equal(t, true, req["enabled"])
	}, response))

	cfg, err := mgmt.OutboundSCIM().SetEnabled(context.Background(), "scim-1", true)
	require.NoError(t, err)
	require.NotNil(t, cfg)
	assert.Equal(t, "scim-1", cfg.ID)
	assert.True(t, cfg.Enabled)
	assert.Equal(t, int64(8), cfg.Version)
}

func TestOutboundSCIMSetEnabledFalse(t *testing.T) {
	// Disable — verify enabled:false is transmitted.
	response := map[string]any{"configuration": map[string]any{"id": "scim-1"}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, false, req["enabled"])
	}, response))

	cfg, err := mgmt.OutboundSCIM().SetEnabled(context.Background(), "scim-1", false)
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
