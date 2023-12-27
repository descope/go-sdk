package mgmt

import (
	"context"
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope/tests/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetPasswordSettingsSuccess(t *testing.T) {
	tenantID := "abc"
	response := map[string]any{
		"tenantID": tenantID,
		"enabled":  true,
		"lock": true,
		"uppercase": true,
		"lowercase": true,
		"minLength": 8,
		"number": true,
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		params := helpers.ReadParams(r)
		require.Equal(t, tenantID, params["tenantId"])
	}, response))
	res, err := mgmt.Password().GetSettings(context.Background(), tenantID)
	require.NoError(t, err)
	assert.True(t, res.Lock)
	assert.True(t, res.Enabled)
	assert.True(t, res.Uppercase)
	assert.True(t, res.Lowercase)
	assert.True(t, res.Number)
	assert.EqualValues(t, 8, res.MinLength)
}

func TestGetPasswordSettingsError(t *testing.T) {
	tenantID := "abc"
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		params := helpers.ReadParams(r)
		require.Equal(t, tenantID, params["tenantId"])
	}))
	res, err := mgmt.Password().GetSettings(context.Background(), tenantID)
	require.Error(t, err)
	assert.Nil(t, res)
}

func TestPasswordConfigureSettingsSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "tenant", req["tenantId"])
		require.Equal(t, true, req["enabled"])
		require.Equal(t, float64(8), req["minLength"])
		require.Equal(t, true, req["uppercase"])
		require.Equal(t, true, req["lowercase"])
		require.Equal(t, true, req["number"])
		require.Equal(t, true, req["nonAlphanumeric"])
		require.Equal(t, true, req["expiration"])
		require.Equal(t, float64(3), req["expirationWeeks"])
		require.Equal(t, true, req["reuse"])
		require.Equal(t, float64(3), req["reuseAmount"])
		require.Equal(t, true, req["lock"])
		require.Equal(t, float64(4), req["lockAttempts"])
		require.Equal(t, "Descope", req["emailServiceProvider"])
		require.Equal(t, "subject", req["emailSubject"])
		require.Equal(t, "body", req["emailBody"])
		require.Equal(t, "text", req["emailBodyPlainText"])
	}))
	err := mgmt.Password().ConfigureSettings(context.Background(), "tenant", true, 8, true, true, true, true, true, 3, true, 3, true, 4, "Descope", "subject", "body", "text", true)
	require.NoError(t, err)
}

func TestPasswordConfigureSettingsError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	err := mgmt.Password().ConfigureSettings(context.Background(), "", true, 8, true, true, true, true, true, 3, true, 3, true, 4, "Descope", "subject", "body", "text", true)
	require.Error(t, err)
}
