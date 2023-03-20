package mgmt

import (
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/tests/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExportFlowSuccess(t *testing.T) {
	flowID := "abc"
	response := &descope.FlowResponse{
		Flow: descope.Flow{ID: flowID},
		Screens: []*descope.Screen{},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, flowID, req["flowId"])
	}, response))
	res, err := mgmt.Flow().ExportFlow(flowID)
	require.NoError(t, err)
	assert.EqualValues(t, response, res)
}

func TestExportFlowMissingArgument(t *testing.T) {
	flowID := ""
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.Flow().ExportFlow(flowID)
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("flowID").Message)
	assert.Nil(t, res)
}

func TestImportFlowSuccess(t *testing.T) {
	flowID := "abc"
	response := &descope.FlowResponse{
		Flow: descope.Flow{ID: flowID},
		Screens: []*descope.Screen{{}},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, flowID, req["flowId"])
		require.NotEmpty(t, req["flow"])
		require.Len(t, req["screens"], 1)
	}, response))
	res, err := mgmt.Flow().ImportFlow(flowID, &response.Flow, response.Screens)
	require.NoError(t, err)
	assert.EqualValues(t, response, res)
}

func TestImportFlowMissingArgument(t *testing.T) {
	flowID := ""
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.Flow().ImportFlow(flowID, &descope.Flow{}, nil)
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("flowID").Message)
	assert.Nil(t, res)
}

func TestExportThemeSuccess(t *testing.T) {
	theme := &descope.Theme{
		ID: "aa",
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
	}, theme))
	res, err := mgmt.Flow().ExportTheme()
	require.NoError(t, err)
	assert.EqualValues(t, theme, res)
}

func TestImportThemeSuccess(t *testing.T) {
	theme := &descope.Theme{
		ID: "asas",
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.NotEmpty(t, req["theme"])
	}, theme))
	res, err := mgmt.Flow().ImportTheme(theme)
	require.NoError(t, err)
	assert.EqualValues(t, theme, res)
}
