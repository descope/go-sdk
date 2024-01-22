package mgmt

import (
	"context"
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/tests/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListFlowsSuccess(t *testing.T) {
	response := &descope.FlowsResponse{
		Flows: []*descope.FlowMetadata{{ID: "abc"}},
		Total: 1,
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
	}, response))
	res, err := mgmt.Flow().ListFlows(context.Background())
	require.NoError(t, err)
	assert.EqualValues(t, response, res)
}

func TestDeleteFlowsSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
	}, nil))
	err := mgmt.Flow().DeleteFlows(context.Background(), []string{"flow-1", "flow-2"})
	require.NoError(t, err)
}

func TestDeleteFlowsFailure(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
	}))
	err := mgmt.Flow().DeleteFlows(context.Background(), []string{"flow-1", "flow-2"})
	require.Error(t, err)
}

func TestExportFlowSuccess(t *testing.T) {
	flowID := "abc"
	response := &descope.FlowResponse{
		Flow:    &descope.Flow{FlowMetadata: descope.FlowMetadata{ID: flowID}},
		Screens: []*descope.Screen{},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, flowID, req["flowId"])
	}, response))
	res, err := mgmt.Flow().ExportFlow(context.Background(), flowID)
	require.NoError(t, err)
	assert.EqualValues(t, response, res)
}

func TestExportFlowMissingArgument(t *testing.T) {
	flowID := ""
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.Flow().ExportFlow(context.Background(), flowID)
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("flowID").Message)
	assert.Nil(t, res)
}

func TestImportFlowSuccess(t *testing.T) {
	flowID := "abc"
	response := &descope.FlowResponse{
		Flow:    &descope.Flow{FlowMetadata: descope.FlowMetadata{ID: flowID}},
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
	res, err := mgmt.Flow().ImportFlow(context.Background(), flowID, response.Flow, response.Screens)
	require.NoError(t, err)
	assert.EqualValues(t, response, res)
}

func TestImportFlowMissingArgument(t *testing.T) {
	flowID := ""
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.Flow().ImportFlow(context.Background(), flowID, &descope.Flow{}, nil)
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
	res, err := mgmt.Flow().ExportTheme(context.Background())
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
	res, err := mgmt.Flow().ImportTheme(context.Background(), theme)
	require.NoError(t, err)
	assert.EqualValues(t, theme, res)
}

func TestImportThemeMissingArgument(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.Flow().ImportTheme(context.Background(), nil)
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("theme").Message)
	assert.Nil(t, res)
}
