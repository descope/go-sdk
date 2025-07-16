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
	response := &descope.FlowList{
		Flows: []*descope.FlowListEnty{{FlowID: "abc"}},
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
	flow := map[string]any{
		"flowId":   "xyz",
		"metadata": map[string]any{"foo": "bar"},
	}
	body := map[string]any{
		"flow": flow,
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, flowID, req["flowId"])
	}, body))
	res, err := mgmt.Flow().ExportFlow(context.Background(), flowID)
	require.NoError(t, err)
	assert.EqualValues(t, flow, res)
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
	flow := map[string]any{
		"flowId":   "xyz",
		"metadata": map[string]any{"foo": "bar"},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.NotNil(t, req["flow"])
		flow := req["flow"].(map[string]any)
		require.Equal(t, flowID, flow["flowId"])
		require.Equal(t, map[string]any{"foo": "bar"}, flow["metadata"])
	}, nil))
	err := mgmt.Flow().ImportFlow(context.Background(), flowID, flow)
	require.NoError(t, err)
}

func TestImportFlowMissingArgument(t *testing.T) {
	flowID := ""
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.Flow().ImportFlow(context.Background(), flowID, map[string]any{})
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("flowID").Message)
}

func TestExportThemeSuccess(t *testing.T) {
	theme := map[string]any{
		"styles": map[string]any{"foo": "bar"},
	}
	body := map[string]any{
		"theme": theme,
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
	}, body))
	res, err := mgmt.Flow().ExportTheme(context.Background())
	require.NoError(t, err)
	assert.EqualValues(t, theme, res)
}

func TestImportThemeSuccess(t *testing.T) {
	theme := map[string]any{
		"styles": map[string]any{"foo": "bar"},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.NotEmpty(t, req["theme"])
		assert.Equal(t, map[string]any{"styles": map[string]any{"foo": "bar"}}, req["theme"])
	}, nil))
	err := mgmt.Flow().ImportTheme(context.Background(), theme)
	require.NoError(t, err)
}

func TestImportThemeMissingArgument(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.Flow().ImportTheme(context.Background(), nil)
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("theme").Message)
}

func TestRunManagementFlowSuccess(t *testing.T) {
	flowID := "test-flow"
	options := &descope.MgmtFlowOptions{
		Input: map[string]any{"key": "value"},
	}
	output := map[string]any{
		"result": "success",
		"data":   map[string]any{"foo": "bar"},
	}
	body := map[string]any{
		"output": output,
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, flowID, req["flowId"])
		require.NotNil(t, req["options"])
		optionsMap := req["options"].(map[string]any)
		require.Equal(t, map[string]any{"key": "value"}, optionsMap["input"])
	}, body))
	res, err := mgmt.Flow().RunManagementFlow(context.Background(), flowID, options)
	require.NoError(t, err)
	assert.EqualValues(t, output, res)
}

func TestRunManagementFlowSuccessWithNilOptions(t *testing.T) {
	flowID := "test-flow"
	output := map[string]any{
		"result": "success",
	}
	body := map[string]any{
		"output": output,
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, flowID, req["flowId"])
		require.Nil(t, req["options"])
	}, body))
	res, err := mgmt.Flow().RunManagementFlow(context.Background(), flowID, nil)
	require.NoError(t, err)
	assert.EqualValues(t, output, res)
}

func TestRunManagementFlowFailure(t *testing.T) {
	flowID := "test-flow"
	options := &descope.MgmtFlowOptions{
		Input: map[string]any{"key": "value"},
	}
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, flowID, req["flowId"])
		require.NotNil(t, req["options"])
		optionsMap := req["options"].(map[string]any)
		require.Equal(t, map[string]any{"key": "value"}, optionsMap["input"])
	}))
	res, err := mgmt.Flow().RunManagementFlow(context.Background(), flowID, options)
	require.Error(t, err)
	assert.Nil(t, res)
}
