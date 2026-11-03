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
		Input:  map[string]any{"key": "value"},
		Tenant: "tenant-id",
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
		require.Equal(t, "tenant-id", optionsMap["tenant"])
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

func TestRunManagementFlowAsyncSuccess(t *testing.T) {
	flowID := "test-flow"
	options := &descope.MgmtFlowOptions{
		Input: map[string]any{"key": "value"},
	}
	executionID := "exec-123"
	body := map[string]any{
		"executionId": executionID,
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
	res, err := mgmt.Flow().RunManagementFlowAsync(context.Background(), flowID, options)
	require.NoError(t, err)
	assert.Equal(t, executionID, res)
}

func TestRunManagementFlowAsyncSuccessWithNilOptions(t *testing.T) {
	flowID := "test-flow"
	executionID := "exec-456"
	body := map[string]any{
		"executionId": executionID,
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, flowID, req["flowId"])
		require.Nil(t, req["options"])
	}, body))
	res, err := mgmt.Flow().RunManagementFlowAsync(context.Background(), flowID, nil)
	require.NoError(t, err)
	assert.Equal(t, executionID, res)
}

func TestRunManagementFlowAsyncFailure(t *testing.T) {
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
	res, err := mgmt.Flow().RunManagementFlowAsync(context.Background(), flowID, options)
	require.Error(t, err)
	assert.Equal(t, "", res)
}

func TestGetManagementFlowAsyncResultSuccess(t *testing.T) {
	executionID := "exec-789"
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
		require.Equal(t, executionID, req["executionId"])
	}, body))
	res, err := mgmt.Flow().GetManagementFlowAsyncResult(context.Background(), executionID)
	require.NoError(t, err)
	assert.EqualValues(t, output, res)
}

func TestGetManagementFlowAsyncResultFailure(t *testing.T) {
	executionID := "exec-invalid"
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, executionID, req["executionId"])
	}))
	res, err := mgmt.Flow().GetManagementFlowAsyncResult(context.Background(), executionID)
	require.Error(t, err)
	assert.Nil(t, res)
}

func TestGetTenantThemeSuccess(t *testing.T) {
	body := map[string]any{
		"styles":            map[string]any{"light": map[string]any{"foo": "bar"}},
		"componentsVersion": "1.2.3",
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/v1/mgmt/theme/tenant/t1", r.URL.Path)
	}, body))
	res, err := mgmt.Flow().GetTenantTheme(context.Background(), "t1")
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.EqualValues(t, map[string]any{"light": map[string]any{"foo": "bar"}}, res.Styles)
	assert.Equal(t, "1.2.3", res.ComponentsVersion)
}

func TestGetTenantThemeMissingArgument(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.Flow().GetTenantTheme(context.Background(), "")
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("tenantID").Message)
	require.Nil(t, res)
}

func TestGetTenantThemeError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.Flow().GetTenantTheme(context.Background(), "t1")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestSetTenantThemeSuccess(t *testing.T) {
	styles := map[string]any{"light": map[string]any{"foo": "bar"}}
	body := map[string]any{
		"styles":            styles,
		"componentsVersion": "1.2.3",
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/theme/tenant/t1", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, map[string]any{"styles": styles}, req)
	}, body))
	res, err := mgmt.Flow().SetTenantTheme(context.Background(), "t1", &descope.TenantTheme{Styles: styles})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.EqualValues(t, styles, res.Styles)
	assert.Equal(t, "1.2.3", res.ComponentsVersion)
}

func TestSetTenantThemeMissingArguments(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	styles := map[string]any{"light": map[string]any{}}
	res, err := mgmt.Flow().SetTenantTheme(context.Background(), "", &descope.TenantTheme{Styles: styles})
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("tenantID").Message)
	require.Nil(t, res)
	res, err = mgmt.Flow().SetTenantTheme(context.Background(), "t1", nil)
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("theme").Message)
	require.Nil(t, res)
	res, err = mgmt.Flow().SetTenantTheme(context.Background(), "t1", &descope.TenantTheme{})
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("theme.Styles").Message)
	require.Nil(t, res)
}

func TestSetTenantThemeError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.Flow().SetTenantTheme(context.Background(), "t1", &descope.TenantTheme{Styles: map[string]any{}})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestDeleteTenantThemeSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		require.Equal(t, http.MethodDelete, r.Method)
		require.Equal(t, "/v1/mgmt/theme/tenant/t1", r.URL.Path)
	}))
	err := mgmt.Flow().DeleteTenantTheme(context.Background(), "t1")
	require.NoError(t, err)
}

func TestDeleteTenantThemeMissingArgument(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.Flow().DeleteTenantTheme(context.Background(), "")
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("tenantID").Message)
}
