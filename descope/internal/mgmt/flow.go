package mgmt

import (
	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
)

type flow struct {
	managementBase
}

func (r *flow) ExportFlow(flowID string) (*descope.FlowResponse, error) {
	if flowID == "" {
		return nil, utils.NewInvalidArgumentError("flowID")
	}
	body := map[string]any{
		"flowId": flowID,
	}
	res, err := r.client.DoPostRequest(api.Routes.ManagementFlowExport(), body, nil, r.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalFlowResponse(res)
}

func (r *flow) ImportFlow(flowID string, flow *descope.Flow, screens []*descope.Screen) (*descope.FlowResponse, error) {
	if flowID == "" {
		return nil, utils.NewInvalidArgumentError("flowID")
	}
	body := map[string]any{
		"flowId": flowID,
		"flow": flow,
		"screens": screens,
	}
	res, err := r.client.DoPostRequest(api.Routes.ManagementFlowImport(), body, nil, r.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalFlowResponse(res)
}

func (r *flow) ExportTheme() (*descope.Theme, error) {
	res, err := r.client.DoPostRequest(api.Routes.ManagementThemeExport(), nil, nil, r.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalTheme(res)
}

func (r *flow) ImportTheme(theme *descope.Theme) (*descope.Theme, error) {
	if theme == nil {
		return nil, utils.NewInvalidArgumentError("theme")
	}
	body := map[string]any{
		"theme": theme,
	}
	res, err := r.client.DoPostRequest(api.Routes.ManagementThemeImport(), body, nil, r.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalTheme(res)

}

func unmarshalFlowResponse(res *api.HTTPResponse) (*descope.FlowResponse, error) {
	var a *descope.FlowResponse
	err := utils.Unmarshal([]byte(res.BodyStr), &a)
	if err != nil {
		// notest
		return nil, err
	}
	return a, nil
}

func unmarshalTheme(res *api.HTTPResponse) (*descope.Theme, error) {
	var a *descope.Theme
	err := utils.Unmarshal([]byte(res.BodyStr), &a)
	if err != nil {
		// notest
		return nil, err
	}
	return a, nil
}
