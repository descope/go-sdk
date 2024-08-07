package mgmt

import (
	"context"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/sdk"
)

type flow struct {
	managementBase
}

var _ sdk.Flow = &flow{}

func (r *flow) ListFlows(ctx context.Context) (*descope.FlowsResponse, error) {
	res, err := r.client.DoPostRequest(ctx, api.Routes.ManagementListFlows(), nil, nil, r.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalFlowsResponse(res)
}

func (r *flow) DeleteFlows(ctx context.Context, flowIDs []string) error {
	body := map[string]any{
		"ids": flowIDs,
	}
	_, err := r.client.DoPostRequest(ctx, api.Routes.ManagementDeleteFlows(), body, nil, r.conf.ManagementKey)
	return err
}

func (r *flow) ExportFlow(ctx context.Context, flowID string) (*descope.FlowResponse, error) {
	if flowID == "" {
		return nil, utils.NewInvalidArgumentError("flowID")
	}
	body := map[string]any{
		"flowId": flowID,
	}
	res, err := r.client.DoPostRequest(ctx, api.Routes.ManagementFlowExport(), body, nil, r.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalFlowResponse(res)
}

func (r *flow) ImportFlow(ctx context.Context, flowID string, flow *descope.Flow, screens []*descope.Screen) (*descope.FlowResponse, error) {
	if flowID == "" {
		return nil, utils.NewInvalidArgumentError("flowID")
	}
	body := map[string]any{
		"flowId":  flowID,
		"flow":    flow,
		"screens": screens,
	}
	res, err := r.client.DoPostRequest(ctx, api.Routes.ManagementFlowImport(), body, nil, r.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalFlowResponse(res)
}

func (r *flow) ExportTheme(ctx context.Context) (*descope.Theme, error) {
	res, err := r.client.DoPostRequest(ctx, api.Routes.ManagementThemeExport(), nil, nil, r.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalTheme(res)
}

func (r *flow) ImportTheme(ctx context.Context, theme *descope.Theme) (*descope.Theme, error) {
	if theme == nil {
		return nil, utils.NewInvalidArgumentError("theme")
	}
	body := map[string]any{
		"theme": theme,
	}
	res, err := r.client.DoPostRequest(ctx, api.Routes.ManagementThemeImport(), body, nil, r.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalTheme(res)

}

func unmarshalFlowsResponse(res *api.HTTPResponse) (*descope.FlowsResponse, error) {
	var a *descope.FlowsResponse
	err := utils.Unmarshal([]byte(res.BodyStr), &a)
	if err != nil {
		// notest
		return nil, err
	}
	return a, nil
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
