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

func (r *flow) RunManagementFlow(ctx context.Context, flowID string, options *descope.MgmtFlowOptions) (map[string]any, error) {
	res, err := r.client.DoPostRequest(ctx, api.Routes.ManagementRunManagementFlow(), map[string]any{
		"flowId":  flowID,
		"options": options,
	}, nil, r.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalManagementFlowResponse(res)
}

func (r *flow) ListFlows(ctx context.Context) (*descope.FlowList, error) {
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

func (r *flow) ExportFlow(ctx context.Context, flowID string) (map[string]any, error) {
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
	return unmarshalFlow(res)
}

func (r *flow) ImportFlow(ctx context.Context, flowID string, flow map[string]any) error {
	if flowID == "" {
		return utils.NewInvalidArgumentError("flowID")
	}
	flow["flowId"] = flowID
	body := map[string]any{
		"flow": flow,
	}
	_, err := r.client.DoPostRequest(ctx, api.Routes.ManagementFlowImport(), body, nil, r.conf.ManagementKey)
	return err
}

func (r *flow) ExportTheme(ctx context.Context) (map[string]any, error) {
	res, err := r.client.DoPostRequest(ctx, api.Routes.ManagementThemeExport(), nil, nil, r.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalTheme(res)
}

func (r *flow) ImportTheme(ctx context.Context, theme map[string]any) error {
	if theme == nil {
		return utils.NewInvalidArgumentError("theme")
	}
	body := map[string]any{
		"theme": theme,
	}
	_, err := r.client.DoPostRequest(ctx, api.Routes.ManagementThemeImport(), body, nil, r.conf.ManagementKey)
	return err
}

func unmarshalFlowsResponse(res *api.HTTPResponse) (*descope.FlowList, error) {
	var a *descope.FlowList
	err := utils.Unmarshal([]byte(res.BodyStr), &a)
	if err != nil {
		// notest
		return nil, err
	}
	return a, nil
}

func unmarshalFlow(res *api.HTTPResponse) (map[string]any, error) {
	type flowResponse struct {
		Flow map[string]any `json:"flow"`
	}
	var a *flowResponse
	err := utils.Unmarshal([]byte(res.BodyStr), &a)
	if err != nil { // notest
		return nil, err
	}
	return a.Flow, nil
}

func unmarshalTheme(res *api.HTTPResponse) (map[string]any, error) {
	type themeResponse struct {
		Theme map[string]any `json:"theme"`
	}
	var a *themeResponse
	err := utils.Unmarshal([]byte(res.BodyStr), &a)
	if err != nil { // notest
		return nil, err
	}
	return a.Theme, nil
}

func unmarshalManagementFlowResponse(res *api.HTTPResponse) (map[string]any, error) {
	type mgmtFlowResponse struct {
		Output map[string]any `json:"output"`
	}
	var resp mgmtFlowResponse
	err := utils.Unmarshal([]byte(res.BodyStr), &resp)
	if err != nil { // notest
		return nil, err
	}
	return resp.Output, nil
}
