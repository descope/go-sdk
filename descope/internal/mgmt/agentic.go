package mgmt

import (
	"context"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/sdk"
)

type agentic struct {
	managementBase
}

var _ sdk.Agentic = &agentic{}

type agenticIdentitiesSearchResp struct {
	Identities []*descope.AgenticIdentity `json:"identities,omitempty"`
	Total      int                        `json:"total,omitempty"`
}

type agenticIdentitiesRevokeResp struct {
	Revoked int `json:"revoked,omitempty"`
}

type governanceAccessRequestsSearchResp struct {
	Requests []*descope.GovernanceAccessRequest `json:"requests,omitempty"`
	Total    int                                `json:"total,omitempty"`
}

func (a *agentic) SearchIdentities(ctx context.Context, options *descope.AgenticIdentitySearchOptions) ([]*descope.AgenticIdentity, int, error) {
	if options == nil {
		options = &descope.AgenticIdentitySearchOptions{}
	}
	resp, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAgenticIdentitiesSearch(), options, nil, "")
	if err != nil {
		return nil, 0, err
	}
	res := &agenticIdentitiesSearchResp{}
	if err = utils.Unmarshal([]byte(resp.BodyStr), res); err != nil {
		return nil, 0, err
	}
	return res.Identities, res.Total, nil
}

func (a *agentic) RevokeIdentities(ctx context.Context, options *descope.AgenticIdentityRevokeOptions) (int, error) {
	if options == nil {
		return 0, utils.NewInvalidArgumentError("options")
	}
	resp, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAgenticIdentitiesRevoke(), options, nil, "")
	if err != nil {
		return 0, err
	}
	res := &agenticIdentitiesRevokeResp{}
	if err = utils.Unmarshal([]byte(resp.BodyStr), res); err != nil {
		return 0, err
	}
	return res.Revoked, nil
}

func (a *agentic) GetGovernanceSettings(ctx context.Context) (*descope.AgenticGovernanceSettings, error) {
	resp, err := a.client.DoGetRequest(ctx, api.Routes.ManagementAgenticGovernanceSettings(), nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalAgenticGovernanceSettings(resp)
}

func (a *agentic) SetGovernanceSettings(ctx context.Context, settings *descope.AgenticGovernanceSettings) (*descope.AgenticGovernanceSettings, error) {
	if settings == nil {
		return nil, utils.NewInvalidArgumentError("settings")
	}
	resp, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAgenticGovernanceSettings(), settings, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalAgenticGovernanceSettings(resp)
}

func (a *agentic) SearchGovernanceAccessRequests(ctx context.Context, options *descope.GovernanceAccessRequestSearchOptions) ([]*descope.GovernanceAccessRequest, int, error) {
	if options == nil {
		options = &descope.GovernanceAccessRequestSearchOptions{}
	}
	for _, s := range options.Sort {
		if s == nil || s.Field == "" {
			return nil, 0, utils.NewInvalidArgumentError("options.Sort.Field")
		}
	}
	resp, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAgenticGovernanceRequestsSearch(), options, nil, "")
	if err != nil {
		return nil, 0, err
	}
	res := &governanceAccessRequestsSearchResp{}
	if err = utils.Unmarshal([]byte(resp.BodyStr), res); err != nil {
		return nil, 0, err
	}
	return res.Requests, res.Total, nil
}

func (a *agentic) GetGovernanceAccessRequest(ctx context.Context, id string) (*descope.GovernanceAccessRequest, error) {
	if id == "" {
		return nil, utils.NewInvalidArgumentError("id")
	}
	body := map[string]any{"id": id}
	resp, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAgenticGovernanceRequestsGet(), body, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalGovernanceAccessRequest(resp)
}

func (a *agentic) ResolveGovernanceAccessRequest(ctx context.Context, id string, action descope.GovernanceAccessRequestAction, resolutionNote string) (*descope.GovernanceAccessRequest, error) {
	if id == "" {
		return nil, utils.NewInvalidArgumentError("id")
	}
	if action == "" {
		return nil, utils.NewInvalidArgumentError("action")
	}
	body := map[string]any{
		"id":     id,
		"action": action,
	}
	if resolutionNote != "" {
		body["resolutionNote"] = resolutionNote
	}
	resp, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAgenticGovernanceRequestsResolve(), body, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalGovernanceAccessRequest(resp)
}

func (a *agentic) CreateGovernanceAccessRequest(ctx context.Context, request *descope.GovernanceAccessRequestCreate) (*descope.GovernanceAccessRequest, error) {
	if request == nil {
		return nil, utils.NewInvalidArgumentError("request")
	}
	if request.RequestorUserID == "" {
		return nil, utils.NewInvalidArgumentError("request.RequestorUserID")
	}
	for _, grantType := range request.GrantTypes {
		if grantType == "" {
			return nil, utils.NewInvalidArgumentError("request.GrantTypes")
		}
	}
	resp, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAgenticGovernanceRequestsCreate(), request, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalGovernanceAccessRequest(resp)
}

func unmarshalAgenticGovernanceSettings(resp *api.HTTPResponse) (*descope.AgenticGovernanceSettings, error) {
	res := &descope.AgenticGovernanceSettings{}
	if err := utils.Unmarshal([]byte(resp.BodyStr), res); err != nil {
		return nil, err
	}
	return res, nil
}

func unmarshalGovernanceAccessRequest(resp *api.HTTPResponse) (*descope.GovernanceAccessRequest, error) {
	res := &descope.GovernanceAccessRequest{}
	if err := utils.Unmarshal([]byte(resp.BodyStr), res); err != nil {
		return nil, err
	}
	return res, nil
}
