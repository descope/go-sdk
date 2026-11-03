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

func (a *agentic) SearchIdentities(ctx context.Context, options *descope.AgenticIdentitySearchOptions) ([]*descope.AgenticIdentity, int, error) {
	if options == nil {
		options = &descope.AgenticIdentitySearchOptions{}
	}
	res, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAgenticIdentitiesSearch(), options, nil, "")
	if err != nil {
		return nil, 0, err
	}
	identitiesRes := struct {
		Identities []*descope.AgenticIdentity `json:"identities"`
		Total      int                        `json:"total"`
	}{}
	if err := utils.Unmarshal([]byte(res.BodyStr), &identitiesRes); err != nil {
		return nil, 0, err
	}
	return identitiesRes.Identities, identitiesRes.Total, nil
}

func (a *agentic) RevokeIdentities(ctx context.Context, options *descope.AgenticIdentityRevokeOptions) (int, error) {
	if options == nil || (options.UserID == "" && options.ClientID == "" && options.ResourceID == "" && options.ConsentID == "") {
		return 0, utils.NewInvalidArgumentError("options")
	}
	res, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAgenticIdentitiesRevoke(), options, nil, "")
	if err != nil {
		return 0, err
	}
	revokeRes := struct {
		Revoked int `json:"revoked"`
	}{}
	if err := utils.Unmarshal([]byte(res.BodyStr), &revokeRes); err != nil {
		return 0, err
	}
	return revokeRes.Revoked, nil
}

func (a *agentic) GetGovernanceSettings(ctx context.Context) (*descope.AgenticGovernanceSettings, error) {
	res, err := a.client.DoGetRequest(ctx, api.Routes.ManagementAgenticGovernanceSettings(), nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalAgenticGovernanceSettingsResponse(res)
}

func (a *agentic) ConfigureGovernanceSettings(ctx context.Context, settings *descope.AgenticGovernanceSettingsRequest) (*descope.AgenticGovernanceSettings, error) {
	if settings == nil {
		return nil, utils.NewInvalidArgumentError("settings")
	}
	res, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAgenticGovernanceSettings(), settings, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalAgenticGovernanceSettingsResponse(res)
}

func (a *agentic) SearchGovernanceAccessRequests(ctx context.Context, options *descope.GovernanceAccessRequestSearchOptions) ([]*descope.GovernanceAccessRequest, int, error) {
	if options == nil {
		options = &descope.GovernanceAccessRequestSearchOptions{}
	}
	for _, s := range options.Sort {
		if s.Field == "" {
			return nil, 0, utils.NewInvalidArgumentError("options.Sort.Field")
		}
	}
	res, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAgenticGovernanceRequestsSearch(), options, nil, "")
	if err != nil {
		return nil, 0, err
	}
	searchRes := struct {
		Requests []*descope.GovernanceAccessRequest `json:"requests"`
		Total    int                                `json:"total"`
	}{}
	if err := utils.Unmarshal([]byte(res.BodyStr), &searchRes); err != nil {
		return nil, 0, err
	}
	return searchRes.Requests, searchRes.Total, nil
}

func (a *agentic) GetGovernanceAccessRequest(ctx context.Context, id string) (*descope.GovernanceAccessRequest, error) {
	if id == "" {
		return nil, utils.NewInvalidArgumentError("id")
	}
	req := map[string]any{"id": id}
	res, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAgenticGovernanceRequestsGet(), req, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalGovernanceAccessRequestResponse(res)
}

func (a *agentic) ResolveGovernanceAccessRequest(ctx context.Context, id string, action descope.GovernanceAccessRequestAction, resolutionNote string) (*descope.GovernanceAccessRequest, error) {
	if id == "" {
		return nil, utils.NewInvalidArgumentError("id")
	}
	if action == "" {
		return nil, utils.NewInvalidArgumentError("action")
	}
	req := map[string]any{
		"id":     id,
		"action": action,
	}
	if resolutionNote != "" {
		req["resolutionNote"] = resolutionNote
	}
	res, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAgenticGovernanceRequestsResolve(), req, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalGovernanceAccessRequestResponse(res)
}

func (a *agentic) CreateGovernanceAccessRequest(ctx context.Context, request *descope.GovernanceAccessRequestCreateRequest) (*descope.GovernanceAccessRequest, error) {
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
	res, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAgenticGovernanceRequestsCreate(), request, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalGovernanceAccessRequestResponse(res)
}

func unmarshalAgenticGovernanceSettingsResponse(res *api.HTTPResponse) (*descope.AgenticGovernanceSettings, error) {
	settings := &descope.AgenticGovernanceSettings{}
	if err := utils.Unmarshal([]byte(res.BodyStr), settings); err != nil {
		return nil, err
	}
	return settings, nil
}

func unmarshalGovernanceAccessRequestResponse(res *api.HTTPResponse) (*descope.GovernanceAccessRequest, error) {
	request := &descope.GovernanceAccessRequest{}
	if err := utils.Unmarshal([]byte(res.BodyStr), request); err != nil {
		return nil, err
	}
	return request, nil
}
