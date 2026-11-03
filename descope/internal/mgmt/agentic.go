package mgmt

import (
	"context"
	"fmt"

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
		return nil, 0, utils.NewInvalidArgumentError("options")
	}
	res, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAgenticIdentitiesSearch(), options, nil, "")
	if err != nil {
		return nil, 0, err
	}
	ires := struct {
		Identities []*descope.AgenticIdentity `json:"identities"`
		Total      int                        `json:"total"`
	}{}
	if err := utils.Unmarshal([]byte(res.BodyStr), &ires); err != nil {
		return nil, 0, err // notest
	}
	return ires.Identities, ires.Total, nil
}

func (a *agentic) RevokeIdentities(ctx context.Context, options *descope.AgenticIdentityRevokeOptions) (int, error) {
	if options == nil {
		return 0, utils.NewInvalidArgumentError("options")
	}
	res, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAgenticIdentitiesRevoke(), options, nil, "")
	if err != nil {
		return 0, err
	}
	rres := struct {
		Revoked int `json:"revoked"`
	}{}
	if err := utils.Unmarshal([]byte(res.BodyStr), &rres); err != nil {
		return 0, err // notest
	}
	return rres.Revoked, nil
}

func (a *agentic) GetGovernanceSettings(ctx context.Context) (*descope.AgenticGovernanceSettings, error) {
	res, err := a.client.DoGetRequest(ctx, api.Routes.ManagementAgenticGovernanceSettings(), nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalAgenticGovernanceSettings(res)
}

func (a *agentic) SetGovernanceSettings(ctx context.Context, settings *descope.AgenticGovernanceSettings) (*descope.AgenticGovernanceSettings, error) {
	if settings == nil {
		return nil, utils.NewInvalidArgumentError("settings")
	}
	res, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAgenticGovernanceSettings(), settings, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalAgenticGovernanceSettings(res)
}

func (a *agentic) SearchGovernanceAccessRequests(ctx context.Context, options *descope.GovernanceAccessRequestSearchOptions) ([]*descope.GovernanceAccessRequest, int, error) {
	if options == nil {
		return nil, 0, utils.NewInvalidArgumentError("options")
	}
	for i, sort := range options.Sort {
		if sort == nil || sort.Field == "" {
			return nil, 0, utils.NewInvalidArgumentError(fmt.Sprintf("options.Sort[%d].Field", i))
		}
	}
	res, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAgenticGovernanceRequestsSearch(), options, nil, "")
	if err != nil {
		return nil, 0, err
	}
	sres := struct {
		Requests []*descope.GovernanceAccessRequest `json:"requests"`
		Total    int                                `json:"total"`
	}{}
	if err := utils.Unmarshal([]byte(res.BodyStr), &sres); err != nil {
		return nil, 0, err
	}
	return sres.Requests, sres.Total, nil
}

func (a *agentic) GetGovernanceAccessRequest(ctx context.Context, id string) (*descope.GovernanceAccessRequest, error) {
	if id == "" {
		return nil, utils.NewInvalidArgumentError("id")
	}
	req := map[string]any{"id": id}
	res, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAgenticGovernanceRequestGet(), req, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalGovernanceAccessRequest(res)
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
	res, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAgenticGovernanceRequestResolve(), req, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalGovernanceAccessRequest(res)
}

func (a *agentic) CreateGovernanceAccessRequest(ctx context.Context, request *descope.GovernanceAccessRequestCreateRequest) (*descope.GovernanceAccessRequest, error) {
	if request == nil {
		return nil, utils.NewInvalidArgumentError("request")
	}
	if request.RequestorUserID == "" {
		return nil, utils.NewInvalidArgumentError("request.RequestorUserID")
	}
	for i, grantType := range request.GrantTypes {
		if grantType == "" {
			return nil, utils.NewInvalidArgumentError(fmt.Sprintf("request.GrantTypes[%d]", i))
		}
	}
	res, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAgenticGovernanceRequestCreate(), request, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalGovernanceAccessRequest(res)
}

func unmarshalAgenticGovernanceSettings(res *api.HTTPResponse) (*descope.AgenticGovernanceSettings, error) {
	settings := &descope.AgenticGovernanceSettings{}
	if err := utils.Unmarshal([]byte(res.BodyStr), settings); err != nil {
		return nil, err // notest
	}
	return settings, nil
}

func unmarshalGovernanceAccessRequest(res *api.HTTPResponse) (*descope.GovernanceAccessRequest, error) {
	request := &descope.GovernanceAccessRequest{}
	if err := utils.Unmarshal([]byte(res.BodyStr), request); err != nil {
		return nil, err
	}
	return request, nil
}
