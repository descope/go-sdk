package mgmt

import (
	"context"
	"slices"

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
	sres := struct {
		Identities []*descope.AgenticIdentity `json:"identities"`
		Total      int                        `json:"total"`
	}{}
	if err := utils.Unmarshal([]byte(res.BodyStr), &sres); err != nil {
		return nil, 0, err // notest
	}
	return sres.Identities, sres.Total, nil
}

func (a *agentic) RevokeIdentities(ctx context.Context, options *descope.AgenticIdentityRevokeOptions) (int, error) {
	if options == nil {
		return 0, utils.NewInvalidArgumentError("options")
	}
	if options.UserID == "" && options.ClientID == "" && options.ResourceID == "" && options.ConsentID == "" {
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
	return unmarshalGovernanceSettings(res)
}

func (a *agentic) SetGovernanceSettings(ctx context.Context, settings *descope.AgenticGovernanceSettings) (*descope.AgenticGovernanceSettings, error) {
	if settings == nil {
		return nil, utils.NewInvalidArgumentError("settings")
	}
	res, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAgenticGovernanceSettings(), settings, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalGovernanceSettings(res)
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
	res, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAgenticGovernanceRequestsSearch(), options, nil, "")
	if err != nil {
		return nil, 0, err
	}
	sres := struct {
		Requests []*descope.GovernanceAccessRequest `json:"requests"`
		Total    int                                `json:"total"`
	}{}
	if err := utils.Unmarshal([]byte(res.BodyStr), &sres); err != nil {
		return nil, 0, err // notest
	}
	return sres.Requests, sres.Total, nil
}

func (a *agentic) GetGovernanceAccessRequest(ctx context.Context, id string) (*descope.GovernanceAccessRequest, error) {
	if id == "" {
		return nil, utils.NewInvalidArgumentError("id")
	}
	res, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAgenticGovernanceRequestGet(), map[string]any{"id": id}, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalGovernanceAccessRequest(res)
}

func (a *agentic) ResolveGovernanceAccessRequest(ctx context.Context, id string, action string, resolutionNote string) (*descope.GovernanceAccessRequest, error) {
	if id == "" {
		return nil, utils.NewInvalidArgumentError("id")
	}
	if action == "" {
		return nil, utils.NewInvalidArgumentError("action")
	}
	req := map[string]any{"id": id, "action": action}
	if resolutionNote != "" {
		req["resolutionNote"] = resolutionNote
	}
	res, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAgenticGovernanceRequestResolve(), req, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalGovernanceAccessRequest(res)
}

func (a *agentic) CreateGovernanceAccessRequest(ctx context.Context, request *descope.GovernanceAccessRequestCreate) (*descope.GovernanceAccessRequest, error) {
	if request == nil {
		return nil, utils.NewInvalidArgumentError("request")
	}
	if request.RequestorUserID == "" {
		return nil, utils.NewInvalidArgumentError("request.RequestorUserID")
	}
	if slices.Contains(request.GrantTypes, "") {
		return nil, utils.NewInvalidArgumentError("request.GrantTypes")
	}
	res, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAgenticGovernanceRequestCreate(), request, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalGovernanceAccessRequest(res)
}

func unmarshalGovernanceSettings(res *api.HTTPResponse) (*descope.AgenticGovernanceSettings, error) {
	settings := &descope.AgenticGovernanceSettings{}
	if err := utils.Unmarshal([]byte(res.BodyStr), settings); err != nil {
		return nil, err // notest
	}
	return settings, nil
}

func unmarshalGovernanceAccessRequest(res *api.HTTPResponse) (*descope.GovernanceAccessRequest, error) {
	req := &descope.GovernanceAccessRequest{}
	if err := utils.Unmarshal([]byte(res.BodyStr), req); err != nil {
		return nil, err // notest
	}
	return req, nil
}
