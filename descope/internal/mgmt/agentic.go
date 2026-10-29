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
	req := map[string]any{
		"userId":     options.UserID,
		"clientId":   options.ClientID,
		"resourceId": options.ResourceID,
		"consentId":  options.ConsentID,
		"page":       options.Page,
		"limit":      options.Limit,
	}
	res, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAgenticIdentitiesSearch(), req, nil, "")
	if err != nil {
		return nil, 0, err
	}
	ares := struct {
		Identities []*descope.AgenticIdentity `json:"identities"`
		Total      int                        `json:"total"`
	}{}
	if err := utils.Unmarshal([]byte(res.BodyStr), &ares); err != nil {
		return nil, 0, err // notest
	}
	return ares.Identities, ares.Total, nil
}

func (a *agentic) RevokeIdentities(ctx context.Context, options *descope.AgenticIdentityRevokeOptions) (int, error) {
	if options == nil {
		return 0, utils.NewInvalidArgumentError("options")
	}
	if options.UserID == "" && options.ClientID == "" && options.ResourceID == "" && options.ConsentID == "" {
		return 0, utils.NewInvalidArgumentError("options")
	}
	req := map[string]any{
		"userId":     options.UserID,
		"clientId":   options.ClientID,
		"resourceId": options.ResourceID,
		"consentId":  options.ConsentID,
	}
	res, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAgenticIdentitiesRevoke(), req, nil, "")
	if err != nil {
		return 0, err
	}
	ares := struct {
		Revoked int `json:"revoked"`
	}{}
	if err := utils.Unmarshal([]byte(res.BodyStr), &ares); err != nil {
		return 0, err // notest
	}
	return ares.Revoked, nil
}
