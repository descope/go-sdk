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

func (s *agentic) SearchIdentities(ctx context.Context, options *descope.AgenticIdentitySearchOptions) ([]*descope.AgenticIdentity, int, error) {
	if options == nil {
		return nil, 0, utils.NewInvalidArgumentError("options")
	}

	req := map[string]any{
		"userId":     options.UserID,
		"clientId":   options.ClientID,
		"resourceId": options.ResourceID,
		"consentId":  options.ConsentID,
		"page":       options.Page,
		"limit":      options.Limit,
	}
	res, err := s.client.DoPostRequest(ctx, api.Routes.ManagementAgenticIdentitiesSearch(), req, nil, "")
	if err != nil {
		return nil, 0, err
	}
	identitiesRes := struct {
		Identities []*descope.AgenticIdentity
		Total      int
	}{}
	if err := utils.Unmarshal([]byte(res.BodyStr), &identitiesRes); err != nil {
		return nil, 0, err
	}
	return identitiesRes.Identities, identitiesRes.Total, nil
}

func (s *agentic) RevokeIdentities(ctx context.Context, options *descope.AgenticIdentityRevokeOptions) (int, error) {
	if options == nil {
		return 0, utils.NewInvalidArgumentError("options")
	}

	req := map[string]any{
		"userId":     options.UserID,
		"clientId":   options.ClientID,
		"resourceId": options.ResourceID,
		"consentId":  options.ConsentID,
	}
	res, err := s.client.DoPostRequest(ctx, api.Routes.ManagementAgenticIdentitiesRevoke(), req, nil, "")
	if err != nil {
		return 0, err
	}
	revokeRes := struct {
		Revoked int
	}{}
	if err := utils.Unmarshal([]byte(res.BodyStr), &revokeRes); err != nil {
		return 0, err
	}
	return revokeRes.Revoked, nil
}
