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
		return nil, 0, utils.NewInvalidArgumentError("options")
	}
	res, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAgenticIdentitiesSearch(), options, nil, "")
	if err != nil {
		return nil, 0, err
	}
	tmp := &struct {
		Identities []*descope.AgenticIdentity `json:"identities"`
		Total      int                        `json:"total"`
	}{}
	if err = utils.Unmarshal([]byte(res.BodyStr), tmp); err != nil {
		return nil, 0, err
	}
	return tmp.Identities, tmp.Total, nil
}

func (a *agentic) RevokeIdentities(ctx context.Context, options *descope.AgenticIdentityRevokeOptions) (int, error) {
	if options == nil {
		return 0, utils.NewInvalidArgumentError("options")
	}
	res, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAgenticIdentitiesRevoke(), options, nil, "")
	if err != nil {
		return 0, err
	}
	tmp := &struct {
		Revoked int `json:"revoked"`
	}{}
	if err = utils.Unmarshal([]byte(res.BodyStr), tmp); err != nil {
		return 0, err
	}
	return tmp.Revoked, nil
}
