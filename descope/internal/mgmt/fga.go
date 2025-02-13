package mgmt

import (
	"context"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/sdk"
)

type fga struct {
	managementBase
	fgaCacheURL string
}

var _ sdk.FGA = &fga{} // Ensure that the fga struct implements the sdk.FGA interface

type DSLSchema struct {
	DSL string `json:"dsl"`
}

func (f *fga) SaveSchema(ctx context.Context, schema *descope.FGASchema) error {
	if schema == nil {
		return utils.NewInvalidArgumentError("schema")
	}
	body := &DSLSchema{
		DSL: schema.Schema,
	}

	options := &api.HTTPRequest{}
	options.BaseURL = f.fgaCacheURL
	_, err := f.client.DoPostRequest(ctx, api.Routes.ManagementFGASaveSchema(), body, options, f.conf.ManagementKey)
	return err
}

func (f *fga) LoadSchema(ctx context.Context) (*descope.FGASchema, error) {
	res, err := f.client.DoGetRequest(ctx, api.Routes.ManagementFGALoadSchema(), nil, f.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	var dslSchema *DSLSchema
	err = utils.Unmarshal([]byte(res.BodyStr), &dslSchema)
	if err != nil {
		return nil, err // notest
	}
	return &descope.FGASchema{Schema: dslSchema.DSL}, nil
}

func (f *fga) CreateRelations(ctx context.Context, relations []*descope.FGARelation) error {
	if len(relations) == 0 {
		return utils.NewInvalidArgumentError("relations")
	}

	body := map[string]any{
		"tuples": relations,
	}

	options := &api.HTTPRequest{}
	options.BaseURL = f.fgaCacheURL
	_, err := f.client.DoPostRequest(ctx, api.Routes.ManagementFGACreateRelations(), body, options, f.conf.ManagementKey)
	return err
}

func (f *fga) DeleteRelations(ctx context.Context, relations []*descope.FGARelation) error {
	if len(relations) == 0 {
		return utils.NewInvalidArgumentError("relations")
	}

	body := map[string]any{
		"tuples": relations,
	}

	options := &api.HTTPRequest{}
	options.BaseURL = f.fgaCacheURL
	_, err := f.client.DoPostRequest(ctx, api.Routes.ManagementFGADeleteRelations(), body, options, f.conf.ManagementKey)
	return err
}

type CheckResponseTuple struct {
	Allowed bool                  `json:"allowed"`
	Tuple   *descope.FGARelation  `json:"tuple"`
	Info    *descope.FGACheckInfo `json:"info"`
}

type checkResponse struct {
	CheckResponseTuple []*CheckResponseTuple `json:"tuples"`
}

func (f *fga) Check(ctx context.Context, relations []*descope.FGARelation) ([]*descope.FGACheck, error) {
	if len(relations) == 0 {
		return nil, utils.NewInvalidArgumentError("relations")
	}

	body := map[string]any{
		"tuples": relations,
	}

	options := &api.HTTPRequest{}
	options.BaseURL = f.fgaCacheURL
	res, err := f.client.DoPostRequest(ctx, api.Routes.ManagementFGACheck(), body, options, f.conf.ManagementKey)
	if err != nil {
		return nil, err
	}

	var response *checkResponse
	err = utils.Unmarshal([]byte(res.BodyStr), &response)
	if err != nil {
		return nil, err
	}

	checks := make([]*descope.FGACheck, len(response.CheckResponseTuple))
	for i, tuple := range response.CheckResponseTuple {
		var direct bool
		if tuple.Info != nil {
			direct = tuple.Info.Direct
		}
		checks[i] = &descope.FGACheck{
			Relation: tuple.Tuple,
			Allowed:  tuple.Allowed,
			Info:     &descope.FGACheckInfo{Direct: direct},
		}
	}

	return checks, nil
}
