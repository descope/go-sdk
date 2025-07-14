package mgmt

import (
	"context"
	"strconv"

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

func (f *fga) DryRunSchema(ctx context.Context, schema *descope.FGASchema) (*descope.FGASchemaDryRunResponse, error) {
	if schema == nil {
		return nil, utils.NewInvalidArgumentError("schema")
	}
	body := &DSLSchema{
		DSL: schema.Schema,
	}

	options := &api.HTTPRequest{}
	res, err := f.client.DoPostRequest(ctx, api.Routes.ManagementFGASchemaDryRun(), body, options, f.conf.ManagementKey)
	if err != nil {
		return nil, err
	}

	var dryRunResponse *descope.FGASchemaDryRunResponse
	err = utils.Unmarshal([]byte(res.BodyStr), &dryRunResponse)
	if err != nil {
		return nil, err // notest
	}
	return dryRunResponse, nil
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

func (f *fga) LoadMappableSchema(ctx context.Context, tenantID string, options *descope.FGAMappableResourcesOptions) (*descope.FGAMappableSchema, error) {
	if tenantID == "" {
		return nil, utils.NewInvalidArgumentError("tenantID")
	}

	params := map[string]string{"tenantId": tenantID}
	if options != nil && options.ResourcesLimit > 0 {
		params["resourcesLimit"] = strconv.Itoa(int(options.ResourcesLimit))
	}
	req := &api.HTTPRequest{
		QueryParams: params,
	}
	res, err := f.client.DoGetRequest(ctx, api.Routes.ManagementFGALoadMappableSchema(), req, f.conf.ManagementKey)
	if err != nil {
		return nil, err
	}

	var mappableSchema *descope.FGAMappableSchema
	err = utils.Unmarshal([]byte(res.BodyStr), &mappableSchema)
	if err != nil {
		return nil, err // notest
	}
	return mappableSchema, nil
}

type mappableResourcesResponse struct {
	FGAMappableResources []*descope.FGAMappableResources `json:"mappableResources"`
}

func (f *fga) SearchMappableResources(ctx context.Context, tenantID string, resourcesQueries []*descope.FGAMappableResourcesQuery, options *descope.FGAMappableResourcesOptions) ([]*descope.FGAMappableResources, error) {
	if tenantID == "" {
		return nil, utils.NewInvalidArgumentError("tenantID")
	}

	if len(resourcesQueries) == 0 {
		return nil, utils.NewInvalidArgumentError("resourcesQueries")
	}

	body := map[string]any{
		"tenantId":         tenantID,
		"resourcesQueries": resourcesQueries,
	}
	if options != nil && options.ResourcesLimit > 0 {
		body["resourcesLimit"] = strconv.Itoa(int(options.ResourcesLimit))
	}

	res, err := f.client.DoPostRequest(ctx, api.Routes.ManagementFGASearchMappableResources(), body, nil, f.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	var mappableResources *mappableResourcesResponse
	err = utils.Unmarshal([]byte(res.BodyStr), &mappableResources)
	if err != nil {
		return nil, err // notest
	}

	return mappableResources.FGAMappableResources, nil
}

type resourcesDetailsResponse struct {
	ResourcesDetails []*descope.ResourceDetails `json:"resourcesDetails"`
}

func (f *fga) LoadResourcesDetails(ctx context.Context, resourceIdentifiers []*descope.ResourceIdentifier) ([]*descope.ResourceDetails, error) {
	if len(resourceIdentifiers) == 0 {
		return nil, utils.NewInvalidArgumentError("resourceIdentifiers")
	}

	body := map[string]any{
		"resourceIdentifiers": resourceIdentifiers,
	}

	res, err := f.client.DoPostRequest(ctx, api.Routes.ManagementFGAResourcesLoad(), body, nil, f.conf.ManagementKey)
	if err != nil {
		return nil, err
	}

	var resp resourcesDetailsResponse
	if err := utils.Unmarshal([]byte(res.BodyStr), &resp); err != nil {
		return nil, err // notest
	}
	return resp.ResourcesDetails, nil
}

func (f *fga) SaveResourcesDetails(ctx context.Context, resourcesDetails []*descope.ResourceDetails) error {
	if len(resourcesDetails) == 0 {
		return utils.NewInvalidArgumentError("resourcesDetails")
	}

	body := map[string]any{
		"resourcesDetails": resourcesDetails,
	}

	_, err := f.client.DoPostRequest(ctx, api.Routes.ManagementFGAResourcesSave(), body, nil, f.conf.ManagementKey)
	return err
}
