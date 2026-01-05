package mgmt

import (
	"context"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/sdk"
)

type descoper struct {
	managementBase
}

var _ sdk.Descoper = &descoper{}

type descoperGetResp struct {
	Descoper *descope.Descoper `json:"descoper,omitempty"`
}
type descoperUpdateResp descoperGetResp

type descoperListResp struct {
	Descopers []*descope.Descoper `json:"descopers,omitempty"`
	Total     int                 `json:"total,omitempty"`
}
type descoperCreateResp descoperListResp

func (r *descoper) Create(ctx context.Context, descopers []*descope.DescoperCreate) ([]*descope.Descoper, int, error) {
	if len(descopers) == 0 {
		return nil, 0, utils.NewInvalidArgumentError("descopers")
	}
	body := map[string]any{
		"descopers": descopers,
	}
	resp, err := r.client.DoPutRequest(ctx, api.Routes.ManagementDescoperCreate(), body, nil, "")
	if err != nil {
		return nil, 0, err
	}
	res := &descoperCreateResp{}
	err = utils.Unmarshal([]byte(resp.BodyStr), res)
	if err != nil {
		return nil, 0, err
	}
	return res.Descopers, res.Total, nil
}

func (r *descoper) Update(ctx context.Context, id string, attributes *descope.DescoperAttributes, rbac *descope.DescoperRBAC) (*descope.Descoper, error) {
	if id == "" {
		return nil, utils.NewInvalidArgumentError("id")
	}
	body := map[string]any{
		"id": id,
		// following fields are updated on the object
		"attributes": attributes,
		"rbac":       rbac,
	}
	resp, err := r.client.DoPatchRequest(ctx, api.Routes.ManagementDescoperUpdate(), body, nil, "")
	if err != nil {
		return nil, err
	}
	res := &descoperUpdateResp{}
	err = utils.Unmarshal([]byte(resp.BodyStr), res)
	if err != nil {
		return nil, err
	}
	return res.Descoper, nil
}

func (r *descoper) Get(ctx context.Context, id string) (*descope.Descoper, error) {
	if id == "" {
		return nil, utils.NewInvalidArgumentError("id")
	}
	req := &api.HTTPRequest{
		QueryParams: map[string]string{"id": id},
	}
	resp, err := r.client.DoGetRequest(ctx, api.Routes.ManagementDescoperGet(), req, "")
	if err != nil {
		return nil, err
	}

	res := &descoperGetResp{}
	err = utils.Unmarshal([]byte(resp.BodyStr), &res)
	if err != nil {
		return nil, err
	}
	return res.Descoper, nil
}

func (r *descoper) Delete(ctx context.Context, id string) error {
	if id == "" {
		return utils.NewInvalidArgumentError("id")
	}
	req := &api.HTTPRequest{
		QueryParams: map[string]string{"id": id},
	}
	_, err := r.client.DoDeleteRequest(ctx, api.Routes.ManagementDescoperDelete(), req, "")
	if err != nil {
		return err
	}
	return nil
}

func (r *descoper) List(ctx context.Context, _ *descope.DescoperLoadOptions) ([]*descope.Descoper, int, error) {
	body := map[string]any{}
	resp, err := r.client.DoPostRequest(ctx, api.Routes.ManagementDescoperSearch(), body, nil, "")
	if err != nil {
		return nil, 0, err
	}

	res := &descoperListResp{}
	err = utils.Unmarshal([]byte(resp.BodyStr), &res)
	if err != nil {
		return nil, 0, err
	}
	return res.Descopers, res.Total, nil
}
