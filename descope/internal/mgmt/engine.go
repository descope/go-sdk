package mgmt

import (
	"context"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/sdk"
)

type engine struct {
	managementBase
}

var _ sdk.Engine = &engine{}

func (s *engine) Create(ctx context.Context, name string) (*descope.Engine, error) {
	if name == "" {
		return nil, utils.NewInvalidArgumentError("name")
	}
	body := map[string]any{"name": name}
	res, err := s.client.DoPostRequest(ctx, api.Routes.ManagementEngineCreate(), body, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalEngineResponse(res)
}

func (s *engine) Update(ctx context.Context, id, name string) (*descope.Engine, error) {
	if id == "" {
		return nil, utils.NewInvalidArgumentError("id")
	}
	if name == "" {
		return nil, utils.NewInvalidArgumentError("name")
	}
	body := map[string]any{"id": id, "name": name}
	res, err := s.client.DoPostRequest(ctx, api.Routes.ManagementEngineUpdate(), body, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalEngineResponse(res)
}

func (s *engine) Delete(ctx context.Context, id string) error {
	if id == "" {
		return utils.NewInvalidArgumentError("id")
	}
	body := map[string]any{"id": id}
	_, err := s.client.DoPostRequest(ctx, api.Routes.ManagementEngineDelete(), body, nil, "")
	return err
}

func (s *engine) Load(ctx context.Context, id string) (*descope.Engine, error) {
	if id == "" {
		return nil, utils.NewInvalidArgumentError("id")
	}
	req := &api.HTTPRequest{QueryParams: map[string]string{"id": id}}
	res, err := s.client.DoGetRequest(ctx, api.Routes.ManagementEngineLoad(), req, "")
	if err != nil {
		return nil, err
	}
	return unmarshalEngineResponse(res)
}

func (s *engine) LoadAll(ctx context.Context) ([]*descope.Engine, error) {
	res, err := s.client.DoGetRequest(ctx, api.Routes.ManagementEngineLoadAll(), nil, "")
	if err != nil {
		return nil, err
	}
	tmp := &struct {
		Engines []*descope.Engine `json:"engines"`
	}{}
	if err = utils.Unmarshal([]byte(res.BodyStr), tmp); err != nil {
		return nil, err
	}
	return tmp.Engines, nil
}

func (s *engine) RotateSecret(ctx context.Context, id string) (string, error) {
	if id == "" {
		return "", utils.NewInvalidArgumentError("id")
	}
	body := map[string]any{"id": id}
	res, err := s.client.DoPostRequest(ctx, api.Routes.ManagementEngineRotateSecret(), body, nil, "")
	if err != nil {
		return "", err
	}
	tmp := &struct {
		Secret string `json:"secret"`
	}{}
	if err = utils.Unmarshal([]byte(res.BodyStr), tmp); err != nil {
		return "", err
	}
	return tmp.Secret, nil
}

func unmarshalEngineResponse(httpRes *api.HTTPResponse) (*descope.Engine, error) {
	res := &struct {
		Engine *descope.Engine `json:"engine"`
	}{}
	if err := utils.Unmarshal([]byte(httpRes.BodyStr), res); err != nil {
		return nil, err
	}
	return res.Engine, nil
}
