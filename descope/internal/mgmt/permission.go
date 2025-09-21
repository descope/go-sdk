package mgmt

import (
	"context"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/sdk"
)

type permission struct {
	managementBase
}

var _ sdk.Permission = &permission{}

func (p *permission) Create(ctx context.Context, name, description string) error {
	if name == "" {
		return utils.NewInvalidArgumentError("name")
	}
	body := map[string]any{
		"name":        name,
		"description": description,
	}
	_, err := p.client.DoPostRequest(ctx, api.Routes.ManagementPermissionCreate(), body, nil, "")
	return err
}

func (p *permission) Update(ctx context.Context, name, newName, description string) error {
	if name == "" {
		return utils.NewInvalidArgumentError("name")
	}
	if newName == "" {
		return utils.NewInvalidArgumentError("newName")
	}
	body := map[string]any{
		"name":        name,
		"newName":     newName,
		"description": description,
	}
	_, err := p.client.DoPostRequest(ctx, api.Routes.ManagementPermissionUpdate(), body, nil, "")
	return err
}

func (p *permission) Delete(ctx context.Context, name string) error {
	if name == "" {
		return utils.NewInvalidArgumentError("name")
	}
	body := map[string]any{"name": name}
	_, err := p.client.DoPostRequest(ctx, api.Routes.ManagementPermissionDelete(), body, nil, "")
	return err
}

func (p *permission) LoadAll(ctx context.Context) ([]*descope.Permission, error) {
	res, err := p.client.DoGetRequest(ctx, api.Routes.ManagementPermissionLoadAll(), nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalPermissionsLoadAllResponse(res)
}

func unmarshalPermissionsLoadAllResponse(res *api.HTTPResponse) ([]*descope.Permission, error) {
	pres := struct {
		Permissions []*descope.Permission
	}{}
	err := utils.Unmarshal([]byte(res.BodyStr), &pres)
	if err != nil {
		return nil, err
	}
	return pres.Permissions, err
}
