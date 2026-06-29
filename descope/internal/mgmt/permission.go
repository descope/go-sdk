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

func (p *permission) CreateBatch(ctx context.Context, permissions []*descope.Permission) error {
	if len(permissions) == 0 {
		return utils.NewInvalidArgumentError("permissions")
	}
	body := map[string]any{"permissions": permissions}
	_, err := p.client.DoPostRequest(ctx, api.Routes.ManagementPermissionCreateBatch(), body, nil, "")
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

func (p *permission) UpdateWithID(ctx context.Context, id, newName, description string) error {
	if id == "" {
		return utils.NewInvalidArgumentError("id")
	}
	if newName == "" {
		return utils.NewInvalidArgumentError("newName")
	}
	body := map[string]any{
		"id":          id,
		"newName":     newName,
		"description": description,
	}
	_, err := p.client.DoPostRequest(ctx, api.Routes.ManagementPermissionUpdate(), body, nil, "")
	return err
}

func (p *permission) UpdateBatch(ctx context.Context, permissions []*descope.PermissionUpdateRequest) error {
	if len(permissions) == 0 {
		return utils.NewInvalidArgumentError("permissions")
	}
	body := map[string]any{"permissions": permissions}
	_, err := p.client.DoPostRequest(ctx, api.Routes.ManagementPermissionUpdateBatch(), body, nil, "")
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

func (p *permission) DeleteWithID(ctx context.Context, id string) error {
	if id == "" {
		return utils.NewInvalidArgumentError("id")
	}
	body := map[string]any{"id": id}
	_, err := p.client.DoPostRequest(ctx, api.Routes.ManagementPermissionDelete(), body, nil, "")
	return err
}

func (p *permission) DeleteBatch(ctx context.Context, names []string, ids []string) error {
	if len(names) == 0 && len(ids) == 0 {
		return utils.NewInvalidArgumentError("names")
	}
	body := map[string]any{"names": names, "ids": ids}
	_, err := p.client.DoPostRequest(ctx, api.Routes.ManagementPermissionDeleteBatch(), body, nil, "")
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
