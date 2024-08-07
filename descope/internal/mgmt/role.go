package mgmt

import (
	"context"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/sdk"
)

type role struct {
	managementBase
}

var _ sdk.Role = &role{}

func (r *role) Create(ctx context.Context, name, description string, permissionNames []string, tenantID string) error {
	if name == "" {
		return utils.NewInvalidArgumentError("name")
	}
	body := map[string]any{
		"name":            name,
		"description":     description,
		"permissionNames": permissionNames,
		"tenantId":        tenantID,
	}
	_, err := r.client.DoPostRequest(ctx, api.Routes.ManagementRoleCreate(), body, nil, r.conf.ManagementKey)
	return err
}

func (r *role) Update(ctx context.Context, name, tenantID, newName, description string, permissionNames []string) error {
	if name == "" {
		return utils.NewInvalidArgumentError("name")
	}
	if newName == "" {
		return utils.NewInvalidArgumentError("newName")
	}
	body := map[string]any{
		"name":            name,
		"newName":         newName,
		"description":     description,
		"permissionNames": permissionNames,
		"tenantId":        tenantID,
	}
	_, err := r.client.DoPostRequest(ctx, api.Routes.ManagementRoleUpdate(), body, nil, r.conf.ManagementKey)
	return err
}

func (r *role) Delete(ctx context.Context, name, tenantID string) error {
	if name == "" {
		return utils.NewInvalidArgumentError("name")
	}
	body := map[string]any{
		"name":     name,
		"tenantId": tenantID,
	}
	_, err := r.client.DoPostRequest(ctx, api.Routes.ManagementRoleDelete(), body, nil, r.conf.ManagementKey)
	return err
}

func (r *role) LoadAll(ctx context.Context) ([]*descope.Role, error) {
	res, err := r.client.DoGetRequest(ctx, api.Routes.ManagementRoleLoadAll(), nil, r.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalRolesLoadAllResponse(res)
}

func (r *role) Search(ctx context.Context, options *descope.RoleSearchOptions) ([]*descope.Role, error) {
	res, err := r.client.DoPostRequest(ctx, api.Routes.ManagementRoleSearch(), options, nil, r.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalRolesLoadAllResponse(res)
}

func unmarshalRolesLoadAllResponse(res *api.HTTPResponse) ([]*descope.Role, error) {
	pres := struct {
		Roles []*descope.Role
	}{}
	err := utils.Unmarshal([]byte(res.BodyStr), &pres)
	if err != nil {
		return nil, err
	}
	return pres.Roles, nil
}
