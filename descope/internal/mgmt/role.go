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

func (r *role) Create(ctx context.Context, name, description string, permissionNames []string, tenantID string, defaultRole bool, private bool) error {
	if name == "" {
		return utils.NewInvalidArgumentError("name")
	}
	body := map[string]any{
		"name":            name,
		"description":     description,
		"permissionNames": permissionNames,
		"tenantId":        tenantID,
		"default":         defaultRole,
		"private":         private,
	}
	_, err := r.client.DoPostRequest(ctx, api.Routes.ManagementRoleCreate(), body, nil, "")
	return err
}

func (r *role) CreateBatch(ctx context.Context, roles []*descope.Role) ([]*descope.Role, error) {
	if len(roles) == 0 {
		return nil, utils.NewInvalidArgumentError("roles")
	}
	body := map[string]any{"roles": roles}
	res, err := r.client.DoPostRequest(ctx, api.Routes.ManagementRoleCreateBatch(), body, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalRolesLoadAllResponse(res)
}

func (r *role) Update(ctx context.Context, name, tenantID, newName, description string, permissionNames []string, defaultRole bool, private bool) error {
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
		"default":         defaultRole,
		"private":         private,
	}
	_, err := r.client.DoPostRequest(ctx, api.Routes.ManagementRoleUpdate(), body, nil, "")
	return err
}

func (r *role) UpdateWithID(ctx context.Context, id, tenantID, newName, description string, permissionNames []string, defaultRole bool, private bool) error {
	if id == "" {
		return utils.NewInvalidArgumentError("id")
	}
	if newName == "" {
		return utils.NewInvalidArgumentError("newName")
	}
	body := map[string]any{
		"id":              id,
		"newName":         newName,
		"description":     description,
		"permissionNames": permissionNames,
		"tenantId":        tenantID,
		"default":         defaultRole,
		"private":         private,
	}
	_, err := r.client.DoPostRequest(ctx, api.Routes.ManagementRoleUpdate(), body, nil, "")
	return err
}

func (r *role) UpdateBatch(ctx context.Context, roles []*descope.RoleUpdateRequest) ([]*descope.Role, error) {
	if len(roles) == 0 {
		return nil, utils.NewInvalidArgumentError("roles")
	}
	body := map[string]any{"roles": roles}
	res, err := r.client.DoPostRequest(ctx, api.Routes.ManagementRoleUpdateBatch(), body, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalRolesLoadAllResponse(res)
}

func (r *role) Delete(ctx context.Context, name, tenantID string) error {
	if name == "" {
		return utils.NewInvalidArgumentError("name")
	}
	body := map[string]any{
		"name":     name,
		"tenantId": tenantID,
	}
	_, err := r.client.DoPostRequest(ctx, api.Routes.ManagementRoleDelete(), body, nil, "")
	return err
}

func (r *role) DeleteWithID(ctx context.Context, id, tenantID string) error {
	if id == "" {
		return utils.NewInvalidArgumentError("id")
	}
	body := map[string]any{
		"id":       id,
		"tenantId": tenantID,
	}
	_, err := r.client.DoPostRequest(ctx, api.Routes.ManagementRoleDelete(), body, nil, "")
	return err
}

func (r *role) DeleteBatch(ctx context.Context, roleNames []string, tenantID string, roleIDs []string) error {
	if len(roleNames) == 0 && len(roleIDs) == 0 {
		return utils.NewInvalidArgumentError("roleNames")
	}
	body := map[string]any{
		"roleNames": roleNames,
		"tenantId":  tenantID,
		"roleIds":   roleIDs,
	}
	_, err := r.client.DoPostRequest(ctx, api.Routes.ManagementRoleDeleteBatch(), body, nil, "")
	return err
}

func (r *role) LoadAll(ctx context.Context) ([]*descope.Role, error) {
	res, err := r.client.DoGetRequest(ctx, api.Routes.ManagementRoleLoadAll(), nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalRolesLoadAllResponse(res)
}

func (r *role) Search(ctx context.Context, options *descope.RoleSearchOptions) ([]*descope.Role, error) {
	res, err := r.client.DoPostRequest(ctx, api.Routes.ManagementRoleSearch(), options, nil, "")
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
