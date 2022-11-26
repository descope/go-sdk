package mgmt

import (
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/errors"
)

type user struct {
	managementBase
}

func (u *user) Create(identifier, email, phone, displayName string, roles []string, tenants []UserTenants) error {
	if identifier == "" {
		return errors.NewInvalidArgumentError("identifier")
	}
	req := makeCreateUpdateUserRequest(identifier, email, phone, displayName, roles, tenants)
	_, err := u.client.DoPostRequest(api.Routes.ManagementUserCreate(), req, nil, u.conf.ManagementKey)
	return err
}

func (u *user) Update(identifier, email, phone, displayName string, roles []string, tenants []UserTenants) error {
	if identifier == "" {
		return errors.NewInvalidArgumentError("identifier")
	}
	req := makeCreateUpdateUserRequest(identifier, email, phone, displayName, roles, tenants)
	_, err := u.client.DoPostRequest(api.Routes.ManagementUserUpdate(), req, nil, u.conf.ManagementKey)
	return err
}

func (u *user) Delete(identifier string) error {
	if identifier == "" {
		return errors.NewInvalidArgumentError("identifier")
	}
	req := map[string]any{"identifier": identifier}
	_, err := u.client.DoPostRequest(api.Routes.ManagementUserDelete(), req, nil, u.conf.ManagementKey)
	return err
}

func makeCreateUpdateUserRequest(identifier, email, phone, displayName string, roles []string, tenants []UserTenants) map[string]any {
	return map[string]any{
		"identifier":  identifier,
		"email":       email,
		"phoneNumber": phone,
		"displayName": displayName,
		"roleNames":   roles,
		"userTenants": makeUserTenantsList(tenants),
	}
}

func makeUserTenantsList(tenants []UserTenants) []map[string]any {
	res := []map[string]any{}
	for _, tenant := range tenants {
		res = append(res, map[string]any{
			"tenantId":  tenant.TenantID,
			"roleNames": tenant.Roles,
		})
	}
	return res
}
