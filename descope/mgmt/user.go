package mgmt

import (
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/auth"
	"github.com/descope/go-sdk/descope/errors"
	"github.com/descope/go-sdk/descope/utils"
)

type user struct {
	managementBase
}

func (u *user) Create(identifier, email, phone, displayName string, roles []string, tenants []*AssociatedTenant) error {
	if identifier == "" {
		return errors.NewInvalidArgumentError("identifier")
	}
	req := makeCreateUpdateUserRequest(identifier, email, phone, displayName, roles, tenants)
	_, err := u.client.DoPostRequest(api.Routes.ManagementUserCreate(), req, nil, u.conf.ManagementKey)
	return err
}

func (u *user) Update(identifier, email, phone, displayName string, roles []string, tenants []*AssociatedTenant) error {
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

func (u *user) Load(identifier string) (*auth.UserResponse, error) {
	if identifier == "" {
		return nil, errors.NewInvalidArgumentError("identifier")
	}
	return u.load(identifier, "")
}

func (u *user) LoadByJWTSubject(jwtSubject string) (*auth.UserResponse, error) {
	if jwtSubject == "" {
		return nil, errors.NewInvalidArgumentError("jwtSubject")
	}
	return u.load("", jwtSubject)
}

func (u *user) load(identifier, jwtSubject string) (*auth.UserResponse, error) {
	req := &api.HTTPRequest{
		QueryParams: map[string]string{"identifier": identifier, "jwtSubject": jwtSubject},
	}
	res, err := u.client.DoGetRequest(api.Routes.ManagementUserLoad(), req, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) SearchAll(tenantIDs, roles []string, limit int32) ([]*auth.UserResponse, error) {
	req := makeSearchAllRequest(tenantIDs, roles, limit)
	res, err := u.client.DoPostRequest(api.Routes.ManagementUserSearchAll(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserSearchAllResponse(res)
}

func makeCreateUpdateUserRequest(identifier, email, phone, displayName string, roles []string, tenants []*AssociatedTenant) map[string]any {
	return map[string]any{
		"identifier":  identifier,
		"email":       email,
		"phoneNumber": phone,
		"displayName": displayName,
		"roleNames":   roles,
		"userTenants": makeAssociatedTenantList(tenants),
	}
}

func makeSearchAllRequest(tenantIDs, roles []string, limit int32) map[string]any {
	return map[string]any{
		"tenantIds": tenantIDs,
		"roleNames": roles,
		"limit":     limit,
	}
}

func unmarshalUserResponse(res *api.HTTPResponse) (*auth.UserResponse, error) {
	ures := struct {
		User *auth.UserResponse
	}{}
	err := utils.Unmarshal([]byte(res.BodyStr), &ures)
	if err != nil {
		return nil, err
	}
	return ures.User, err
}

func unmarshalUserSearchAllResponse(res *api.HTTPResponse) ([]*auth.UserResponse, error) {
	ures := struct {
		Users []*auth.UserResponse
	}{}
	err := utils.Unmarshal([]byte(res.BodyStr), &ures)
	if err != nil {
		return nil, err
	}
	return ures.Users, err
}
