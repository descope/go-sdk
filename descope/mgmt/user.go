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

func (u *user) Create(loginID, email, phone, displayName string, roles []string, tenants []*AssociatedTenant) error {
	if loginID == "" {
		return errors.NewInvalidArgumentError("loginID")
	}
	req := makeCreateUpdateUserRequest(loginID, email, phone, displayName, roles, tenants)
	_, err := u.client.DoPostRequest(api.Routes.ManagementUserCreate(), req, nil, u.conf.ManagementKey)
	return err
}

func (u *user) Update(loginID, email, phone, displayName string, roles []string, tenants []*AssociatedTenant) error {
	if loginID == "" {
		return errors.NewInvalidArgumentError("loginID")
	}
	req := makeCreateUpdateUserRequest(loginID, email, phone, displayName, roles, tenants)
	_, err := u.client.DoPostRequest(api.Routes.ManagementUserUpdate(), req, nil, u.conf.ManagementKey)
	return err
}

func (u *user) Delete(loginID string) error {
	if loginID == "" {
		return errors.NewInvalidArgumentError("loginID")
	}
	req := map[string]any{"loginId": loginID}
	_, err := u.client.DoPostRequest(api.Routes.ManagementUserDelete(), req, nil, u.conf.ManagementKey)
	return err
}

func (u *user) Load(loginID string) (*auth.UserResponse, error) {
	if loginID == "" {
		return nil, errors.NewInvalidArgumentError("loginID")
	}
	return u.load(loginID, "")
}

func (u *user) LoadByUserID(userID string) (*auth.UserResponse, error) {
	if userID == "" {
		return nil, errors.NewInvalidArgumentError("userID")
	}
	return u.load("", userID)
}

func (u *user) load(loginID, userID string) (*auth.UserResponse, error) {
	req := &api.HTTPRequest{
		QueryParams: map[string]string{"loginId": loginID, "userId": userID},
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

func makeCreateUpdateUserRequest(loginID, email, phone, displayName string, roles []string, tenants []*AssociatedTenant) map[string]any {
	return map[string]any{
		"loginId":     loginID,
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
