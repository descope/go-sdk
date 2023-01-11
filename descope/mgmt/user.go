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

func (u *user) Create(loginID, email, phone, displayName string, roles []string, tenants []*AssociatedTenant) (*auth.UserResponse, error) {
	if loginID == "" {
		return nil, errors.NewInvalidArgumentError("loginID")
	}
	req := makeCreateUpdateUserRequest(loginID, email, phone, displayName, roles, tenants)
	res, err := u.client.DoPostRequest(api.Routes.ManagementUserCreate(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) Update(loginID, email, phone, displayName string, roles []string, tenants []*AssociatedTenant) (*auth.UserResponse, error) {
	if loginID == "" {
		return nil, errors.NewInvalidArgumentError("loginID")
	}
	req := makeCreateUpdateUserRequest(loginID, email, phone, displayName, roles, tenants)
	res, err := u.client.DoPostRequest(api.Routes.ManagementUserUpdate(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
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

func (u *user) Activate(loginID string) (*auth.UserResponse, error) {
	return u.updateStatus(loginID, "enabled")
}

func (u *user) Deactivate(loginID string) (*auth.UserResponse, error) {
	return u.updateStatus(loginID, "disabled")
}

func (u *user) updateStatus(loginID string, status string) (*auth.UserResponse, error) {
	if loginID == "" {
		return nil, errors.NewInvalidArgumentError("loginID")
	}
	req := map[string]any{"loginId": loginID, "status": status}
	res, err := u.client.DoPostRequest(api.Routes.ManagementUserUpdateStatus(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) UpdateEmail(loginID, email string, isVerified bool) (*auth.UserResponse, error) {
	if loginID == "" {
		return nil, errors.NewInvalidArgumentError("loginID")
	}
	req := map[string]any{"loginId": loginID, "email": email, "verified": isVerified}
	res, err := u.client.DoPostRequest(api.Routes.ManagementUserUpdateEmail(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) UpdatePhone(loginID, phone string, isVerified bool) (*auth.UserResponse, error) {
	if loginID == "" {
		return nil, errors.NewInvalidArgumentError("loginID")
	}
	req := map[string]any{"loginId": loginID, "phone": phone, "verified": isVerified}
	res, err := u.client.DoPostRequest(api.Routes.ManagementUserUpdatePhone(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) UpdateDisplayName(loginID, displayName string) (*auth.UserResponse, error) {
	if loginID == "" {
		return nil, errors.NewInvalidArgumentError("loginID")
	}
	req := map[string]any{"loginId": loginID, "displayName": displayName}
	res, err := u.client.DoPostRequest(api.Routes.ManagementUserUpdateDisplayName(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) AddRoles(loginID string, roles []string) (*auth.UserResponse, error) {
	if loginID == "" {
		return nil, errors.NewInvalidArgumentError("loginID")
	}
	req := makeUpdateUserRolesRequest(loginID, "", roles)
	res, err := u.client.DoPostRequest(api.Routes.ManagementUserAddRole(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) RemoveRoles(loginID string, roles []string) (*auth.UserResponse, error) {
	if loginID == "" {
		return nil, errors.NewInvalidArgumentError("loginID")
	}
	req := makeUpdateUserRolesRequest(loginID, "", roles)
	res, err := u.client.DoPostRequest(api.Routes.ManagementUserRemoveRole(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) AddTenant(loginID string, tenantID string) (*auth.UserResponse, error) {
	if loginID == "" {
		return nil, errors.NewInvalidArgumentError("loginID")
	}
	req := makeUpdateUserTenantRequest(loginID, tenantID)
	res, err := u.client.DoPostRequest(api.Routes.ManagementUserAddTenant(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) RemoveTenant(loginID string, tenantID string) (*auth.UserResponse, error) {
	if loginID == "" {
		return nil, errors.NewInvalidArgumentError("loginID")
	}
	req := makeUpdateUserTenantRequest(loginID, tenantID)
	res, err := u.client.DoPostRequest(api.Routes.ManagementUserRemoveTenant(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) AddTenantRoles(loginID string, tenantID string, roles []string) (*auth.UserResponse, error) {
	if loginID == "" {
		return nil, errors.NewInvalidArgumentError("loginID")
	}
	req := makeUpdateUserRolesRequest(loginID, tenantID, roles)
	res, err := u.client.DoPostRequest(api.Routes.ManagementUserAddRole(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) RemoveTenantRoles(loginID string, tenantID string, roles []string) (*auth.UserResponse, error) {
	if loginID == "" {
		return nil, errors.NewInvalidArgumentError("loginID")
	}
	req := makeUpdateUserRolesRequest(loginID, tenantID, roles)
	res, err := u.client.DoPostRequest(api.Routes.ManagementUserRemoveRole(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func makeCreateUpdateUserRequest(loginID, email, phone, displayName string, roles []string, tenants []*AssociatedTenant) map[string]any {
	return map[string]any{
		"loginId":     loginID,
		"email":       email,
		"phone":       phone,
		"displayName": displayName,
		"roleNames":   roles,
		"userTenants": makeAssociatedTenantList(tenants),
	}
}

func makeUpdateUserTenantRequest(loginID, tenantID string) map[string]any {
	return map[string]any{
		"loginId":  loginID,
		"tenantId": tenantID,
	}
}

func makeUpdateUserRolesRequest(loginID, tenantID string, roles []string) map[string]any {
	return map[string]any{
		"loginId":   loginID,
		"tenantId":  tenantID,
		"roleNames": roles,
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
