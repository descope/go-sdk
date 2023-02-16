package mgmt

import (
	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
)

type user struct {
	managementBase
}

func (u *user) Create(loginID, email, phone, displayName string, roles []string, tenants []*descope.AssociatedTenant) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	req := makeCreateUpdateUserRequest(loginID, email, phone, displayName, roles, tenants)
	res, err := u.client.DoPostRequest(api.Routes.ManagementUserCreate(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) Update(loginID, email, phone, displayName string, roles []string, tenants []*descope.AssociatedTenant) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
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
		return utils.NewInvalidArgumentError("loginID")
	}
	req := map[string]any{"loginId": loginID}
	_, err := u.client.DoPostRequest(api.Routes.ManagementUserDelete(), req, nil, u.conf.ManagementKey)
	return err
}

func (u *user) Load(loginID string) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	return u.load(loginID, "")
}

func (u *user) LoadByUserID(userID string) (*descope.UserResponse, error) {
	if userID == "" {
		return nil, utils.NewInvalidArgumentError("userID")
	}
	return u.load("", userID)
}

func (u *user) load(loginID, userID string) (*descope.UserResponse, error) {
	req := &api.HTTPRequest{
		QueryParams: map[string]string{"loginId": loginID, "userId": userID},
	}
	res, err := u.client.DoGetRequest(api.Routes.ManagementUserLoad(), req, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) SearchAll(tenantIDs, roles []string, limit, page int32) ([]*descope.UserResponse, error) {
	if limit < 0 {
		return nil, utils.NewInvalidArgumentError("limit")
	}

	if page < 0 {
		return nil, utils.NewInvalidArgumentError("page")
	}

	req := makeSearchAllRequest(tenantIDs, roles, limit, page)
	res, err := u.client.DoPostRequest(api.Routes.ManagementUserSearchAll(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserSearchAllResponse(res)
}

func (u *user) Activate(loginID string) (*descope.UserResponse, error) {
	return u.updateStatus(loginID, "enabled")
}

func (u *user) Deactivate(loginID string) (*descope.UserResponse, error) {
	return u.updateStatus(loginID, "disabled")
}

func (u *user) updateStatus(loginID string, status string) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	req := map[string]any{"loginId": loginID, "status": status}
	res, err := u.client.DoPostRequest(api.Routes.ManagementUserUpdateStatus(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) UpdateEmail(loginID, email string, isVerified bool) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	req := map[string]any{"loginId": loginID, "email": email, "verified": isVerified}
	res, err := u.client.DoPostRequest(api.Routes.ManagementUserUpdateEmail(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) UpdatePhone(loginID, phone string, isVerified bool) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	req := map[string]any{"loginId": loginID, "phone": phone, "verified": isVerified}
	res, err := u.client.DoPostRequest(api.Routes.ManagementUserUpdatePhone(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) UpdateDisplayName(loginID, displayName string) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	req := map[string]any{"loginId": loginID, "displayName": displayName}
	res, err := u.client.DoPostRequest(api.Routes.ManagementUserUpdateDisplayName(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) AddRoles(loginID string, roles []string) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	req := makeUpdateUserRolesRequest(loginID, "", roles)
	res, err := u.client.DoPostRequest(api.Routes.ManagementUserAddRole(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) RemoveRoles(loginID string, roles []string) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	req := makeUpdateUserRolesRequest(loginID, "", roles)
	res, err := u.client.DoPostRequest(api.Routes.ManagementUserRemoveRole(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) AddTenant(loginID string, tenantID string) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	req := makeUpdateUserTenantRequest(loginID, tenantID)
	res, err := u.client.DoPostRequest(api.Routes.ManagementUserAddTenant(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) RemoveTenant(loginID string, tenantID string) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	req := makeUpdateUserTenantRequest(loginID, tenantID)
	res, err := u.client.DoPostRequest(api.Routes.ManagementUserRemoveTenant(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) AddTenantRoles(loginID string, tenantID string, roles []string) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	req := makeUpdateUserRolesRequest(loginID, tenantID, roles)
	res, err := u.client.DoPostRequest(api.Routes.ManagementUserAddRole(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) RemoveTenantRoles(loginID string, tenantID string, roles []string) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	req := makeUpdateUserRolesRequest(loginID, tenantID, roles)
	res, err := u.client.DoPostRequest(api.Routes.ManagementUserRemoveRole(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func makeCreateUpdateUserRequest(loginID, email, phone, displayName string, roles []string, tenants []*descope.AssociatedTenant) map[string]any {
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

func makeSearchAllRequest(tenantIDs, roles []string, limit, page int32) map[string]any {
	return map[string]any{
		"tenantIds": tenantIDs,
		"roleNames": roles,
		"limit":     limit,
		"page":      page,
	}
}

func unmarshalUserResponse(res *api.HTTPResponse) (*descope.UserResponse, error) {
	ures := struct {
		User *descope.UserResponse
	}{}
	err := utils.Unmarshal([]byte(res.BodyStr), &ures)
	if err != nil {
		return nil, err
	}
	return ures.User, err
}

func unmarshalUserSearchAllResponse(res *api.HTTPResponse) ([]*descope.UserResponse, error) {
	ures := struct {
		Users []*descope.UserResponse
	}{}
	err := utils.Unmarshal([]byte(res.BodyStr), &ures)
	if err != nil {
		return nil, err
	}
	return ures.Users, err
}
