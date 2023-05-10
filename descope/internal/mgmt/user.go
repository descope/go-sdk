package mgmt

import (
	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
)

type user struct {
	managementBase
}

func (u *user) Create(loginID string, user *descope.UserRequest) (*descope.UserResponse, error) {
	if user == nil {
		user = &descope.UserRequest{}
	}
	return u.create(loginID, user.Email, user.Phone, user.Name, user.Picture, user.Roles, user.Tenants, false, false, user.CustomAttributes)
}

func (u *user) CreateTestUser(loginID string, user *descope.UserRequest) (*descope.UserResponse, error) {
	if user == nil {
		user = &descope.UserRequest{}
	}
	return u.create(loginID, user.Email, user.Phone, user.Name, user.Picture, user.Roles, user.Tenants, false, true, user.CustomAttributes)
}

func (u *user) Invite(loginID string, user *descope.UserRequest) (*descope.UserResponse, error) {
	if user == nil {
		user = &descope.UserRequest{}
	}
	return u.create(loginID, user.Email, user.Phone, user.Name, user.Picture, user.Roles, user.Tenants, true, false, user.CustomAttributes)
}

func (u *user) create(loginID, email, phone, displayName, picture string, roles []string, tenants []*descope.AssociatedTenant, invite, test bool, customAttributes map[string]any) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	req := makeCreateUserRequest(loginID, email, phone, displayName, picture, roles, tenants, invite, test, customAttributes)
	res, err := u.client.DoPostRequest(api.Routes.ManagementUserCreate(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) Update(loginID string, user *descope.UserRequest) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	if user == nil {
		user = &descope.UserRequest{}
	}
	req := makeUpdateUserRequest(loginID, user.Email, user.Phone, user.Name, user.Picture, user.Roles, user.Tenants, user.CustomAttributes)
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

func (u *user) DeleteAllTestUsers() error {
	_, err := u.client.DoDeleteRequest(api.Routes.ManagementUserDeleteAllTestUsers(), nil, u.conf.ManagementKey)
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

func (u *user) SearchAll(options *descope.UserSearchOptions) ([]*descope.UserResponse, error) {
	// Init empty options if non given
	if options == nil {
		options = &descope.UserSearchOptions{}
	}

	// Make sure limit is non-negative
	if options.Limit < 0 {
		return nil, utils.NewInvalidArgumentError("limit")
	}

	// Make sure page is non-negative
	if options.Page < 0 {
		return nil, utils.NewInvalidArgumentError("page")
	}

	req := makeSearchAllRequest(options)
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

func (u *user) UpdatePicture(loginID, picture string) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	req := map[string]any{"loginId": loginID, "picture": picture}
	res, err := u.client.DoPostRequest(api.Routes.ManagementUserUpdatePicture(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) UpdateCustomAttribute(loginID, key string, value any) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	if key == "" {
		return nil, utils.NewInvalidArgumentError("key")
	}
	req := map[string]any{"loginId": loginID, "attributeKey": key, "attributeValue": value}
	res, err := u.client.DoPostRequest(api.Routes.ManagementUserUpdateCustomAttribute(), req, nil, u.conf.ManagementKey)
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

func (u *user) SetPassword(loginID string, newPassword string) error {
	if loginID == "" {
		return utils.NewInvalidArgumentError("loginID")
	}
	if newPassword == "" {
		return utils.NewInvalidArgumentError("newPassword")
	}

	req := makeSetPasswordRequest(loginID, newPassword)
	_, err := u.client.DoPostRequest(api.Routes.ManagementUserGenerateEnchantedLinkForTest(), req, nil, u.conf.ManagementKey)
	return err
}

func (u *user) ExpirePassword(loginID string) error {
	if loginID == "" {
		return utils.NewInvalidArgumentError("loginID")
	}

	req := makeExpirePasswordRequest(loginID)
	_, err := u.client.DoPostRequest(api.Routes.ManagementUserGenerateEnchantedLinkForTest(), req, nil, u.conf.ManagementKey)
	return err
}

func (u *user) GenerateOTPForTestUser(method descope.DeliveryMethod, loginID string) (code string, err error) {
	if loginID == "" {
		return "", utils.NewInvalidArgumentError("loginID")
	}
	req := makeGenerateOTPForTestUserRequestBody(method, loginID)
	res, err := u.client.DoPostRequest(api.Routes.ManagementUserGenerateOTPForTest(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return "", err
	}
	return unmarshalGenerateOTPForTestResponse(res)
}

func (u *user) GenerateMagicLinkForTestUser(method descope.DeliveryMethod, loginID, URI string) (link string, err error) {
	if loginID == "" {
		return "", utils.NewInvalidArgumentError("loginID")
	}
	req := makeGenerateMagicLinkForTestUserRequestBody(method, loginID, URI)
	res, err := u.client.DoPostRequest(api.Routes.ManagementUserGenerateMagicLinkForTest(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return "", err
	}
	link, _, err = unmarshalGenerateLinkForTestResponse(res)
	return link, err
}

func (u *user) GenerateEnchantedLinkForTestUser(loginID, URI string) (link, pendingRef string, err error) {
	if loginID == "" {
		return "", "", utils.NewInvalidArgumentError("loginID")
	}
	req := makeGenerateEnchantedLinkForTestUserRequestBody(loginID, URI)
	res, err := u.client.DoPostRequest(api.Routes.ManagementUserGenerateEnchantedLinkForTest(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return "", "", err
	}
	return unmarshalGenerateLinkForTestResponse(res)
}

func makeCreateUserRequest(loginID, email, phone, displayName, picture string, roles []string, tenants []*descope.AssociatedTenant, invite, test bool, customAttributes map[string]any) map[string]any {
	req := makeUpdateUserRequest(loginID, email, phone, displayName, picture, roles, tenants, customAttributes)
	req["invite"] = invite
	if test {
		req["test"] = true
	}
	return req
}

func makeUpdateUserRequest(loginID, email, phone, displayName, picture string, roles []string, tenants []*descope.AssociatedTenant, customAttributes map[string]any) map[string]any {
	return map[string]any{
		"loginId":          loginID,
		"email":            email,
		"phone":            phone,
		"displayName":      displayName,
		"roleNames":        roles,
		"userTenants":      makeAssociatedTenantList(tenants),
		"customAttributes": customAttributes,
		"picture":          picture,
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

func makeSetPasswordRequest(loginID string, newPassword string) map[string]any {
	return map[string]any{
		"loginId":     loginID,
		"newPassword": newPassword,
	}
}

func makeExpirePasswordRequest(loginID string) map[string]any {
	return map[string]any{
		"loginId": loginID,
	}
}

func makeSearchAllRequest(options *descope.UserSearchOptions) map[string]any {
	return map[string]any{
		"tenantIds":        options.TenantIDs,
		"roleNames":        options.Roles,
		"limit":            options.Limit,
		"page":             options.Page,
		"testUsersOnly":    options.TestUsersOnly,
		"withTestUser":     options.WithTestUsers,
		"customAttributes": options.CustomAttributes,
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

type generateForTestUserRequestBody struct {
	LoginID string `json:"loginId,omitempty"`
}

type generateOTPForTestUserRequestBody struct {
	*generateForTestUserRequestBody `json:",inline"`
	DeliveryMethod                  string `json:"deliveryMethod,omitempty"`
}

type generateMagicLinkForTestUserRequestBody struct {
	*generateForTestUserRequestBody `json:",inline"`
	DeliveryMethod                  string `json:"deliveryMethod,omitempty"`
	URI                             string `json:"URI,omitempty"`
}

type generateEnchantedLinkForTestUserRequestBody struct {
	*generateForTestUserRequestBody `json:",inline"`
	URI                             string `json:"URI,omitempty"`
}

func makeGenerateOTPForTestUserRequestBody(method descope.DeliveryMethod, loginID string) *generateOTPForTestUserRequestBody {
	return &generateOTPForTestUserRequestBody{
		generateForTestUserRequestBody: &generateForTestUserRequestBody{
			LoginID: loginID,
		},
		DeliveryMethod: string(method),
	}
}

func makeGenerateMagicLinkForTestUserRequestBody(method descope.DeliveryMethod, loginID, URI string) *generateMagicLinkForTestUserRequestBody {
	return &generateMagicLinkForTestUserRequestBody{
		generateForTestUserRequestBody: &generateForTestUserRequestBody{
			LoginID: loginID,
		},
		DeliveryMethod: string(method),
		URI:            URI,
	}
}

func makeGenerateEnchantedLinkForTestUserRequestBody(loginID, URI string) *generateEnchantedLinkForTestUserRequestBody {
	return &generateEnchantedLinkForTestUserRequestBody{
		generateForTestUserRequestBody: &generateForTestUserRequestBody{
			LoginID: loginID,
		},
		URI: URI,
	}
}

type GenerateOTPForTestResponse struct {
	LoginID string `json:"loginId,omitempty"`
	Code    string `json:"code,omitempty"`
}

type GenerateLinkForTestResponse struct {
	LoginID    string `json:"loginId,omitempty"`
	Link       string `json:"link,omitempty"`
	PendingRef string `json:"pendingRef,omitempty"`
}

func unmarshalGenerateOTPForTestResponse(res *api.HTTPResponse) (string, error) {
	resBody := &GenerateOTPForTestResponse{}
	err := utils.Unmarshal([]byte(res.BodyStr), &resBody)
	if err != nil {
		return "", err
	}
	return resBody.Code, err
}

func unmarshalGenerateLinkForTestResponse(res *api.HTTPResponse) (string, string, error) {
	resBody := &GenerateLinkForTestResponse{}
	err := utils.Unmarshal([]byte(res.BodyStr), &resBody)
	if err != nil {
		return "", "", err
	}
	return resBody.Link, resBody.PendingRef, err
}
