package mgmt

import (
	"context"
	"strconv"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/sdk"
)

type user struct {
	managementBase
}

var _ sdk.User = &user{}

type createUserRequest struct {
	loginID            string
	email              string
	phone              string
	name               string
	givenName          string
	middleName         string
	familyName         string
	picture            string
	roles              []string
	tenants            []*descope.AssociatedTenant
	invite             bool
	templateID         string
	test               bool
	customAttributes   map[string]any
	verifiedEmail      *bool
	verifiedPhone      *bool
	additionalLoginIDs []string
	options            *descope.InviteOptions
	ssoAppIDs          []string
}

func (u *user) Create(ctx context.Context, loginID string, user *descope.UserRequest) (*descope.UserResponse, error) {
	if user == nil {
		user = &descope.UserRequest{}
	}
	return u.create(ctx, loginID, user.Email, user.Phone, user.Name, user.GivenName, user.MiddleName, user.FamilyName, user.Picture, user.Roles, user.Tenants, false, false, user.CustomAttributes, user.VerifiedEmail, user.VerifiedPhone, user.AdditionalLoginIDs, nil, user.SSOAppIDs)
}

func (u *user) CreateTestUser(ctx context.Context, loginID string, user *descope.UserRequest) (*descope.UserResponse, error) {
	if user == nil {
		user = &descope.UserRequest{}
	}
	return u.create(ctx, loginID, user.Email, user.Phone, user.Name, user.GivenName, user.MiddleName, user.FamilyName, user.Picture, user.Roles, user.Tenants, false, true, user.CustomAttributes, user.VerifiedEmail, user.VerifiedPhone, user.AdditionalLoginIDs, nil, user.SSOAppIDs)
}

func (u *user) CreateBatch(ctx context.Context, users []*descope.BatchUser) (*descope.UsersBatchResponse, error) {
	if users == nil {
		users = []*descope.BatchUser{} // notest
	}
	return u.createBatch(ctx, users, nil)
}

func (u *user) Invite(ctx context.Context, loginID string, user *descope.UserRequest, options *descope.InviteOptions) (*descope.UserResponse, error) {
	if user == nil {
		user = &descope.UserRequest{}
	}
	return u.create(ctx, loginID, user.Email, user.Phone, user.Name, user.GivenName, user.MiddleName, user.FamilyName, user.Picture, user.Roles, user.Tenants, true, false, user.CustomAttributes, user.VerifiedEmail, user.VerifiedPhone, user.AdditionalLoginIDs, options, user.SSOAppIDs)
}

func (u *user) InviteBatch(ctx context.Context, users []*descope.BatchUser, options *descope.InviteOptions) (*descope.UsersBatchResponse, error) {
	if users == nil {
		users = []*descope.BatchUser{} // notest
	}
	return u.createBatch(ctx, users, options)
}

func (u *user) create(ctx context.Context, loginID, email, phone, displayName, givenName, middleName, familyName, picture string, roles []string, tenants []*descope.AssociatedTenant, invite, test bool, customAttributes map[string]any, verifiedEmail *bool, verifiedPhone *bool, additionalLoginIDs []string, options *descope.InviteOptions, ssoAppIDs []string) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	var templateID string
	if options != nil {
		templateID = options.TemplateID
	}
	req := makeCreateUserRequest(&createUserRequest{
		loginID:            loginID,
		email:              email,
		phone:              phone,
		name:               displayName,
		givenName:          givenName,
		middleName:         middleName,
		familyName:         familyName,
		picture:            picture,
		roles:              roles,
		tenants:            tenants,
		invite:             invite,
		templateID:         templateID,
		test:               test,
		customAttributes:   customAttributes,
		verifiedEmail:      verifiedEmail,
		verifiedPhone:      verifiedPhone,
		additionalLoginIDs: additionalLoginIDs,
		options:            options,
		ssoAppIDs:          ssoAppIDs,
	})

	var res *api.HTTPResponse
	var err error
	if test {
		res, err = u.client.DoPostRequest(ctx, api.Routes.ManagementTestUserCreate(), req, nil, u.conf.ManagementKey)
	} else {
		res, err = u.client.DoPostRequest(ctx, api.Routes.ManagementUserCreate(), req, nil, u.conf.ManagementKey)
	}

	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) createBatch(ctx context.Context, users []*descope.BatchUser, options *descope.InviteOptions) (*descope.UsersBatchResponse, error) {
	req, err := makeCreateUsersBatchRequest(users, options)
	if err != nil {
		return nil, err
	}
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserCreateBatch(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserBatchResponse(res)
}

func (u *user) Update(ctx context.Context, loginIDOrUserID string, user *descope.UserRequest) (*descope.UserResponse, error) {
	if loginIDOrUserID == "" {
		return nil, utils.NewInvalidArgumentError("loginIDOrUserID")
	}
	if user == nil {
		user = &descope.UserRequest{}
	}
	req := makeUpdateUserRequest(&createUserRequest{
		loginID:            loginIDOrUserID,
		email:              user.Email,
		phone:              user.Phone,
		name:               user.Name,
		givenName:          user.GivenName,
		middleName:         user.MiddleName,
		familyName:         user.FamilyName,
		picture:            user.Picture,
		roles:              user.Roles,
		tenants:            user.Tenants,
		customAttributes:   user.CustomAttributes,
		verifiedEmail:      user.VerifiedEmail,
		verifiedPhone:      user.VerifiedPhone,
		additionalLoginIDs: user.AdditionalLoginIDs,
		ssoAppIDs:          user.SSOAppIDs,
	})
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserUpdate(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) Patch(ctx context.Context, loginIDOrUserID string, user *descope.PatchUserRequest) (*descope.UserResponse, error) {
	if loginIDOrUserID == "" {
		return nil, utils.NewInvalidArgumentError("loginIDOrUserID")
	}
	if user == nil {
		return nil, utils.NewInvalidArgumentError("user")
	}
	req := makePatchUserRequest(loginIDOrUserID, user)
	res, err := u.client.DoPatchRequest(ctx, api.Routes.ManagementUserPatch(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) Delete(ctx context.Context, loginIDOrUserID string) error {
	if loginIDOrUserID == "" {
		return utils.NewInvalidArgumentError("loginIDOrUserID")
	}
	return u.delete(ctx, loginIDOrUserID, "")
}

// Deprecated
func (u *user) DeleteByUserID(ctx context.Context, userID string) error {
	if userID == "" {
		return utils.NewInvalidArgumentError("userID")
	}
	return u.delete(ctx, "", userID)
}

func (u *user) delete(ctx context.Context, loginID, userID string) error {
	req := map[string]any{"loginId": loginID, "userId": userID}
	_, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserDelete(), req, nil, u.conf.ManagementKey)
	return err
}

func (u *user) DeleteAllTestUsers(ctx context.Context) error {
	_, err := u.client.DoDeleteRequest(ctx, api.Routes.ManagementUserDeleteAllTestUsers(), nil, u.conf.ManagementKey)
	return err
}

func (u *user) Import(ctx context.Context, source string, users, hashes []byte, dryrun bool) (*descope.UserImportResponse, error) {
	if source == "" {
		return nil, utils.NewInvalidArgumentError("source")
	}
	req := map[string]any{
		"source": source,
		"dryrun": dryrun,
	}
	if len(users) > 0 {
		req["users"] = users
	}
	if len(hashes) > 0 {
		req["hashes"] = hashes
	}
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserImport(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserImportResponse(res)
}

func (u *user) Load(ctx context.Context, loginIDOrUserID string) (*descope.UserResponse, error) {
	if loginIDOrUserID == "" {
		return nil, utils.NewInvalidArgumentError("loginIDOrUserID")
	}
	return u.load(ctx, loginIDOrUserID, "")
}

// Deprecated
func (u *user) LoadByUserID(ctx context.Context, userID string) (*descope.UserResponse, error) {
	if userID == "" {
		return nil, utils.NewInvalidArgumentError("userID")
	}
	return u.load(ctx, "", userID)
}

func (u *user) load(ctx context.Context, loginID, userID string) (*descope.UserResponse, error) {
	req := &api.HTTPRequest{
		QueryParams: map[string]string{"loginId": loginID, "userId": userID},
	}
	res, err := u.client.DoGetRequest(ctx, api.Routes.ManagementUserLoad(), req, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) SearchAll(ctx context.Context, options *descope.UserSearchOptions) ([]*descope.UserResponse, int, error) {
	return u.searchAll(ctx, options, false)
}

func (u *user) SearchAllTestUsers(ctx context.Context, options *descope.UserSearchOptions) ([]*descope.UserResponse, int, error) {
	// Init empty options if non given
	if options == nil {
		options = &descope.UserSearchOptions{}
	}
	options.WithTestUsers = true
	options.TestUsersOnly = true
	return u.searchAll(ctx, options, true)
}

func (u *user) searchAll(ctx context.Context, options *descope.UserSearchOptions, useTestEndpoint bool) ([]*descope.UserResponse, int, error) {
	// Init empty options if non given
	if options == nil {
		options = &descope.UserSearchOptions{}
	}

	// Make sure limit is non-negative
	if options.Limit < 0 {
		return nil, 0, utils.NewInvalidArgumentError("limit")
	}

	// Make sure page is non-negative
	if options.Page < 0 {
		return nil, 0, utils.NewInvalidArgumentError("page")
	}

	req := makeSearchAllRequest(options)

	var res *api.HTTPResponse
	var err error
	if useTestEndpoint {
		res, err = u.client.DoPostRequest(ctx, api.Routes.ManagementTestUserSearchAll(), req, nil, u.conf.ManagementKey)
	} else {
		res, err = u.client.DoPostRequest(ctx, api.Routes.ManagementUserSearchAll(), req, nil, u.conf.ManagementKey)
	}
	if err != nil {
		return nil, 0, err
	}
	return unmarshalUserSearchAllResponse(res)
}

func (u *user) Activate(ctx context.Context, loginIDOrUserID string) (*descope.UserResponse, error) {
	return u.updateStatus(ctx, loginIDOrUserID, "enabled")
}

func (u *user) Deactivate(ctx context.Context, loginIDOrUserID string) (*descope.UserResponse, error) {
	return u.updateStatus(ctx, loginIDOrUserID, "disabled")
}

func (u *user) updateStatus(ctx context.Context, loginIDOrUserID string, status string) (*descope.UserResponse, error) {
	if loginIDOrUserID == "" {
		return nil, utils.NewInvalidArgumentError("loginIDOrUserID")
	}
	req := map[string]any{"loginId": loginIDOrUserID, "status": status}
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserUpdateStatus(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) UpdateLoginID(ctx context.Context, loginID, newLoginID string) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	req := map[string]any{"loginId": loginID, "newLoginId": newLoginID}
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserUpdateLoginID(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) UpdateEmail(ctx context.Context, loginIDOrUserID, email string, isVerified bool) (*descope.UserResponse, error) {
	if loginIDOrUserID == "" {
		return nil, utils.NewInvalidArgumentError("loginIDOrUserID")
	}
	req := map[string]any{"loginId": loginIDOrUserID, "email": email, "verified": isVerified}
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserUpdateEmail(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) UpdatePhone(ctx context.Context, loginIDOrUserID, phone string, isVerified bool) (*descope.UserResponse, error) {
	if loginIDOrUserID == "" {
		return nil, utils.NewInvalidArgumentError("loginIDOrUserID")
	}
	req := map[string]any{"loginId": loginIDOrUserID, "phone": phone, "verified": isVerified}
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserUpdatePhone(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) UpdateDisplayName(ctx context.Context, loginIDOrUserID, displayName string) (*descope.UserResponse, error) {
	if loginIDOrUserID == "" {
		return nil, utils.NewInvalidArgumentError("loginIDOrUserID")
	}
	req := map[string]any{"loginId": loginIDOrUserID, "displayName": displayName}
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserUpdateDisplayName(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) UpdateUserNames(ctx context.Context, loginIDOrUserID, givenName, middleName, familyName string) (*descope.UserResponse, error) {
	if loginIDOrUserID == "" {
		return nil, utils.NewInvalidArgumentError("loginIDOrUserID")
	}
	req := map[string]any{"loginId": loginIDOrUserID, "givenName": givenName, "middleName": middleName, "familyName": familyName}
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserUpdateDisplayName(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) UpdatePicture(ctx context.Context, loginIDOrUserID, picture string) (*descope.UserResponse, error) {
	if loginIDOrUserID == "" {
		return nil, utils.NewInvalidArgumentError("loginIDOrUserID")
	}
	req := map[string]any{"loginId": loginIDOrUserID, "picture": picture}
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserUpdatePicture(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) UpdateCustomAttribute(ctx context.Context, loginIDOrUserID, key string, value any) (*descope.UserResponse, error) {
	if loginIDOrUserID == "" {
		return nil, utils.NewInvalidArgumentError("loginIDOrUserID")
	}
	if key == "" {
		return nil, utils.NewInvalidArgumentError("key")
	}
	req := map[string]any{"loginId": loginIDOrUserID, "attributeKey": key, "attributeValue": value}
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserUpdateCustomAttribute(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) SetRoles(ctx context.Context, loginIDOrUserID string, roles []string) (*descope.UserResponse, error) {
	if loginIDOrUserID == "" {
		return nil, utils.NewInvalidArgumentError("loginIDOrUserID")
	}
	req := makeUpdateUserRolesRequest(loginIDOrUserID, "", roles)
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserSetRole(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) AddRoles(ctx context.Context, loginIDOrUserID string, roles []string) (*descope.UserResponse, error) {
	if loginIDOrUserID == "" {
		return nil, utils.NewInvalidArgumentError("loginIDOrUserID")
	}
	req := makeUpdateUserRolesRequest(loginIDOrUserID, "", roles)
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserAddRole(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) RemoveRoles(ctx context.Context, loginIDOrUserID string, roles []string) (*descope.UserResponse, error) {
	if loginIDOrUserID == "" {
		return nil, utils.NewInvalidArgumentError("loginIDOrUserID")
	}
	req := makeUpdateUserRolesRequest(loginIDOrUserID, "", roles)
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserRemoveRole(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) AddSSOApps(ctx context.Context, loginIDOrUserID string, ssoAppIDs []string) (*descope.UserResponse, error) {
	if loginIDOrUserID == "" {
		return nil, utils.NewInvalidArgumentError("loginIDOrUserID")
	}
	req := makeUpdateUserSSOAppsRequest(loginIDOrUserID, ssoAppIDs)
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserAddSSOApps(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) SetSSOApps(ctx context.Context, loginIDOrUserID string, ssoAppIDs []string) (*descope.UserResponse, error) {
	if loginIDOrUserID == "" {
		return nil, utils.NewInvalidArgumentError("loginIDOrUserID")
	}
	req := makeUpdateUserSSOAppsRequest(loginIDOrUserID, ssoAppIDs)
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserSetSSOApps(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) RemoveSSOApps(ctx context.Context, loginIDOrUserID string, ssoAppIDs []string) (*descope.UserResponse, error) {
	if loginIDOrUserID == "" {
		return nil, utils.NewInvalidArgumentError("loginIDOrUserID")
	}
	req := makeUpdateUserSSOAppsRequest(loginIDOrUserID, ssoAppIDs)
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserRemoveSSOApps(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) AddTenant(ctx context.Context, loginIDOrUserID string, tenantID string) (*descope.UserResponse, error) {
	if loginIDOrUserID == "" {
		return nil, utils.NewInvalidArgumentError("loginIDOrUserID")
	}
	req := makeUpdateUserTenantRequest(loginIDOrUserID, tenantID)
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserAddTenant(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) RemoveTenant(ctx context.Context, loginIDOrUserID string, tenantID string) (*descope.UserResponse, error) {
	if loginIDOrUserID == "" {
		return nil, utils.NewInvalidArgumentError("loginIDOrUserID")
	}
	req := makeUpdateUserTenantRequest(loginIDOrUserID, tenantID)
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserRemoveTenant(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) SetTenantRoles(ctx context.Context, loginIDOrUserID string, tenantID string, roles []string) (*descope.UserResponse, error) {
	if loginIDOrUserID == "" {
		return nil, utils.NewInvalidArgumentError("loginIDOrUserID")
	}
	req := makeUpdateUserRolesRequest(loginIDOrUserID, tenantID, roles)
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserSetRole(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) AddTenantRoles(ctx context.Context, loginIDOrUserID string, tenantID string, roles []string) (*descope.UserResponse, error) {
	if loginIDOrUserID == "" {
		return nil, utils.NewInvalidArgumentError("loginIDOrUserID")
	}
	req := makeUpdateUserRolesRequest(loginIDOrUserID, tenantID, roles)
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserAddRole(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) RemoveTenantRoles(ctx context.Context, loginIDOrUserID string, tenantID string, roles []string) (*descope.UserResponse, error) {
	if loginIDOrUserID == "" {
		return nil, utils.NewInvalidArgumentError("loginIDOrUserID")
	}
	req := makeUpdateUserRolesRequest(loginIDOrUserID, tenantID, roles)
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserRemoveRole(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) SetTemporaryPassword(ctx context.Context, loginID string, password string) error {
	if loginID == "" {
		return utils.NewInvalidArgumentError("loginID")
	}
	if password == "" {
		return utils.NewInvalidArgumentError("password")
	}

	req := makeSetPasswordRequest(loginID, password, false)
	_, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserSetTemporaryPassword(), req, nil, u.conf.ManagementKey)
	return err
}
func (u *user) SetActivePassword(ctx context.Context, loginID string, password string) error {
	if loginID == "" {
		return utils.NewInvalidArgumentError("loginID")
	}
	if password == "" {
		return utils.NewInvalidArgumentError("password")
	}

	req := makeSetPasswordRequest(loginID, password, true)
	_, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserSetActivePassword(), req, nil, u.conf.ManagementKey)
	return err
}

/* Deprecated */
func (u *user) SetPassword(ctx context.Context, loginID string, password string) error {
	if loginID == "" {
		return utils.NewInvalidArgumentError("loginID")
	}
	if password == "" {
		return utils.NewInvalidArgumentError("password")
	}

	req := makeSetPasswordRequest(loginID, password, false)
	_, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserSetPassword(), req, nil, u.conf.ManagementKey)
	return err
}

func (u *user) ExpirePassword(ctx context.Context, loginID string) error {
	if loginID == "" {
		return utils.NewInvalidArgumentError("loginID")
	}

	req := map[string]any{"loginId": loginID}
	_, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserExpirePassword(), req, nil, u.conf.ManagementKey)
	return err
}

func (u *user) RemoveAllPasskeys(ctx context.Context, loginID string) error {
	if loginID == "" {
		return utils.NewInvalidArgumentError("loginID")
	}

	req := map[string]any{"loginId": loginID}
	_, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserRemoveAllPasskeys(), req, nil, u.conf.ManagementKey)
	return err
}

func (u *user) GetProviderToken(ctx context.Context, loginID, provider string) (*descope.ProviderTokenResponse, error) {
	return u.GetProviderTokenWithOptions(ctx, loginID, provider, nil)
}

func (u *user) GetProviderTokenWithOptions(ctx context.Context, loginID, provider string, options *descope.ProviderTokenOptions) (*descope.ProviderTokenResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	if provider == "" {
		return nil, utils.NewInvalidArgumentError("provider")
	}
	if options == nil {
		options = &descope.ProviderTokenOptions{}
	}
	req := &api.HTTPRequest{
		QueryParams: map[string]string{
			"loginId":          loginID,
			"provider":         provider,
			"withRefreshToken": strconv.FormatBool(options.WithRefreshToken),
			"forceRefresh":     strconv.FormatBool(options.ForceRefresh),
		},
	}
	res, err := u.client.DoGetRequest(ctx, api.Routes.ManagementUserGetProviderToken(), req, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}

	return unmarshalProviderTokenResponse(res)
}

func (u *user) LogoutUser(ctx context.Context, loginID string) error {
	if len(loginID) == 0 {
		return utils.NewInvalidArgumentError("loginID")
	}
	return u.logoutUser(ctx, "", loginID)
}

func (u *user) LogoutUserByUserID(ctx context.Context, userID string) error {
	if len(userID) == 0 {
		return utils.NewInvalidArgumentError("userID")
	}
	return u.logoutUser(ctx, userID, "")
}

func (u *user) logoutUser(ctx context.Context, userID string, loginID string) error {
	_, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserLogoutAllDevices(), map[string]any{"userId": userID, "loginId": loginID}, nil, u.conf.ManagementKey)
	return err
}

func (u *user) GenerateOTPForTestUser(ctx context.Context, method descope.DeliveryMethod, loginID string, loginOptions *descope.LoginOptions) (code string, err error) {
	if loginID == "" {
		return "", utils.NewInvalidArgumentError("loginID")
	}
	req := makeGenerateOTPForTestUserRequestBody(method, loginID, loginOptions)
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserGenerateOTPForTest(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return "", err
	}
	return unmarshalGenerateOTPForTestResponse(res)
}

func (u *user) GenerateMagicLinkForTestUser(ctx context.Context, method descope.DeliveryMethod, loginID, URI string, loginOptions *descope.LoginOptions) (link string, err error) {
	if loginID == "" {
		return "", utils.NewInvalidArgumentError("loginID")
	}
	req := makeGenerateMagicLinkForTestUserRequestBody(method, loginID, URI, loginOptions)
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserGenerateMagicLinkForTest(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return "", err
	}
	link, _, err = unmarshalGenerateLinkForTestResponse(res)
	return link, err
}

func (u *user) GenerateEnchantedLinkForTestUser(ctx context.Context, loginID, URI string, loginOptions *descope.LoginOptions) (link, pendingRef string, err error) {
	if loginID == "" {
		return "", "", utils.NewInvalidArgumentError("loginID")
	}
	req := makeGenerateEnchantedLinkForTestUserRequestBody(loginID, URI, loginOptions)
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserGenerateEnchantedLinkForTest(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return "", "", err
	}
	return unmarshalGenerateLinkForTestResponse(res)
}

type embeddedLinkRes struct {
	Token string `json:"token"`
}

func (u *user) GenerateEmbeddedLink(ctx context.Context, loginID string, customClaims map[string]any) (string, error) {
	if loginID == "" {
		return "", utils.NewInvalidArgumentError("loginID")
	}
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementGenerateEmbeddedLink(), map[string]any{
		"loginId":      loginID,
		"customClaims": customClaims,
	}, nil, u.conf.ManagementKey)
	if err != nil {
		return "", err
	}
	tRes := &embeddedLinkRes{}
	err = utils.Unmarshal([]byte(res.BodyStr), tRes)
	if err != nil {
		return "", err //notest
	}
	return tRes.Token, nil
}

func (u *user) History(ctx context.Context, userIDs []string) ([]*descope.UserHistoryResponse, error) {
	if userIDs == nil {
		return nil, utils.NewInvalidArgumentError("userIDs")
	}
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserHistory(), userIDs, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	tRes := []*descope.UserHistoryResponse{}
	err = utils.Unmarshal([]byte(res.BodyStr), &tRes)
	if err != nil {
		return nil, err //notest
	}
	return tRes, nil
}

func makeCreateUserRequest(createReq *createUserRequest) map[string]any {
	req := makeUpdateUserRequest(createReq)
	req["invite"] = createReq.invite
	if len(createReq.templateID) > 0 {
		req["templateId"] = createReq.templateID
	}
	req["additionalLoginIds"] = createReq.additionalLoginIDs
	if createReq.test {
		req["test"] = true
	}
	if options := createReq.options; options != nil {
		if len(options.InviteURL) > 0 {
			req["inviteUrl"] = options.InviteURL
		}
		if options.SendMail != nil {
			req["sendMail"] = *options.SendMail
		}
		if options.SendSMS != nil {
			req["sendSMS"] = *options.SendSMS
		}
		if options.TemplateOptions != nil {
			req["templateOptions"] = options.TemplateOptions
		}
	}
	return req
}

func makeCreateUsersBatchRequest(users []*descope.BatchUser, options *descope.InviteOptions) (map[string]any, error) {
	var usersReq []map[string]any
	for _, u := range users {
		user := makeUpdateUserRequest(&createUserRequest{
			loginID:            u.LoginID,
			email:              u.Email,
			phone:              u.Phone,
			name:               u.Name,
			givenName:          u.GivenName,
			middleName:         u.MiddleName,
			familyName:         u.FamilyName,
			picture:            u.Picture,
			roles:              u.Roles,
			tenants:            u.Tenants,
			customAttributes:   u.CustomAttributes,
			verifiedEmail:      u.VerifiedEmail,
			verifiedPhone:      u.VerifiedPhone,
			additionalLoginIDs: u.AdditionalLoginIDs,
			ssoAppIDs:          u.SSOAppIDs,
		})
		if u.Password != nil {
			if cleartext := u.Password.Cleartext; cleartext != "" {
				user["password"] = u.Password.Cleartext
			}
			if hashed := u.Password.Hashed; hashed != nil {
				b, err := utils.Marshal(hashed)
				if err != nil {
					return nil, err
				}
				var m map[string]any
				if err := utils.Unmarshal(b, &m); err != nil {
					return nil, err
				}
				user["hashedPassword"] = m
			}
		}
		if u.Seed != nil {
			user["seed"] = u.Seed
		}
		usersReq = append(usersReq, user)
	}
	req := map[string]any{
		"users": usersReq,
	}
	if options != nil {
		req["invite"] = true
		if len(options.InviteURL) > 0 {
			req["inviteUrl"] = options.InviteURL
		}
		if options.SendMail != nil {
			req["sendMail"] = *options.SendMail
		}
		if options.SendSMS != nil {
			req["sendSMS"] = *options.SendSMS
		}
	}

	return req, nil
}

func makeUpdateUserRequest(req *createUserRequest) map[string]any {
	res := map[string]any{
		"loginId":            req.loginID,
		"email":              req.email,
		"phone":              req.phone,
		"displayName":        req.name,
		"givenName":          req.givenName,
		"middleName":         req.middleName,
		"familyName":         req.familyName,
		"roleNames":          req.roles,
		"userTenants":        makeAssociatedTenantList(req.tenants),
		"customAttributes":   req.customAttributes,
		"picture":            req.picture,
		"additionalLoginIds": req.additionalLoginIDs,
	}
	if req.verifiedEmail != nil {
		res["verifiedEmail"] = *req.verifiedEmail
	}
	if req.verifiedPhone != nil {
		res["verifiedPhone"] = *req.verifiedPhone
	}
	res["ssoAppIDs"] = req.ssoAppIDs
	return res
}

func makePatchUserRequest(loginID string, req *descope.PatchUserRequest) map[string]any {
	res := map[string]interface{}{
		"loginId": loginID,
	}
	if req.Name != nil {
		res["name"] = *req.Name
	}
	if req.GivenName != nil {
		res["givenName"] = *req.GivenName
	}
	if req.MiddleName != nil {
		res["middleName"] = *req.MiddleName
	}
	if req.FamilyName != nil {
		res["familyName"] = *req.FamilyName
	}
	if req.Phone != nil {
		res["phone"] = *req.Phone
	}
	if req.Email != nil {
		res["email"] = *req.Email
	}
	if req.Roles != nil {
		res["roleNames"] = *req.Roles
	}
	if req.Tenants != nil {
		res["userTenants"] = makeAssociatedTenantList(*req.Tenants)
	}
	if req.CustomAttributes != nil {
		res["customAttributes"] = req.CustomAttributes
	}
	if req.Picture != nil {
		res["picture"] = *req.Picture
	}
	if req.VerifiedEmail != nil {
		res["verifiedEmail"] = *req.VerifiedEmail
	}
	if req.VerifiedPhone != nil {
		res["verifiedPhone"] = *req.VerifiedPhone
	}
	if req.SSOAppIDs != nil {
		res["ssoAppIds"] = *req.SSOAppIDs
	}
	return res
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

func makeUpdateUserSSOAppsRequest(loginID string, ssoAppIDs []string) map[string]any {
	return map[string]any{
		"loginId":   loginID,
		"ssoAppIds": ssoAppIDs,
	}
}

func makeSetPasswordRequest(loginID string, password string, setActive bool) map[string]any {
	return map[string]any{
		"loginId":   loginID,
		"password":  password,
		"setActive": setActive,
	}
}

func makeSearchAllRequest(options *descope.UserSearchOptions) map[string]any {
	return map[string]any{
		"tenantIds":        options.TenantIDs,
		"roleNames":        options.Roles,
		"limit":            options.Limit,
		"page":             options.Page,
		"sort":             options.Sort,
		"text":             options.Text,
		"loginIds":         options.LoginIDs,
		"testUsersOnly":    options.TestUsersOnly,
		"withTestUser":     options.WithTestUsers,
		"customAttributes": options.CustomAttributes,
		"statuses":         options.Statuses,
		"emails":           options.Emails,
		"phones":           options.Phones,
		"ssoAppIds":        options.SSOAppIDs,
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
	return ures.User, nil
}

func unmarshalUserImportResponse(res *api.HTTPResponse) (*descope.UserImportResponse, error) {
	resBody := &descope.UserImportResponse{}
	err := utils.Unmarshal([]byte(res.BodyStr), &resBody)
	if err != nil {
		return nil, err
	}
	return resBody, nil
}

func unmarshalUserBatchResponse(res *api.HTTPResponse) (*descope.UsersBatchResponse, error) {
	ures := &descope.UsersBatchResponse{}
	err := utils.Unmarshal([]byte(res.BodyStr), ures)
	if err != nil {
		return nil, err
	}
	return ures, err
}

func unmarshalUserSearchAllResponse(res *api.HTTPResponse) ([]*descope.UserResponse, int, error) {
	ures := struct {
		Users []*descope.UserResponse
		Total int
	}{}
	err := utils.Unmarshal([]byte(res.BodyStr), &ures)
	if err != nil {
		return nil, 0, err
	}
	return ures.Users, ures.Total, nil
}

func unmarshalProviderTokenResponse(res *api.HTTPResponse) (*descope.ProviderTokenResponse, error) {
	resBody := &descope.ProviderTokenResponse{}
	err := utils.Unmarshal([]byte(res.BodyStr), &resBody)
	if err != nil {
		return nil, err
	}
	return resBody, nil
}

type generateForTestUserRequestBody struct {
	LoginID      string                `json:"loginId,omitempty"`
	LoginOptions *descope.LoginOptions `json:"loginOptions,omitempty"`
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

func makeGenerateOTPForTestUserRequestBody(method descope.DeliveryMethod, loginID string, loginOptions *descope.LoginOptions) *generateOTPForTestUserRequestBody {
	return &generateOTPForTestUserRequestBody{
		generateForTestUserRequestBody: &generateForTestUserRequestBody{
			LoginID:      loginID,
			LoginOptions: loginOptions,
		},
		DeliveryMethod: string(method),
	}
}

func makeGenerateMagicLinkForTestUserRequestBody(method descope.DeliveryMethod, loginID, URI string, loginOptions *descope.LoginOptions) *generateMagicLinkForTestUserRequestBody {
	return &generateMagicLinkForTestUserRequestBody{
		generateForTestUserRequestBody: &generateForTestUserRequestBody{
			LoginID:      loginID,
			LoginOptions: loginOptions,
		},
		DeliveryMethod: string(method),
		URI:            URI,
	}
}

func makeGenerateEnchantedLinkForTestUserRequestBody(loginID, URI string, loginOptions *descope.LoginOptions) *generateEnchantedLinkForTestUserRequestBody {
	return &generateEnchantedLinkForTestUserRequestBody{
		generateForTestUserRequestBody: &generateForTestUserRequestBody{
			LoginID:      loginID,
			LoginOptions: loginOptions,
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
	return resBody.Code, nil
}

func unmarshalGenerateLinkForTestResponse(res *api.HTTPResponse) (string, string, error) {
	resBody := &GenerateLinkForTestResponse{}
	err := utils.Unmarshal([]byte(res.BodyStr), &resBody)
	if err != nil {
		return "", "", err
	}
	return resBody.Link, resBody.PendingRef, nil
}
