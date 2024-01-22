package mgmt

import (
	"context"
	"encoding/base64"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
)

type user struct {
	managementBase
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
		users = []*descope.BatchUser{}
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
		users = []*descope.BatchUser{}
	}
	return u.createBatch(ctx, users, options)
}

func (u *user) create(ctx context.Context, loginID, email, phone, displayName, givenName, middleName, familyName, picture string, roles []string, tenants []*descope.AssociatedTenant, invite, test bool, customAttributes map[string]any, verifiedEmail *bool, verifiedPhone *bool, additionalLoginIDs []string, options *descope.InviteOptions, ssoAppIDs []string) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	req := makeCreateUserRequest(loginID, email, phone, displayName, givenName, middleName, familyName, picture, roles, tenants, invite, test, customAttributes, verifiedEmail, verifiedPhone, additionalLoginIDs, options, ssoAppIDs)
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserCreate(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) createBatch(ctx context.Context, users []*descope.BatchUser, options *descope.InviteOptions) (*descope.UsersBatchResponse, error) {
	req := makeCreateUsersBatchRequest(users, options)
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserCreateBatch(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserBatchResponse(res)
}

func (u *user) Update(ctx context.Context, loginID string, user *descope.UserRequest) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	if user == nil {
		user = &descope.UserRequest{}
	}
	req := makeUpdateUserRequest(loginID, user.Email, user.Phone, user.Name, user.GivenName, user.MiddleName, user.FamilyName, user.Picture, user.Roles, user.Tenants, user.CustomAttributes, user.VerifiedEmail, user.VerifiedPhone, user.AdditionalLoginIDs, user.SSOAppIDs)
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserUpdate(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) Delete(ctx context.Context, loginID string) error {
	if loginID == "" {
		return utils.NewInvalidArgumentError("loginID")
	}
	return u.delete(ctx, loginID, "")
}

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

func (u *user) Load(ctx context.Context, loginID string) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	return u.load(ctx, loginID, "")
}

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

func (u *user) SearchAll(ctx context.Context, options *descope.UserSearchOptions) ([]*descope.UserResponse, error) {
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
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserSearchAll(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserSearchAllResponse(res)
}

func (u *user) Activate(ctx context.Context, loginID string) (*descope.UserResponse, error) {
	return u.updateStatus(ctx, loginID, "enabled")
}

func (u *user) Deactivate(ctx context.Context, loginID string) (*descope.UserResponse, error) {
	return u.updateStatus(ctx, loginID, "disabled")
}

func (u *user) updateStatus(ctx context.Context, loginID string, status string) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	req := map[string]any{"loginId": loginID, "status": status}
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

func (u *user) UpdateEmail(ctx context.Context, loginID, email string, isVerified bool) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	req := map[string]any{"loginId": loginID, "email": email, "verified": isVerified}
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserUpdateEmail(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) UpdatePhone(ctx context.Context, loginID, phone string, isVerified bool) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	req := map[string]any{"loginId": loginID, "phone": phone, "verified": isVerified}
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserUpdatePhone(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) UpdateDisplayName(ctx context.Context, loginID, displayName string) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	req := map[string]any{"loginId": loginID, "displayName": displayName}
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserUpdateDisplayName(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) UpdateUserNames(ctx context.Context, loginID, givenName, middleName, familyName string) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	req := map[string]any{"loginId": loginID, "givenName": givenName, "middleName": middleName, "familyName": familyName}
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserUpdateDisplayName(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) UpdatePicture(ctx context.Context, loginID, picture string) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	req := map[string]any{"loginId": loginID, "picture": picture}
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserUpdatePicture(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) UpdateCustomAttribute(ctx context.Context, loginID, key string, value any) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	if key == "" {
		return nil, utils.NewInvalidArgumentError("key")
	}
	req := map[string]any{"loginId": loginID, "attributeKey": key, "attributeValue": value}
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserUpdateCustomAttribute(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) SetRoles(ctx context.Context, loginID string, roles []string) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	req := makeUpdateUserRolesRequest(loginID, "", roles)
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserSetRole(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) AddRoles(ctx context.Context, loginID string, roles []string) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	req := makeUpdateUserRolesRequest(loginID, "", roles)
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserAddRole(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) RemoveRoles(ctx context.Context, loginID string, roles []string) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	req := makeUpdateUserRolesRequest(loginID, "", roles)
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserRemoveRole(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) AddSSOApps(ctx context.Context, loginID string, ssoAppIDs []string) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	req := makeUpdateUserSSOAppsRequest(loginID, ssoAppIDs)
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserAddSSOApps(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) SetSSOApps(ctx context.Context, loginID string, ssoAppIDs []string) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	req := makeUpdateUserSSOAppsRequest(loginID, ssoAppIDs)
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserSetSSOApps(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) RemoveSSOApps(ctx context.Context, loginID string, ssoAppIDs []string) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	req := makeUpdateUserSSOAppsRequest(loginID, ssoAppIDs)
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserRemoveSSOApps(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) AddTenant(ctx context.Context, loginID string, tenantID string) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	req := makeUpdateUserTenantRequest(loginID, tenantID)
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserAddTenant(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) RemoveTenant(ctx context.Context, loginID string, tenantID string) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	req := makeUpdateUserTenantRequest(loginID, tenantID)
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserRemoveTenant(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) SetTenantRoles(ctx context.Context, loginID string, tenantID string, roles []string) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	req := makeUpdateUserRolesRequest(loginID, tenantID, roles)
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserSetRole(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) AddTenantRoles(ctx context.Context, loginID string, tenantID string, roles []string) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	req := makeUpdateUserRolesRequest(loginID, tenantID, roles)
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserAddRole(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) RemoveTenantRoles(ctx context.Context, loginID string, tenantID string, roles []string) (*descope.UserResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	req := makeUpdateUserRolesRequest(loginID, tenantID, roles)
	res, err := u.client.DoPostRequest(ctx, api.Routes.ManagementUserRemoveRole(), req, nil, u.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (u *user) SetPassword(ctx context.Context, loginID string, password string) error {
	if loginID == "" {
		return utils.NewInvalidArgumentError("loginID")
	}
	if password == "" {
		return utils.NewInvalidArgumentError("password")
	}

	req := makeSetPasswordRequest(loginID, password)
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
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	if provider == "" {
		return nil, utils.NewInvalidArgumentError("provider")
	}

	req := &api.HTTPRequest{
		QueryParams: map[string]string{"loginId": loginID, "provider": provider},
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

func makeCreateUserRequest(loginID, email, phone, displayName, givenName, middleName, familyName, picture string, roles []string, tenants []*descope.AssociatedTenant, invite, test bool, customAttributes map[string]any, verifiedEmail *bool, verifiedPhone *bool, additionalLoginIDs []string, options *descope.InviteOptions, ssoAppIDs []string) map[string]any {
	req := makeUpdateUserRequest(loginID, email, phone, displayName, givenName, middleName, familyName, picture, roles, tenants, customAttributes, verifiedEmail, verifiedPhone, additionalLoginIDs, ssoAppIDs)
	req["invite"] = invite
	req["additionalLoginIds"] = additionalLoginIDs
	if test {
		req["test"] = true
	}
	if options != nil {
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
	return req
}

func makeCreateUsersBatchRequest(users []*descope.BatchUser, options *descope.InviteOptions) map[string]any {
	var usersReq []map[string]any
	for _, u := range users {
		user := makeUpdateUserRequest(u.LoginID, u.Email, u.Phone, u.Name, u.GivenName, u.MiddleName, u.FamilyName, u.Picture, u.Roles, u.Tenants, u.CustomAttributes, u.VerifiedEmail, u.VerifiedPhone, u.AdditionalLoginIDs, u.SSOAppIDs)
		if u.Password != nil {
			if cleartext := u.Password.Cleartext; cleartext != "" {
				user["password"] = u.Password.Cleartext
			}
			if hashed := u.Password.Hashed; hashed != nil {
				m := map[string]any{
					"algorithm": hashed.Algorithm,
					"hash":      base64.RawStdEncoding.EncodeToString(hashed.Hash),
				}
				if len(hashed.Salt) > 0 {
					m["salt"] = base64.RawStdEncoding.EncodeToString(hashed.Salt)
				}
				if hashed.Iterations != 0 {
					m["iterations"] = hashed.Iterations
				}
				user["hashedPassword"] = m
			}
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

	return req
}

func makeUpdateUserRequest(loginID, email, phone, displayName, givenName, middleName, familyName, picture string, roles []string, tenants []*descope.AssociatedTenant, customAttributes map[string]any, verifiedEmail *bool, verifiedPhone *bool, additionalLoginIDs []string, ssoAppIDs []string) map[string]any {
	res := map[string]any{
		"loginId":            loginID,
		"email":              email,
		"phone":              phone,
		"displayName":        displayName,
		"givenName":          givenName,
		"middleName":         middleName,
		"familyName":         familyName,
		"roleNames":          roles,
		"userTenants":        makeAssociatedTenantList(tenants),
		"customAttributes":   customAttributes,
		"picture":            picture,
		"additionalLoginIds": additionalLoginIDs,
	}
	if verifiedEmail != nil {
		res["verifiedEmail"] = *verifiedEmail
	}
	if verifiedPhone != nil {
		res["verifiedPhone"] = *verifiedPhone
	}
	res["ssoAppIDs"] = ssoAppIDs
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

func makeSetPasswordRequest(loginID string, password string) map[string]any {
	return map[string]any{
		"loginId":  loginID,
		"password": password,
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

func unmarshalUserSearchAllResponse(res *api.HTTPResponse) ([]*descope.UserResponse, error) {
	ures := struct {
		Users []*descope.UserResponse
	}{}
	err := utils.Unmarshal([]byte(res.BodyStr), &ures)
	if err != nil {
		return nil, err
	}
	return ures.Users, nil
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
