package mocksmgmt

import (
	"context"
	"time"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/sdk"
)

type MockManagement struct {
	*MockJWT
	*MockSSO
	*MockPasswordManagement
	*MockUser
	*MockAccessKey
	*MockTenant
	*MockSSOApplication
	*MockPermission
	*MockRole
	*MockGroup
	*MockFlow
	*MockProject
	*MockAudit
	*MockAnalytics
	*MockAuthz
	*MockFGA
	*MockThirdPartyApplication
	*MockOutboundApplication
	*MockManagementKey
	*MockDescoper
}

func (m *MockManagement) JWT() sdk.JWT {
	return m.MockJWT
}

func (m *MockManagement) SSO() sdk.SSO {
	return m.MockSSO
}

func (m *MockManagement) User() sdk.User {
	return m.MockUser
}

func (m *MockManagement) AccessKey() sdk.AccessKey {
	return m.MockAccessKey
}

func (m *MockManagement) Tenant() sdk.Tenant {
	return m.MockTenant
}

func (m *MockManagement) SSOApplication() sdk.SSOApplication {
	return m.MockSSOApplication
}

func (m *MockManagement) Permission() sdk.Permission {
	return m.MockPermission
}

func (m *MockManagement) Role() sdk.Role {
	return m.MockRole
}

func (m *MockManagement) Group() sdk.Group {
	return m.MockGroup
}

func (m *MockManagement) Flow() sdk.Flow {
	return m.MockFlow
}

func (m *MockManagement) Project() sdk.Project {
	return m.MockProject
}

func (m *MockManagement) Audit() sdk.Audit {
	return m.MockAudit
}

func (m *MockManagement) Analytics() sdk.Analytics {
	return m.MockAnalytics
}

func (m *MockManagement) Authz() sdk.Authz {
	return m.MockAuthz
}

func (m *MockManagement) Password() sdk.PasswordManagement {
	return m.MockPasswordManagement
}

func (m *MockManagement) FGA() sdk.FGA {
	return m.MockFGA
}

func (m *MockManagement) ThirdPartyApplication() sdk.ThirdPartyApplication {
	return m.MockThirdPartyApplication
}

func (m *MockManagement) OutboundApplication() sdk.OutboundApplication {
	return m.MockOutboundApplication
}

func (m *MockManagement) ManagementKey() sdk.ManagementKey {
	return m.MockManagementKey
}

// Mock JWT

type MockJWT struct {
	UpdateJWTWithCustomClaimsAssert   func(jwt string, customClaims map[string]any, refreshDuration int32)
	UpdateJWTWithCustomClaimsResponse string
	UpdateJWTWithCustomClaimsError    error

	ImpersonateAssert   func(impersonatorID string, loginID string, validateConcent bool, customClaims map[string]any, tenantID string, refreshDuration int32)
	ImpersonateResponse string
	ImpersonateError    error

	StopImpersonationAssert   func(jwt string, customClaims map[string]any, tenantID string, refreshDuration int32)
	StopImpersonationResponse string
	StopImpersonationError    error

	SignInAssert   func(loginID string, loginOptions *descope.MgmLoginOptions)
	SignInResponse *descope.AuthenticationInfo
	SignInError    error

	SignUpAssert   func(loginID string, user *descope.MgmtUserRequest, signUpOptions *descope.MgmSignUpOptions)
	SignUpResponse *descope.AuthenticationInfo
	SignUpError    error

	SignUpOrInAssert   func(loginID string, user *descope.MgmtUserRequest, signUpOptions *descope.MgmSignUpOptions)
	SignUpOrInResponse *descope.AuthenticationInfo
	SignUpOrInError    error

	AnonymousAssert   func(customClaims map[string]any, selectedTenant string, refreshDuration int32)
	AnonymousResponse *descope.AnonymousAuthenticationInfo
	AnonymousError    error
}

func (m *MockJWT) UpdateJWTWithCustomClaims(_ context.Context, jwt string, customClaims map[string]any, refreshDuration int32) (string, error) {
	if m.UpdateJWTWithCustomClaimsAssert != nil {
		m.UpdateJWTWithCustomClaimsAssert(jwt, customClaims, refreshDuration)
	}
	return m.UpdateJWTWithCustomClaimsResponse, m.UpdateJWTWithCustomClaimsError
}

func (m *MockJWT) Impersonate(_ context.Context, impersonatorID string, loginID string, validateConcent bool, customClaims map[string]any, tenantID string, refreshDuration int32) (string, error) {
	if m.ImpersonateAssert != nil {
		m.ImpersonateAssert(impersonatorID, loginID, validateConcent, customClaims, tenantID, refreshDuration)
	}
	return m.ImpersonateResponse, m.ImpersonateError
}

func (m *MockJWT) StopImpersonation(_ context.Context, jwt string, customClaims map[string]any, tenantID string, refreshDuration int32) (string, error) {
	if m.StopImpersonationAssert != nil {
		m.StopImpersonationAssert(jwt, customClaims, tenantID, refreshDuration)
	}
	return m.StopImpersonationResponse, m.StopImpersonationError
}

func (m *MockJWT) SignIn(_ context.Context, loginID string, loginOptions *descope.MgmLoginOptions) (*descope.AuthenticationInfo, error) {
	if m.SignInAssert != nil {
		m.SignInAssert(loginID, loginOptions)
	}
	return m.SignInResponse, m.SignInError
}
func (m *MockJWT) SignUp(_ context.Context, loginID string, user *descope.MgmtUserRequest, signUpOptions *descope.MgmSignUpOptions) (*descope.AuthenticationInfo, error) {
	if m.SignUpAssert != nil {
		m.SignUpAssert(loginID, user, signUpOptions)
	}
	return m.SignUpResponse, m.SignUpError
}
func (m *MockJWT) SignUpOrIn(_ context.Context, loginID string, user *descope.MgmtUserRequest, signUpOptions *descope.MgmSignUpOptions) (*descope.AuthenticationInfo, error) {
	if m.SignUpOrInAssert != nil {
		m.SignUpOrInAssert(loginID, user, signUpOptions)
	}
	return m.SignUpOrInResponse, m.SignUpOrInError
}

func (m *MockJWT) Anonymous(_ context.Context, customClaims map[string]any, selectedTenant string, refreshDuration int32) (*descope.AnonymousAuthenticationInfo, error) {
	if m.AnonymousAssert != nil {
		m.AnonymousAssert(customClaims, selectedTenant, refreshDuration)
	}
	return m.AnonymousResponse, m.AnonymousError
}

// Mock SSO

type MockSSO struct {
	LoadSettingsAssert   func(tenantID string, ssoID string)
	LoadSettingsResponse *descope.SSOTenantSettingsResponse
	LoadSettingsError    error

	LoadAllSettingsAssert   func(tenantID string)
	LoadAllSettingsResponse []*descope.SSOTenantSettingsResponse
	LoadAllSettingsError    error

	ConfigureSAMLSettingsAssert func(tenantID string, settings *descope.SSOSAMLSettings, redirectURL string, domains []string, ssoID string)
	ConfigureSAMLSettingsError  error

	ConfigureSAMLSettingsByMetadataAssert func(tenantID string, settings *descope.SSOSAMLSettingsByMetadata, redirectURL string, domains []string, ssoID string)
	ConfigureSAMLSettingsByMetadataError  error

	ConfigureSSORedirectURLAssert func(tenantID string, samlRedirectURL *string, oauthRedirectURL *string, ssoID string)
	ConfigureSSORedirectURLError  error

	ConfigureOIDCSettingsAssert func(tenantID string, settings *descope.SSOOIDCSettings, domains []string, ssoID string)
	ConfigureOIDCSettingsError  error

	NewSettingsAssert   func(tenantID string, ssoID string, displayName string)
	NewSettingsResponse *descope.SSOTenantSettingsResponse
	NewSettingsError    error

	DeleteSettingsAssert func(tenantID string, ssoID string)
	DeleteSettingsError  error

	GetSettingsAssert   func(tenantID string)
	GetSettingsResponse *descope.SSOSettingsResponse
	GetSettingsError    error

	ConfigureSettingsAssert func(tenantID, idpURL, idpCert, entityID, redirectURL string, domains []string)
	ConfigureSettingsError  error

	ConfigureMetadataAssert func(tenantID, idpMetadataURL, redirectURL string, domains []string)
	ConfigureMetadataError  error

	ConfigureMappingAssert func(tenantID string, roleMappings []*descope.RoleMapping, attributeMapping *descope.AttributeMapping)
	ConfigureMappingError  error
}

func (m *MockSSO) LoadSettings(_ context.Context, tenantID string, ssoID string) (*descope.SSOTenantSettingsResponse, error) {
	if m.LoadSettingsAssert != nil {
		m.LoadSettingsAssert(tenantID, ssoID)
	}
	return m.LoadSettingsResponse, m.LoadSettingsError
}

func (m *MockSSO) LoadAllSettings(_ context.Context, tenantID string) ([]*descope.SSOTenantSettingsResponse, error) {
	if m.LoadAllSettingsAssert != nil {
		m.LoadAllSettingsAssert(tenantID)
	}
	return m.LoadAllSettingsResponse, m.LoadAllSettingsError
}

func (m *MockSSO) ConfigureSAMLSettings(_ context.Context, tenantID string, settings *descope.SSOSAMLSettings, redirectURL string, domains []string, ssoID string) error {
	if m.ConfigureSAMLSettingsAssert != nil {
		m.ConfigureSAMLSettingsAssert(tenantID, settings, redirectURL, domains, ssoID)
	}
	return m.ConfigureSAMLSettingsError
}

func (m *MockSSO) ConfigureSAMLSettingsByMetadata(_ context.Context, tenantID string, settings *descope.SSOSAMLSettingsByMetadata, redirectURL string, domains []string, ssoID string) error {
	if m.ConfigureSAMLSettingsByMetadataAssert != nil {
		m.ConfigureSAMLSettingsByMetadataAssert(tenantID, settings, redirectURL, domains, ssoID)
	}
	return m.ConfigureSAMLSettingsByMetadataError
}

func (m *MockSSO) ConfigureSSORedirectURL(_ context.Context, tenantID string, samlRedirectURL *string, oauthRedirectURL *string, ssoID string) error {
	if m.ConfigureSSORedirectURLAssert != nil {
		m.ConfigureSSORedirectURLAssert(tenantID, samlRedirectURL, oauthRedirectURL, ssoID)
	}
	return m.ConfigureSSORedirectURLError
}

func (m *MockSSO) ConfigureOIDCSettings(_ context.Context, tenantID string, settings *descope.SSOOIDCSettings, domains []string, ssoID string) error {
	if m.ConfigureOIDCSettingsAssert != nil {
		m.ConfigureOIDCSettingsAssert(tenantID, settings, domains, ssoID)
	}
	return m.ConfigureOIDCSettingsError
}

func (m *MockSSO) NewSettings(_ context.Context, tenantID string, ssoID string, displayName string) (*descope.SSOTenantSettingsResponse, error) {
	if m.NewSettingsAssert != nil {
		m.NewSettingsAssert(tenantID, ssoID, displayName)
	}
	return m.NewSettingsResponse, m.NewSettingsError
}

func (m *MockSSO) DeleteSettings(_ context.Context, tenantID string, ssoID string) error {
	if m.DeleteSettingsAssert != nil {
		m.DeleteSettingsAssert(tenantID, ssoID)
	}
	return m.DeleteSettingsError
}

func (m *MockSSO) GetSettings(_ context.Context, tenantID string) (*descope.SSOSettingsResponse, error) {
	if m.GetSettingsAssert != nil {
		m.GetSettingsAssert(tenantID)
	}
	return m.GetSettingsResponse, m.GetSettingsError
}

func (m *MockSSO) ConfigureSettings(_ context.Context, tenantID, idpURL, idpCert, entityID, redirectURL string, domains []string) error {
	if m.ConfigureSettingsAssert != nil {
		m.ConfigureSettingsAssert(tenantID, idpURL, idpCert, entityID, redirectURL, domains)
	}
	return m.ConfigureSettingsError
}

func (m *MockSSO) ConfigureMetadata(_ context.Context, tenantID, idpMetadataURL, redirectURL string, domains []string) error {
	if m.ConfigureMetadataAssert != nil {
		m.ConfigureMetadataAssert(tenantID, idpMetadataURL, redirectURL, domains)
	}
	return m.ConfigureMetadataError
}

func (m *MockSSO) ConfigureMapping(_ context.Context, tenantID string, roleMappings []*descope.RoleMapping, attributeMapping *descope.AttributeMapping) error {
	if m.ConfigureMappingAssert != nil {
		m.ConfigureMappingAssert(tenantID, roleMappings, attributeMapping)
	}
	return m.ConfigureMappingError
}

// Mock Password

type MockPasswordManagement struct {
	GetSettingsAssert   func(tenantID string)
	GetSettingsResponse *descope.PasswordSettings
	GetSettingsError    error

	ConfigureSettingsAssert func(tenantID string, settings *descope.PasswordSettings)
	ConfigureSettingsError  error
}

func (m *MockPasswordManagement) GetSettings(_ context.Context, tenantID string) (*descope.PasswordSettings, error) {
	if m.GetSettingsAssert != nil {
		m.GetSettingsAssert(tenantID)
	}
	return m.GetSettingsResponse, m.GetSettingsError
}

func (m *MockPasswordManagement) ConfigureSettings(_ context.Context, tenantID string, settings *descope.PasswordSettings) error {
	if m.ConfigureSettingsAssert != nil {
		m.ConfigureSettingsAssert(tenantID, settings)
	}
	return m.ConfigureSettingsError
}

// Mock User

type MockUser struct {
	CreateAssert   func(loginID string, user *descope.UserRequest)
	CreateResponse *descope.UserResponse
	CreateError    error

	CreateTestUserAssert   func(loginID string, user *descope.UserRequest)
	CreateTestUserResponse *descope.UserResponse
	CreateTestUserError    error

	CreateBatchAssert   func(users []*descope.BatchUser)
	CreateBatchResponse *descope.UsersBatchResponse
	CreateBatchError    error

	InviteAssert   func(loginID string, user *descope.UserRequest, options *descope.InviteOptions)
	InviteResponse *descope.UserResponse
	InviteError    error

	InviteBatchAssert   func(users []*descope.BatchUser, options *descope.InviteOptions)
	InviteBatchResponse *descope.UsersBatchResponse
	InviteBatchError    error

	UpdateAssert   func(loginID string, user *descope.UserRequest)
	UpdateResponse *descope.UserResponse
	UpdateError    error

	PatchAssert   func(loginID string, user *descope.PatchUserRequest)
	PatchResponse *descope.UserResponse
	PatchError    error

	PatchBatchAssert   func(users []*descope.PatchUserBatchRequest)
	PatchBatchResponse *descope.UsersBatchResponse
	PatchBatchError    error

	DeleteAssert func(loginID string)
	DeleteError  error

	DeleteAllTestUsersAssert func()
	DeleteAllTestUsersError  error

	ImportAssert   func(source string, users, hashes []byte, dryrun bool)
	ImportResponse *descope.UserImportResponse
	ImportError    error

	LoadAssert   func(loginID string)
	LoadResponse *descope.UserResponse
	LoadError    error

	LoadUsersAssert        func(userIDs []string, includeInvalidUsers bool)
	LoadUsersResponse      []*descope.UserResponse
	LoadUsersTotalResponse int
	LoadUsersError         error

	SearchAllAssert        func(options *descope.UserSearchOptions)
	SearchAllResponse      []*descope.UserResponse
	SearchAllTotalResponse int
	SearchAllError         error

	SearchAllTestUsersAssert        func(options *descope.UserSearchOptions)
	SearchAllTestUsersResponse      []*descope.UserResponse
	SearchAllTestUsersTotalResponse int
	SearchAllTestUsersError         error

	ActivateAssert   func(loginID string)
	ActivateResponse *descope.UserResponse
	ActivateError    error

	DeactivateAssert   func(loginID string)
	DeactivateResponse *descope.UserResponse
	DeactivateError    error

	UpdateLoginIDAssert   func(loginID, newLoginID string)
	UpdateLoginIDResponse *descope.UserResponse
	UpdateLoginIDError    error

	UpdateEmailAssert   func(loginID, email string, isVerified bool)
	UpdateEmailResponse *descope.UserResponse
	UpdateEmailError    error

	UpdatePhoneAssert   func(loginID, phone string, isVerified bool)
	UpdatePhoneResponse *descope.UserResponse
	UpdatePhoneError    error

	UpdateDisplayNameAssert   func(loginID, displayName string)
	UpdateDisplayNameResponse *descope.UserResponse
	UpdateDisplayNameError    error

	UpdateUserNamesAssert   func(loginID, givenName, middleName, familyName string)
	UpdateUserNamesResponse *descope.UserResponse
	UpdateUserNamesError    error

	UpdatePictureAssert   func(loginID, picture string)
	UpdatePictureResponse *descope.UserResponse
	UpdatePictureError    error

	UpdateCustomAttributeAssert   func(loginID, key string, value any)
	UpdateCustomAttributeResponse *descope.UserResponse
	UpdateCustomAttributeError    error

	SetRoleAssert   func(loginID string, roles []string)
	SetRoleResponse *descope.UserResponse
	SetRoleError    error

	AddRoleAssert   func(loginID string, roles []string)
	AddRoleResponse *descope.UserResponse
	AddRoleError    error

	RemoveRoleAssert   func(loginID string, roles []string)
	RemoveRoleResponse *descope.UserResponse
	RemoveRoleError    error

	AddSSOAppsAssert   func(loginID string, ssoAppIDs []string)
	AddSSOAppsResponse *descope.UserResponse
	AddSSOAppsError    error

	SetSSOAppsAssert   func(loginID string, ssoAppIDs []string)
	SetSSOAppsResponse *descope.UserResponse
	SetSSOAppsError    error

	RemoveSSOAppsAssert   func(loginID string, ssoAppIDs []string)
	RemoveSSOAppsResponse *descope.UserResponse
	RemoveSSOAppsError    error

	AddTenantAssert   func(loginID, tenantID string)
	AddTenantResponse *descope.UserResponse
	AddTenantError    error

	RemoveTenantAssert   func(loginID, tenantID string)
	RemoveTenantResponse *descope.UserResponse
	RemoveTenantError    error

	SetTenantRoleAssert   func(loginID, tenantID string, roles []string)
	SetTenantRoleResponse *descope.UserResponse
	SetTenantRoleError    error

	AddTenantRoleAssert   func(loginID, tenantID string, roles []string)
	AddTenantRoleResponse *descope.UserResponse
	AddTenantRoleError    error

	RemoveTenantRoleAssert   func(loginID, tenantID string, roles []string)
	RemoveTenantRoleResponse *descope.UserResponse
	RemoveTenantRoleError    error

	SetPasswordAssert func(loginID, password string, setActive bool)
	SetPasswordError  error

	ExpirePasswordAssert func(loginID string)
	ExpirePasswordError  error

	RemoveAllPasskeysAssert func(loginID string)
	RemoveAllPasskeysError  error

	RemoveTOTPSeedAssert func(loginID string)
	RemoveTOTPSeedError  error

	ListTrustedDevicesAssert   func(loginIDsOrUserIDs []string)
	ListTrustedDevicesResponse []*descope.UserTrustedDevice
	ListTrustedDevicesError    error

	RemoveTrustedDevicesAssert func(loginIDOrUserID string, deviceIDs []string)
	RemoveTrustedDevicesError  error

	GetProviderTokenWithOptionsAssert   func(loginID, provider string, options *descope.ProviderTokenOptions)
	GetProviderTokenWithOptionsResponse *descope.ProviderTokenResponse
	GetProviderTokenWithOptionsError    error

	GetProviderTokenAssert   func(loginID, provider string)
	GetProviderTokenResponse *descope.ProviderTokenResponse
	GetProviderTokenError    error

	GenerateOTPForTestUserAssert   func(method descope.DeliveryMethod, loginID string, loginOptions *descope.LoginOptions)
	GenerateOTPForTestUserResponse string
	GenerateOTPForTestUserError    error

	GenerateMagicLinkForTestUserAssert   func(method descope.DeliveryMethod, loginID, URI string, loginOptions *descope.LoginOptions)
	GenerateMagicLinkForTestUserResponse string
	GenerateMagicLinkForTestUserError    error

	GenerateEnchantedLinkForTestUserAssert             func(loginID, URI string, loginOptions *descope.LoginOptions)
	GenerateEnchantedLinkForTestUserResponseLink       string
	GenerateEnchantedLinkForTestUserResponsePendingRef string
	GenerateEnchantedLinkForTestUserError              error

	GenerateEmbeddedLinkAssert   func(loginID string, customClaims map[string]any, timeout int64)
	GenerateEmbeddedLinkResponse string
	GenerateEmbeddedLinkError    error

	GenerateEmbeddedLinkSignUpAssert   func(loginID string, user *descope.MgmtUserRequest, signUpOptions *descope.EmbeddedLinkLoginOptions)
	GenerateEmbeddedLinkSignUpResponse string
	GenerateEmbeddedLinkSignUpError    error

	LogoutAssert func(id string, sessionTypes ...string)
	LogoutError  error

	HistoryAssert   func(userIDs []string)
	HistoryResponse []*descope.UserHistoryResponse
	HistoryError    error
}

func (m *MockUser) Create(_ context.Context, loginID string, user *descope.UserRequest) (*descope.UserResponse, error) {
	if m.CreateAssert != nil {
		m.CreateAssert(loginID, user)
	}
	return m.CreateResponse, m.CreateError
}

func (m *MockUser) CreateTestUser(_ context.Context, loginID string, user *descope.UserRequest) (*descope.UserResponse, error) {
	if m.CreateTestUserAssert != nil {
		m.CreateTestUserAssert(loginID, user)
	}
	return m.CreateTestUserResponse, m.CreateTestUserError
}

func (m *MockUser) CreateBatch(_ context.Context, users []*descope.BatchUser) (*descope.UsersBatchResponse, error) {
	if m.CreateBatchAssert != nil {
		m.CreateBatchAssert(users)
	}
	return m.CreateBatchResponse, m.CreateBatchError
}

func (m *MockUser) Invite(_ context.Context, loginID string, user *descope.UserRequest, options *descope.InviteOptions) (*descope.UserResponse, error) {
	if m.InviteAssert != nil {
		m.InviteAssert(loginID, user, options)
	}
	return m.InviteResponse, m.InviteError
}

func (m *MockUser) InviteBatch(_ context.Context, users []*descope.BatchUser, options *descope.InviteOptions) (*descope.UsersBatchResponse, error) {
	if m.InviteBatchAssert != nil {
		m.InviteBatchAssert(users, options)
	}
	return m.InviteBatchResponse, m.InviteBatchError
}

func (m *MockUser) Update(_ context.Context, loginID string, user *descope.UserRequest) (*descope.UserResponse, error) {
	if m.UpdateAssert != nil {
		m.UpdateAssert(loginID, user)
	}
	return m.UpdateResponse, m.UpdateError
}

func (m *MockUser) Patch(_ context.Context, loginID string, user *descope.PatchUserRequest) (*descope.UserResponse, error) {
	if m.PatchAssert != nil {
		m.PatchAssert(loginID, user)
	}
	return m.PatchResponse, m.PatchError
}

func (m *MockUser) PatchBatch(_ context.Context, users []*descope.PatchUserBatchRequest) (*descope.UsersBatchResponse, error) {
	if m.PatchBatchAssert != nil {
		m.PatchBatchAssert(users)
	}
	return m.PatchBatchResponse, m.PatchBatchError
}

func (m *MockUser) Delete(_ context.Context, loginID string) error {
	if m.DeleteAssert != nil {
		m.DeleteAssert(loginID)
	}
	return m.DeleteError
}

func (m *MockUser) DeleteByUserID(_ context.Context, userID string) error {
	if m.DeleteAssert != nil {
		m.DeleteAssert(userID)
	}
	return m.DeleteError
}

func (m *MockUser) DeleteAllTestUsers(_ context.Context) error {
	if m.DeleteAllTestUsersAssert != nil {
		m.DeleteAllTestUsersAssert()
	}
	return m.DeleteAllTestUsersError
}

func (m *MockUser) Import(_ context.Context, source string, users, hashes []byte, dryrun bool) (*descope.UserImportResponse, error) {
	if m.ImportAssert != nil {
		m.ImportAssert(source, users, hashes, dryrun)
	}
	return m.ImportResponse, m.ImportError
}

func (m *MockUser) Load(_ context.Context, loginID string) (*descope.UserResponse, error) {
	if m.LoadAssert != nil {
		m.LoadAssert(loginID)
	}
	return m.LoadResponse, m.LoadError
}

func (m *MockUser) LoadUsers(_ context.Context, userIDs []string, includeInvalidUsers bool) ([]*descope.UserResponse, int, error) {
	if m.LoadUsersAssert != nil {
		m.LoadUsersAssert(userIDs, includeInvalidUsers)
	}
	return m.LoadUsersResponse, m.LoadUsersTotalResponse, m.LoadUsersError
}

func (m *MockUser) LoadByUserID(_ context.Context, userID string) (*descope.UserResponse, error) {
	if m.LoadAssert != nil {
		m.LoadAssert(userID)
	}
	return m.LoadResponse, m.LoadError
}

func (m *MockUser) LogoutUser(_ context.Context, loginID string, sessionTypes ...string) error {
	if m.LogoutAssert != nil {
		m.LogoutAssert(loginID, sessionTypes...)
	}
	return m.LogoutError
}

func (m *MockUser) LogoutUserByUserID(_ context.Context, userID string, sessionTypes ...string) error {
	if m.LogoutAssert != nil {
		m.LogoutAssert(userID, sessionTypes...)
	}
	return m.LogoutError
}

func (m *MockUser) SearchAll(_ context.Context, options *descope.UserSearchOptions) ([]*descope.UserResponse, int, error) {
	if m.SearchAllAssert != nil {
		m.SearchAllAssert(options)
	}
	return m.SearchAllResponse, m.SearchAllTotalResponse, m.SearchAllError
}

func (m *MockUser) SearchAllTestUsers(_ context.Context, options *descope.UserSearchOptions) ([]*descope.UserResponse, int, error) {
	if m.SearchAllTestUsersAssert != nil {
		m.SearchAllTestUsersAssert(options)
	}
	return m.SearchAllTestUsersResponse, m.SearchAllTestUsersTotalResponse, m.SearchAllTestUsersError
}

func (m *MockUser) Activate(_ context.Context, loginID string) (*descope.UserResponse, error) {
	if m.ActivateAssert != nil {
		m.ActivateAssert(loginID)
	}
	return m.ActivateResponse, m.ActivateError
}

func (m *MockUser) Deactivate(_ context.Context, loginID string) (*descope.UserResponse, error) {
	if m.DeactivateAssert != nil {
		m.DeactivateAssert(loginID)
	}
	return m.DeactivateResponse, m.DeactivateError
}

func (m *MockUser) UpdateLoginID(_ context.Context, loginID, newLoginID string) (*descope.UserResponse, error) {
	if m.UpdateLoginIDAssert != nil {
		m.UpdateLoginIDAssert(loginID, newLoginID)
	}
	return m.UpdateLoginIDResponse, m.UpdateEmailError
}

func (m *MockUser) UpdateEmail(_ context.Context, loginID, email string, isVerified bool) (*descope.UserResponse, error) {
	if m.UpdateEmailAssert != nil {
		m.UpdateEmailAssert(loginID, email, isVerified)
	}
	return m.UpdateEmailResponse, m.UpdateEmailError
}

func (m *MockUser) UpdatePhone(_ context.Context, loginID, phone string, isVerified bool) (*descope.UserResponse, error) {
	if m.UpdatePhoneAssert != nil {
		m.UpdatePhoneAssert(loginID, phone, isVerified)
	}
	return m.UpdatePhoneResponse, m.UpdatePhoneError
}

func (m *MockUser) UpdateDisplayName(_ context.Context, loginID, displayName string) (*descope.UserResponse, error) {
	if m.UpdateDisplayNameAssert != nil {
		m.UpdateDisplayNameAssert(loginID, displayName)
	}
	return m.UpdateDisplayNameResponse, m.UpdateDisplayNameError
}

func (m *MockUser) UpdateUserNames(_ context.Context, loginID, givenName, middleName, familyName string) (*descope.UserResponse, error) {
	if m.UpdateUserNamesAssert != nil {
		m.UpdateUserNamesAssert(loginID, givenName, middleName, familyName)
	}
	return m.UpdateUserNamesResponse, m.UpdateUserNamesError
}

func (m *MockUser) UpdatePicture(_ context.Context, loginID, picture string) (*descope.UserResponse, error) {
	if m.UpdatePictureAssert != nil {
		m.UpdatePictureAssert(loginID, picture)
	}
	return m.UpdatePictureResponse, m.UpdatePictureError
}

func (m *MockUser) UpdateCustomAttribute(_ context.Context, loginID, key string, value any) (*descope.UserResponse, error) {
	if m.UpdateCustomAttributeAssert != nil {
		m.UpdateCustomAttributeAssert(loginID, key, value)
	}
	return m.UpdateCustomAttributeResponse, m.UpdateCustomAttributeError
}

func (m *MockUser) SetRoles(_ context.Context, loginID string, roles []string) (*descope.UserResponse, error) {
	if m.SetRoleAssert != nil {
		m.SetRoleAssert(loginID, roles)
	}
	return m.SetRoleResponse, m.SetRoleError
}

func (m *MockUser) AddRoles(_ context.Context, loginID string, roles []string) (*descope.UserResponse, error) {
	if m.AddRoleAssert != nil {
		m.AddRoleAssert(loginID, roles)
	}
	return m.AddRoleResponse, m.AddRoleError
}

func (m *MockUser) RemoveRoles(_ context.Context, loginID string, roles []string) (*descope.UserResponse, error) {
	if m.RemoveRoleAssert != nil {
		m.RemoveRoleAssert(loginID, roles)
	}
	return m.RemoveRoleResponse, m.RemoveRoleError
}

func (m *MockUser) AddSSOApps(_ context.Context, loginID string, ssoAppIDs []string) (*descope.UserResponse, error) {
	if m.AddSSOAppsAssert != nil {
		m.AddSSOAppsAssert(loginID, ssoAppIDs)
	}
	return m.AddSSOAppsResponse, m.AddSSOAppsError
}

func (m *MockUser) SetSSOApps(_ context.Context, loginID string, ssoAppIDs []string) (*descope.UserResponse, error) {
	if m.SetSSOAppsAssert != nil {
		m.SetSSOAppsAssert(loginID, ssoAppIDs)
	}
	return m.SetSSOAppsResponse, m.SetSSOAppsError
}

func (m *MockUser) RemoveSSOApps(_ context.Context, loginID string, ssoAppIDs []string) (*descope.UserResponse, error) {
	if m.RemoveSSOAppsAssert != nil {
		m.RemoveSSOAppsAssert(loginID, ssoAppIDs)
	}
	return m.RemoveSSOAppsResponse, m.RemoveSSOAppsError
}

func (m *MockUser) AddTenant(_ context.Context, loginID string, tenantID string) (*descope.UserResponse, error) {
	if m.AddTenantAssert != nil {
		m.AddTenantAssert(loginID, tenantID)
	}
	return m.AddTenantResponse, m.AddTenantError
}

func (m *MockUser) RemoveTenant(_ context.Context, loginID string, tenantID string) (*descope.UserResponse, error) {
	if m.RemoveTenantAssert != nil {
		m.RemoveTenantAssert(loginID, tenantID)
	}
	return m.RemoveTenantResponse, m.RemoveTenantError
}

func (m *MockUser) SetTenantRoles(_ context.Context, loginID string, tenantID string, roles []string) (*descope.UserResponse, error) {
	if m.SetTenantRoleAssert != nil {
		m.SetTenantRoleAssert(loginID, tenantID, roles)
	}
	return m.SetTenantRoleResponse, m.SetTenantRoleError
}

func (m *MockUser) AddTenantRoles(_ context.Context, loginID string, tenantID string, roles []string) (*descope.UserResponse, error) {
	if m.AddTenantRoleAssert != nil {
		m.AddTenantRoleAssert(loginID, tenantID, roles)
	}
	return m.AddTenantRoleResponse, m.AddTenantRoleError
}

func (m *MockUser) RemoveTenantRoles(_ context.Context, loginID string, tenantID string, roles []string) (*descope.UserResponse, error) {
	if m.RemoveTenantRoleAssert != nil {
		m.RemoveTenantRoleAssert(loginID, tenantID, roles)
	}
	return m.RemoveTenantRoleResponse, m.RemoveTenantRoleError
}

func (m *MockUser) SetTemporaryPassword(_ context.Context, loginID string, password string) error {
	if m.SetPasswordAssert != nil {
		m.SetPasswordAssert(loginID, password, false)
	}
	return m.SetPasswordError
}

func (m *MockUser) SetActivePassword(_ context.Context, loginID string, password string) error {
	if m.SetPasswordAssert != nil {
		m.SetPasswordAssert(loginID, password, true)
	}
	return m.SetPasswordError
}

/* Deprecated */
func (m *MockUser) SetPassword(_ context.Context, loginID string, password string) error {
	if m.SetPasswordAssert != nil {
		m.SetPasswordAssert(loginID, password, false)
	}
	return m.SetPasswordError
}

func (m *MockUser) ExpirePassword(_ context.Context, loginID string) error {
	if m.ExpirePasswordAssert != nil {
		m.ExpirePasswordAssert(loginID)
	}
	return m.ExpirePasswordError
}

func (m *MockUser) RemoveAllPasskeys(_ context.Context, loginID string) error {
	if m.RemoveAllPasskeysAssert != nil {
		m.RemoveAllPasskeysAssert(loginID)
	}
	return m.RemoveAllPasskeysError
}

func (m *MockUser) RemoveTOTPSeed(_ context.Context, loginID string) error {
	if m.RemoveTOTPSeedAssert != nil {
		m.RemoveTOTPSeedAssert(loginID)
	}
	return m.RemoveTOTPSeedError
}

func (m *MockUser) ListTrustedDevices(_ context.Context, loginIDsOrUserIDs []string) ([]*descope.UserTrustedDevice, error) {
	if m.ListTrustedDevicesAssert != nil {
		m.ListTrustedDevicesAssert(loginIDsOrUserIDs)
	}
	return m.ListTrustedDevicesResponse, m.ListTrustedDevicesError
}

func (m *MockUser) RemoveTrustedDevices(_ context.Context, loginIDOrUserID string, deviceIDs []string) error {
	if m.RemoveTrustedDevicesAssert != nil {
		m.RemoveTrustedDevicesAssert(loginIDOrUserID, deviceIDs)
	}
	return m.RemoveTrustedDevicesError
}

func (m *MockUser) GetProviderToken(_ context.Context, loginID, provider string) (*descope.ProviderTokenResponse, error) {
	if m.GetProviderTokenAssert != nil {
		m.GetProviderTokenAssert(loginID, provider)
	}
	return m.GetProviderTokenResponse, m.GetProviderTokenError
}

func (m *MockUser) GetProviderTokenWithOptions(_ context.Context, loginID, provider string, options *descope.ProviderTokenOptions) (*descope.ProviderTokenResponse, error) {
	if m.GetProviderTokenWithOptionsAssert != nil {
		m.GetProviderTokenWithOptionsAssert(loginID, provider, options)
	}
	return m.GetProviderTokenWithOptionsResponse, m.GetProviderTokenWithOptionsError
}

func (m *MockUser) GenerateOTPForTestUser(_ context.Context, method descope.DeliveryMethod, loginID string, loginOptions *descope.LoginOptions) (code string, err error) {
	if m.GenerateOTPForTestUserAssert != nil {
		m.GenerateOTPForTestUserAssert(method, loginID, loginOptions)
	}
	return m.GenerateOTPForTestUserResponse, m.GenerateOTPForTestUserError
}

func (m *MockUser) GenerateMagicLinkForTestUser(_ context.Context, method descope.DeliveryMethod, loginID, URI string, loginOptions *descope.LoginOptions) (link string, err error) {
	if m.GenerateMagicLinkForTestUserAssert != nil {
		m.GenerateMagicLinkForTestUserAssert(method, loginID, URI, loginOptions)
	}
	return m.GenerateMagicLinkForTestUserResponse, m.GenerateMagicLinkForTestUserError
}

func (m *MockUser) GenerateEnchantedLinkForTestUser(_ context.Context, loginID, URI string, loginOptions *descope.LoginOptions) (link, pendingRef string, err error) {
	if m.GenerateEnchantedLinkForTestUserAssert != nil {
		m.GenerateEnchantedLinkForTestUserAssert(loginID, URI, loginOptions)
	}
	return m.GenerateEnchantedLinkForTestUserResponseLink, m.GenerateEnchantedLinkForTestUserResponsePendingRef, m.GenerateEnchantedLinkForTestUserError
}

func (m *MockUser) GenerateEmbeddedLink(_ context.Context, loginID string, customClaims map[string]any, timeout int64) (string, error) {
	if m.GenerateEmbeddedLinkAssert != nil {
		m.GenerateEmbeddedLinkAssert(loginID, customClaims, timeout)
	}
	return m.GenerateEmbeddedLinkResponse, m.GenerateEmbeddedLinkError
}

func (m *MockUser) GenerateEmbeddedLinkSignUp(_ context.Context, loginID string, user *descope.MgmtUserRequest, signUpOptions *descope.EmbeddedLinkLoginOptions) (string, error) {
	if m.GenerateEmbeddedLinkSignUpAssert != nil {
		m.GenerateEmbeddedLinkSignUpAssert(loginID, user, signUpOptions)
	}
	return m.GenerateEmbeddedLinkSignUpResponse, m.GenerateEmbeddedLinkSignUpError
}

func (m *MockUser) History(_ context.Context, userIDs []string) ([]*descope.UserHistoryResponse, error) {
	if m.HistoryAssert != nil {
		m.HistoryAssert(userIDs)
	}
	return m.HistoryResponse, m.HistoryError
}

// Mock Access Key

type MockAccessKey struct {
	CreateAssert     func(name string, description string, expireTime int64, roles []string, tenants []*descope.AssociatedTenant, userID string, customClaims map[string]any, permittedIPs []string)
	CreateResponseFn func() (string, *descope.AccessKeyResponse)
	CreateError      error

	LoadAssert   func(id string)
	LoadResponse *descope.AccessKeyResponse
	LoadError    error

	SearchAllAssert   func(tenantIDs []string)
	SearchAllResponse []*descope.AccessKeyResponse
	SearchAllError    error

	UpdateAssert   func(id, name string, description *string, roles []string, tenants []*descope.AssociatedTenant, customClaims map[string]any, permittedIPs []string)
	UpdateResponse *descope.AccessKeyResponse
	UpdateError    error

	DeactivateAssert func(id string)
	DeactivateError  error

	ActivateAssert func(id string)
	ActivateError  error

	DeleteAssert func(id string)
	DeleteError  error
}

func (m *MockAccessKey) Create(_ context.Context, name string, description string, expireTime int64, roles []string, tenants []*descope.AssociatedTenant, userID string, customClaims map[string]any, permittedIPs []string) (string, *descope.AccessKeyResponse, error) {
	if m.CreateAssert != nil {
		m.CreateAssert(name, description, expireTime, roles, tenants, userID, customClaims, permittedIPs)
	}
	var cleartext string
	var key *descope.AccessKeyResponse
	if m.CreateResponseFn != nil {
		cleartext, key = m.CreateResponseFn()
	}
	return cleartext, key, m.CreateError
}

func (m *MockAccessKey) Load(_ context.Context, id string) (*descope.AccessKeyResponse, error) {
	if m.LoadAssert != nil {
		m.LoadAssert(id)
	}
	return m.LoadResponse, m.LoadError
}

func (m *MockAccessKey) SearchAll(_ context.Context, tenantIDs []string) ([]*descope.AccessKeyResponse, error) {
	if m.SearchAllAssert != nil {
		m.SearchAllAssert(tenantIDs)
	}
	return m.SearchAllResponse, m.SearchAllError
}

func (m *MockAccessKey) Update(_ context.Context, id, name string, description *string, roles []string, tenants []*descope.AssociatedTenant, customClaims map[string]any, permittedIPs []string) (*descope.AccessKeyResponse, error) {
	if m.UpdateAssert != nil {
		m.UpdateAssert(id, name, description, roles, tenants, customClaims, permittedIPs)
	}
	return m.UpdateResponse, m.UpdateError
}

func (m *MockAccessKey) Deactivate(_ context.Context, id string) error {
	if m.DeactivateAssert != nil {
		m.DeactivateAssert(id)
	}
	return m.DeactivateError
}

func (m *MockAccessKey) Activate(_ context.Context, id string) error {
	if m.ActivateAssert != nil {
		m.ActivateAssert(id)
	}
	return m.ActivateError
}

func (m *MockAccessKey) Delete(_ context.Context, id string) error {
	if m.DeleteAssert != nil {
		m.DeleteAssert(id)
	}
	return m.DeleteError
}

// Mock Tenant

type MockTenant struct {
	CreateAssert   func(tenantRequest *descope.TenantRequest)
	CreateResponse string
	CreateError    error

	CreateWithIDAssert func(id string, tenantRequest *descope.TenantRequest)
	CreateWithIDError  error

	UpdateAssert func(id string, tenantRequest *descope.TenantRequest)
	UpdateError  error

	DeleteAssert func(id string, cascade bool)
	DeleteError  error

	LoadAssert   func(id string)
	LoadResponse *descope.Tenant
	LoadError    error

	LoadAllResponse []*descope.Tenant
	LoadAllError    error

	SearchAllResponse []*descope.Tenant
	SearchAllError    error

	GetSettingsAssert   func(id string)
	GetSettingsResponse *descope.TenantSettings
	GetSettingsError    error

	ConfigureSettingsAssert   func(string, *descope.TenantSettings)
	ConfigureSettingsResponse *descope.TenantSettings
	ConfigureSettingsError    error

	GenerateSSOConfigurationLinkAssert   func(tenantID string, expireDuration int64, ssoID string, email string, templateID string)
	GenerateSSOConfigurationLinkResponse string
	GenerateSSOConfigurationLinkError    error

	RevokeSSOConfigurationLinkAssert func(tenantID string, ssoID string)
	RevokeSSOConfigurationLinkError  error

	UpdateDefaultRolesAssert func(tenantID string, defaultRoles []string)
	UpdateDefaultRolesError  error
}

func (m *MockTenant) Create(_ context.Context, tenantRequest *descope.TenantRequest) (id string, err error) {
	if m.CreateAssert != nil {
		m.CreateAssert(tenantRequest)
	}
	return m.CreateResponse, m.CreateError
}

func (m *MockTenant) CreateWithID(_ context.Context, id string, tenantRequest *descope.TenantRequest) error {
	if m.CreateWithIDAssert != nil {
		m.CreateWithIDAssert(id, tenantRequest)
	}
	return m.CreateWithIDError
}

func (m *MockTenant) Update(_ context.Context, id string, tenantRequest *descope.TenantRequest) error {
	if m.UpdateAssert != nil {
		m.UpdateAssert(id, tenantRequest)
	}
	return m.UpdateError
}

func (m *MockTenant) Delete(_ context.Context, id string, cascade bool) error {
	if m.DeleteAssert != nil {
		m.DeleteAssert(id, cascade)
	}
	return m.DeleteError
}

func (m *MockTenant) Load(_ context.Context, id string) (*descope.Tenant, error) {
	if m.LoadAssert != nil {
		m.LoadAssert(id)
	}
	return m.LoadResponse, m.LoadError
}

func (m *MockTenant) LoadAll(_ context.Context) ([]*descope.Tenant, error) {
	return m.LoadAllResponse, m.LoadAllError
}

func (m *MockTenant) SearchAll(_ context.Context, _ *descope.TenantSearchOptions) ([]*descope.Tenant, error) {
	return m.SearchAllResponse, m.SearchAllError
}

func (m *MockTenant) GetSettings(_ context.Context, tenantID string) (*descope.TenantSettings, error) {
	if m.GetSettingsAssert != nil {
		m.GetSettingsAssert(tenantID)
	}
	return m.GetSettingsResponse, m.GetSettingsError
}

func (m *MockTenant) ConfigureSettings(_ context.Context, tenantID string, settings *descope.TenantSettings) error {
	if m.ConfigureSettingsAssert != nil {
		m.ConfigureSettingsAssert(tenantID, settings)
	}
	return m.ConfigureSettingsError
}

func (m *MockTenant) GenerateSSOConfigurationLink(_ context.Context, tenantID string, expireDuration int64, ssoID string, email string, templateID string) (string, error) {
	if m.GenerateSSOConfigurationLinkAssert != nil {
		m.GenerateSSOConfigurationLinkAssert(tenantID, expireDuration, ssoID, email, templateID)
	}
	return m.GenerateSSOConfigurationLinkResponse, m.GenerateSSOConfigurationLinkError
}

func (m *MockTenant) RevokeSSOConfigurationLink(_ context.Context, tenantID string, ssoID string) error {
	if m.RevokeSSOConfigurationLinkAssert != nil {
		m.RevokeSSOConfigurationLinkAssert(tenantID, ssoID)
	}
	return m.RevokeSSOConfigurationLinkError
}

func (m *MockTenant) UpdateDefaultRoles(_ context.Context, tenantID string, defaultRoles []string) error {
	if m.UpdateDefaultRolesAssert != nil {
		m.UpdateDefaultRolesAssert(tenantID, defaultRoles)
	}
	return m.UpdateDefaultRolesError
}

// Mock SSOApplication

type MockSSOApplication struct {
	CreateOIDCApplicationAssert func(appRequest *descope.OIDCApplicationRequest)
	CreateSAMLApplicationAssert func(appRequest *descope.SAMLApplicationRequest)
	CreateResponse              string
	CreateError                 error

	UpdateOIDCApplicationAssert func(appRequest *descope.OIDCApplicationRequest)
	UpdateSAMLApplicationAssert func(appRequest *descope.SAMLApplicationRequest)
	UpdateError                 error

	DeleteAssert func(id string)
	DeleteError  error

	LoadAssert   func(id string)
	LoadResponse *descope.SSOApplication
	LoadError    error

	LoadAllResponse []*descope.SSOApplication
	LoadAllError    error
}

func (m *MockSSOApplication) CreateOIDCApplication(_ context.Context, appRequest *descope.OIDCApplicationRequest) (id string, err error) {
	if m.CreateOIDCApplicationAssert != nil {
		m.CreateOIDCApplicationAssert(appRequest)
	}
	return m.CreateResponse, m.CreateError
}

func (m *MockSSOApplication) CreateSAMLApplication(_ context.Context, appRequest *descope.SAMLApplicationRequest) (id string, err error) {
	if m.CreateSAMLApplicationAssert != nil {
		m.CreateSAMLApplicationAssert(appRequest)
	}
	return m.CreateResponse, m.CreateError
}

func (m *MockSSOApplication) UpdateOIDCApplication(_ context.Context, appRequest *descope.OIDCApplicationRequest) error {
	if m.UpdateOIDCApplicationAssert != nil {
		m.UpdateOIDCApplicationAssert(appRequest)
	}
	return m.UpdateError
}

func (m *MockSSOApplication) UpdateSAMLApplication(_ context.Context, appRequest *descope.SAMLApplicationRequest) error {
	if m.UpdateSAMLApplicationAssert != nil {
		m.UpdateSAMLApplicationAssert(appRequest)
	}
	return m.UpdateError
}

func (m *MockSSOApplication) Delete(_ context.Context, id string) error {
	if m.DeleteAssert != nil {
		m.DeleteAssert(id)
	}
	return m.DeleteError
}

func (m *MockSSOApplication) Load(_ context.Context, id string) (*descope.SSOApplication, error) {
	if m.LoadAssert != nil {
		m.LoadAssert(id)
	}
	return m.LoadResponse, m.LoadError
}

func (m *MockSSOApplication) LoadAll(_ context.Context) ([]*descope.SSOApplication, error) {
	return m.LoadAllResponse, m.LoadAllError
}

// Mock Permission

type MockPermission struct {
	CreateAssert func(name, description string)
	CreateError  error

	UpdateAssert func(name, newName, description string)
	UpdateError  error

	DeleteAssert func(name string)
	DeleteError  error

	LoadAllResponse []*descope.Permission
	LoadAllError    error
}

func (m *MockPermission) Create(_ context.Context, name, description string) error {
	if m.CreateAssert != nil {
		m.CreateAssert(name, description)
	}
	return m.CreateError
}

func (m *MockPermission) Update(_ context.Context, name, newName, description string) error {
	if m.UpdateAssert != nil {
		m.UpdateAssert(name, newName, description)
	}
	return m.UpdateError
}

func (m *MockPermission) Delete(_ context.Context, name string) error {
	if m.DeleteAssert != nil {
		m.DeleteAssert(name)
	}
	return m.DeleteError
}

func (m *MockPermission) LoadAll(_ context.Context) ([]*descope.Permission, error) {
	return m.LoadAllResponse, m.LoadAllError
}

// Mock Role

type MockRole struct {
	CreateAssert func(name, description string, permissionNames []string, tenantID string, defaultRole bool, private bool)
	CreateError  error

	UpdateAssert func(name, tenantID, newName, description string, permissionNames []string, defaultRole bool, private bool)
	UpdateError  error

	DeleteAssert func(name, tenantID string)
	DeleteError  error

	LoadAllResponse []*descope.Role
	LoadAllError    error

	SearchResponse []*descope.Role
	SearchError    error
}

func (m *MockRole) Create(_ context.Context, name, description string, permissionNames []string, tenantID string, defaultRole bool, private bool) error {
	if m.CreateAssert != nil {
		m.CreateAssert(name, description, permissionNames, tenantID, defaultRole, private)
	}
	return m.CreateError
}

func (m *MockRole) Update(_ context.Context, name, tenantID string, newName, description string, permissionNames []string, defaultRole bool, private bool) error {
	if m.UpdateAssert != nil {
		m.UpdateAssert(name, tenantID, newName, description, permissionNames, defaultRole, private)
	}
	return m.UpdateError
}

func (m *MockRole) Delete(_ context.Context, name, tenantID string) error {
	if m.DeleteAssert != nil {
		m.DeleteAssert(name, tenantID)
	}
	return m.DeleteError
}

func (m *MockRole) LoadAll(_ context.Context) ([]*descope.Role, error) {
	return m.LoadAllResponse, m.LoadAllError
}

func (m *MockRole) Search(_ context.Context, _ *descope.RoleSearchOptions) ([]*descope.Role, error) {
	return m.SearchResponse, m.SearchError
}

// Mock Group

type MockGroup struct {
	LoadAllGroupsAssert   func(tenantID string)
	LoadAllGroupsResponse []*descope.Group
	LoadAllGroupsError    error

	LoadAllGroupsForMembersAssert   func(tenantID string, userIDs, loginIDs []string)
	LoadAllGroupsForMembersResponse []*descope.Group
	LoadAllGroupsForMembersError    error

	LoadAllGroupMembersAssert   func(tenantID, groupID string)
	LoadAllGroupMembersResponse []*descope.Group
	LoadAllGroupMembersError    error
}

func (m *MockGroup) LoadAllGroups(_ context.Context, tenantID string) ([]*descope.Group, error) {
	if m.LoadAllGroupsAssert != nil {
		m.LoadAllGroupsAssert(tenantID)
	}
	return m.LoadAllGroupsResponse, m.LoadAllGroupsError
}

func (m *MockGroup) LoadAllGroupsForMembers(_ context.Context, tenantID string, userIDs, loginIDs []string) ([]*descope.Group, error) {
	if m.LoadAllGroupsForMembersAssert != nil {
		m.LoadAllGroupsForMembersAssert(tenantID, userIDs, loginIDs)
	}
	return m.LoadAllGroupsForMembersResponse, m.LoadAllGroupsForMembersError
}

func (m *MockGroup) LoadAllGroupMembers(_ context.Context, tenantID, groupID string) ([]*descope.Group, error) {
	if m.LoadAllGroupMembersAssert != nil {
		m.LoadAllGroupMembersAssert(tenantID, groupID)
	}
	return m.LoadAllGroupMembersResponse, m.LoadAllGroupMembersError
}

// Mock Flows

type MockFlow struct {
	ListFlowsAssert   func()
	ListFlowsResponse *descope.FlowList
	ListFlowsError    error

	DeleteFlowsAssert func(flowIDs []string)
	DeleteFlowsError  error

	ExportFlowAssert   func(flowID string)
	ExportFlowResponse map[string]any
	ExportFlowError    error

	ExportThemeAssert   func()
	ExportThemeResponse map[string]any
	ExportThemeError    error

	ImportFlowAssert func(flowID string, flow map[string]any)
	ImportFlowError  error

	ImportThemeAssert func(theme map[string]any)
	ImportThemeError  error

	RunManagementFlowAssert   func(flowID string, option *descope.MgmtFlowOptions)
	RunManagementFlowResponse map[string]any
	RunManagementFlowError    error

	RunManagementFlowAsyncAssert   func(flowID string, option *descope.MgmtFlowOptions)
	RunManagementFlowAsyncResponse string
	RunManagementFlowAsyncError    error

	GetManagementFlowAsyncResultAssert   func(executionID string)
	GetManagementFlowAsyncResultResponse map[string]any
	GetManagementFlowAsyncResultError    error
}

func (m *MockFlow) ListFlows(_ context.Context) (*descope.FlowList, error) {
	if m.ListFlowsAssert != nil {
		m.ListFlowsAssert()
	}
	return m.ListFlowsResponse, m.ListFlowsError
}

func (m *MockFlow) DeleteFlows(_ context.Context, flowIDs []string) error {
	if m.DeleteFlowsAssert != nil {
		m.DeleteFlowsAssert(flowIDs)
	}
	return m.DeleteFlowsError
}

func (m *MockFlow) ExportFlow(_ context.Context, flowID string) (map[string]any, error) {
	if m.ExportFlowAssert != nil {
		m.ExportFlowAssert(flowID)
	}
	return m.ExportFlowResponse, m.ExportFlowError
}

func (m *MockFlow) ExportTheme(_ context.Context) (map[string]any, error) {
	if m.ExportThemeAssert != nil {
		m.ExportThemeAssert()
	}
	return m.ExportThemeResponse, m.ExportThemeError
}

func (m *MockFlow) ImportFlow(_ context.Context, flowID string, flow map[string]any) error {
	if m.ImportFlowAssert != nil {
		m.ImportFlowAssert(flowID, flow)
	}
	return m.ImportFlowError
}

func (m *MockFlow) ImportTheme(_ context.Context, theme map[string]any) error {
	if m.ImportThemeAssert != nil {
		m.ImportThemeAssert(theme)
	}
	return m.ImportThemeError
}

func (m *MockFlow) RunManagementFlow(_ context.Context, flowID string, options *descope.MgmtFlowOptions) (map[string]any, error) {
	if m.RunManagementFlowAssert != nil {
		m.RunManagementFlowAssert(flowID, options)
	}
	return m.RunManagementFlowResponse, m.RunManagementFlowError
}

func (m *MockFlow) RunManagementFlowAsync(_ context.Context, flowID string, options *descope.MgmtFlowOptions) (string, error) {
	if m.RunManagementFlowAsyncAssert != nil {
		m.RunManagementFlowAsyncAssert(flowID, options)
	}
	return m.RunManagementFlowAsyncResponse, m.RunManagementFlowAsyncError
}

func (m *MockFlow) GetManagementFlowAsyncResult(_ context.Context, executionID string) (map[string]any, error) {
	if m.GetManagementFlowAsyncResultAssert != nil {
		m.GetManagementFlowAsyncResultAssert(executionID)
	}
	return m.GetManagementFlowAsyncResultResponse, m.GetManagementFlowAsyncResultError
}

// Mock Project

type MockProject struct {
	ExportSnapshotAssert   func(req *descope.ExportSnapshotRequest)
	ExportSnapshotResponse *descope.ExportSnapshotResponse
	ExportSnapshotError    error

	ImportSnapshotAssert func(req *descope.ImportSnapshotRequest)
	ImportSnapshotError  error

	ValidateSnapshotAssert   func(req *descope.ValidateSnapshotRequest)
	ValidateSnapshotError    error
	ValidateSnapshotResponse *descope.ValidateSnapshotResponse

	UpdateNameAssert func(name string)
	UpdateNameError  error

	UpdateTagsAssert func(tags []string)
	UpdateTagsError  error

	CloneAssert   func(name string, tag descope.ProjectEnvironment, tags []string)
	CloneResponse *descope.CloneProjectResponse
	CloneError    error

	DeleteAssert func()
	DeleteError  error

	ListProjectsAssert   func()
	ListProjectsResponse []*descope.Project
	ListProjectsError    error
}

func (m *MockProject) ExportSnapshot(_ context.Context, req *descope.ExportSnapshotRequest) (*descope.ExportSnapshotResponse, error) {
	if m.ExportSnapshotAssert != nil {
		m.ExportSnapshotAssert(req)
	}
	return m.ExportSnapshotResponse, m.ExportSnapshotError
}

func (m *MockProject) ImportSnapshot(_ context.Context, req *descope.ImportSnapshotRequest) error {
	if m.ImportSnapshotAssert != nil {
		m.ImportSnapshotAssert(req)
	}
	return m.ImportSnapshotError
}

func (m *MockProject) ValidateSnapshot(_ context.Context, req *descope.ValidateSnapshotRequest) (*descope.ValidateSnapshotResponse, error) {
	if m.ValidateSnapshotAssert != nil {
		m.ValidateSnapshotAssert(req)
	}
	return m.ValidateSnapshotResponse, m.ValidateSnapshotError
}

func (m *MockProject) UpdateName(_ context.Context, name string) error {
	if m.UpdateNameAssert != nil {
		m.UpdateNameAssert(name)
	}
	return m.UpdateNameError
}

func (m *MockProject) UpdateTags(_ context.Context, tags []string) error {
	if m.UpdateTagsAssert != nil {
		m.UpdateTagsAssert(tags)
	}
	return m.UpdateTagsError
}

func (m *MockProject) Clone(_ context.Context, name string, environment descope.ProjectEnvironment, tags []string) (*descope.CloneProjectResponse, error) {
	if m.CloneAssert != nil {
		m.CloneAssert(name, environment, tags)
	}
	return m.CloneResponse, m.CloneError
}

func (m *MockProject) Delete(_ context.Context) error {
	if m.DeleteAssert != nil {
		m.DeleteAssert()
	}
	return m.DeleteError
}

func (m *MockProject) ListProjects(_ context.Context) ([]*descope.Project, error) {
	if m.ListProjectsAssert != nil {
		m.ListProjectsAssert()
	}
	return m.ListProjectsResponse, m.ListProjectsError
}

// Mock Audit
type MockAudit struct {
	SearchAssert   func(*descope.AuditSearchOptions)
	SearchResponse []*descope.AuditRecord
	SearchTotal    int
	SearchError    error

	CreateEventAssert func(*descope.AuditCreateOptions)
	CreateEventError  error

	CreateAuditWebhookAssert func(*descope.AuditWebhook)
	CreateAuditWebhookError  error
}

func (m *MockAudit) Search(_ context.Context, options *descope.AuditSearchOptions) ([]*descope.AuditRecord, error) {
	if m.SearchAssert != nil {
		m.SearchAssert(options)
	}
	return m.SearchResponse, m.SearchError
}

func (m *MockAudit) SearchAll(_ context.Context, options *descope.AuditSearchOptions) ([]*descope.AuditRecord, int, error) {
	if m.SearchAssert != nil {
		m.SearchAssert(options)
	}
	return m.SearchResponse, m.SearchTotal, m.SearchError
}

func (m *MockAudit) CreateEvent(_ context.Context, options *descope.AuditCreateOptions) error {
	if m.CreateEventAssert != nil {
		m.CreateEventAssert(options)
	}
	return m.CreateEventError
}

func (m *MockAudit) CreateAuditWebhook(_ context.Context, options *descope.AuditWebhook) error {
	if m.CreateAuditWebhookAssert != nil {
		m.CreateAuditWebhookAssert(options)
	}
	return m.CreateAuditWebhookError
}

type MockAnalytics struct {
	SearchAssert   func(*descope.AnalyticsSearchOptions)
	SearchResponse []*descope.AnalyticRecord
	SearchError    error
}

func (m *MockAnalytics) Search(_ context.Context, options *descope.AnalyticsSearchOptions) ([]*descope.AnalyticRecord, error) {
	if m.SearchAssert != nil {
		m.SearchAssert(options)
	}
	return m.SearchResponse, m.SearchError
}

type MockAuthz struct {
	SaveSchemaAssert func(schema *descope.AuthzSchema, upgrade bool)
	SaveSchemaError  error

	DeleteSchemaError error

	LoadSchemaResponse *descope.AuthzSchema
	LoadSchemaError    error

	SaveNamespaceAssert func(namespace *descope.AuthzNamespace, oldName, schemaName string)
	SaveNamespaceError  error

	DeleteNamespaceAssert func(name, schemaName string)
	DeleteNamespaceError  error

	SaveRelationDefinitionAssert func(relationDefinition *descope.AuthzRelationDefinition, namespace, oldName, schemaName string)
	SaveRelationDefinitionError  error

	DeleteRelationDefinitionAssert func(name, namespace, schemaName string)
	DeleteRelationDefinitionError  error

	CreateRelationsAssert func(relations []*descope.AuthzRelation)
	CreateRelationsError  error

	DeleteRelationsAssert func(relations []*descope.AuthzRelation)
	DeleteRelationsError  error

	DeleteRelationsForResourcesAssert func(resources []string)
	DeleteRelationsForResourcesError  error

	HasRelationsAssert   func(relationQueries []*descope.AuthzRelationQuery)
	HasRelationsResponse []*descope.AuthzRelationQuery
	HasRelationsError    error

	WhoCanAccessAssert   func(resource, relationDefinition, namespace string)
	WhoCanAccessResponse []string
	WhoCanAccessError    error

	ResourceRelationsAssert   func(resource string)
	ResourceRelationsResponse []*descope.AuthzRelation
	ResourceRelationsError    error

	TargetsRelationsAssert   func(targets []string)
	TargetsRelationsResponse []*descope.AuthzRelation
	TargetsRelationsError    error

	WhatCanTargetAccessAssert   func(target string)
	WhatCanTargetAccessResponse []*descope.AuthzRelation
	WhatCanTargetAccessError    error

	WhatCanTargetAccessWithRelationAssert   func(target, relationDefinition, namespace string)
	WhatCanTargetAccessWithRelationResponse []*descope.AuthzRelation
	WhatCanTargetAccessWithRelationError    error

	GetModifiedAssert   func(since time.Time)
	GetModifiedResponse *descope.AuthzModified
	GetModifiedError    error
}

func (m *MockAuthz) SaveSchema(_ context.Context, schema *descope.AuthzSchema, upgrade bool) error {
	if m.SaveSchemaAssert != nil {
		m.SaveSchemaAssert(schema, upgrade)
	}
	return m.SaveSchemaError
}

func (m *MockAuthz) DeleteSchema(_ context.Context) error {
	return m.DeleteSchemaError
}

func (m *MockAuthz) LoadSchema(_ context.Context) (*descope.AuthzSchema, error) {
	return m.LoadSchemaResponse, m.LoadSchemaError
}

func (m *MockAuthz) SaveNamespace(_ context.Context, namespace *descope.AuthzNamespace, oldName, schemaName string) error {
	if m.SaveNamespaceAssert != nil {
		m.SaveNamespaceAssert(namespace, oldName, schemaName)
	}
	return m.SaveNamespaceError
}

func (m *MockAuthz) DeleteNamespace(_ context.Context, name, schemaName string) error {
	if m.DeleteNamespaceAssert != nil {
		m.DeleteNamespaceAssert(name, schemaName)
	}
	return m.DeleteNamespaceError
}

func (m *MockAuthz) SaveRelationDefinition(_ context.Context, relationDefinition *descope.AuthzRelationDefinition, namespace, oldName, schemaName string) error {
	if m.SaveRelationDefinitionAssert != nil {
		m.SaveRelationDefinitionAssert(relationDefinition, namespace, oldName, schemaName)
	}
	return m.SaveRelationDefinitionError
}

func (m *MockAuthz) DeleteRelationDefinition(_ context.Context, name, namespace, schemaName string) error {
	if m.DeleteRelationDefinitionAssert != nil {
		m.DeleteRelationDefinitionAssert(name, namespace, schemaName)
	}
	return m.DeleteRelationDefinitionError
}

func (m *MockAuthz) CreateRelations(_ context.Context, relations []*descope.AuthzRelation) error {
	if m.CreateRelationsAssert != nil {
		m.CreateRelationsAssert(relations)
	}
	return m.CreateRelationsError
}

func (m *MockAuthz) DeleteRelations(_ context.Context, relations []*descope.AuthzRelation) error {
	if m.DeleteRelationsAssert != nil {
		m.DeleteRelationsAssert(relations)
	}
	return m.DeleteRelationsError
}

func (m *MockAuthz) DeleteRelationsForResources(_ context.Context, resources []string) error {
	if m.DeleteRelationsForResourcesAssert != nil {
		m.DeleteRelationsForResourcesAssert(resources)
	}
	return m.DeleteRelationsForResourcesError
}

func (m *MockAuthz) HasRelations(_ context.Context, relationQueries []*descope.AuthzRelationQuery) ([]*descope.AuthzRelationQuery, error) {
	if m.HasRelationsAssert != nil {
		m.HasRelationsAssert(relationQueries)
	}
	return m.HasRelationsResponse, m.HasRelationsError
}

func (m *MockAuthz) WhoCanAccess(_ context.Context, resource, relationDefinition, namespace string) ([]string, error) {
	if m.WhoCanAccessAssert != nil {
		m.WhoCanAccessAssert(resource, relationDefinition, namespace)
	}
	return m.WhoCanAccessResponse, m.WhoCanAccessError
}

func (m *MockAuthz) ResourceRelationsWithTargetSetsFilter(ctx context.Context, resource string, _ bool) ([]*descope.AuthzRelation, error) {
	return m.ResourceRelations(ctx, resource)
}

func (m *MockAuthz) ResourceRelations(_ context.Context, resource string) ([]*descope.AuthzRelation, error) {
	if m.ResourceRelationsAssert != nil {
		m.ResourceRelationsAssert(resource)
	}
	return m.ResourceRelationsResponse, m.ResourceRelationsError
}

func (m *MockAuthz) TargetsRelationsWithTargetSetsFilter(ctx context.Context, targets []string, _ bool) ([]*descope.AuthzRelation, error) {
	return m.TargetsRelations(ctx, targets)
}

func (m *MockAuthz) TargetsRelations(_ context.Context, targets []string) ([]*descope.AuthzRelation, error) {
	if m.TargetsRelationsAssert != nil {
		m.TargetsRelationsAssert(targets)
	}
	return m.TargetsRelationsResponse, m.TargetsRelationsError
}

func (m *MockAuthz) WhatCanTargetAccess(_ context.Context, target string) ([]*descope.AuthzRelation, error) {
	if m.WhatCanTargetAccessAssert != nil {
		m.WhatCanTargetAccessAssert(target)
	}
	return m.WhatCanTargetAccessResponse, m.WhatCanTargetAccessError
}

func (m *MockAuthz) WhatCanTargetAccessWithRelation(_ context.Context, target, relationDefinition, namespace string) ([]*descope.AuthzRelation, error) {
	if m.WhatCanTargetAccessWithRelationAssert != nil {
		m.WhatCanTargetAccessWithRelationAssert(target, relationDefinition, namespace)
	}
	return m.WhatCanTargetAccessWithRelationResponse, m.WhatCanTargetAccessWithRelationError
}

func (m *MockAuthz) GetModified(_ context.Context, since time.Time) (*descope.AuthzModified, error) {
	if m.GetModifiedAssert != nil {
		m.GetModifiedAssert(since)
	}
	return m.GetModifiedResponse, m.GetModifiedError
}

type MockFGA struct {
	SaveSchemaAssert func(schema *descope.FGASchema)
	SaveSchemaError  error

	LoadSchemaResponse *descope.FGASchema
	LoadSchemaError    error

	DryRunSchemaAssert   func(schema *descope.FGASchema)
	DryRunSchemaResponse *descope.FGASchemaDryRunResponse
	DryRunSchemaError    error

	CreateRelationsAssert func(relations []*descope.FGARelation)
	CreateRelationsError  error

	DeleteRelationsAssert func(relations []*descope.FGARelation)
	DeleteRelationsError  error

	CheckAssert   func(relations []*descope.FGARelation)
	CheckResponse []*descope.FGACheck
	CheckError    error

	LoadMappableSchemaAssert   func(tenantID string, options *descope.FGAMappableResourcesOptions)
	LoadMappableSchemaResponse *descope.FGAMappableSchema
	LoadMappableSchemaError    error

	SearchMappableResourcesAssert   func(tenantID string, resourcesQueries []*descope.FGAMappableResourcesQuery, options *descope.FGAMappableResourcesOptions)
	SearchMappableResourcesResponse []*descope.FGAMappableResources
	SearchMappableResourcesError    error

	LoadResourcesDetailsAssert   func(resourceIdentifiers []*descope.ResourceIdentifier)
	LoadResourcesDetailsResponse []*descope.ResourceDetails
	LoadResourcesDetailsError    error

	SaveResourcesDetailsAssert func(resourcesDetails []*descope.ResourceDetails)
	SaveResourcesDetailsError  error
}

func (m *MockFGA) SaveSchema(_ context.Context, schema *descope.FGASchema) error {
	if m.SaveSchemaAssert != nil {
		m.SaveSchemaAssert(schema)
	}
	return m.SaveSchemaError
}

func (m *MockFGA) LoadSchema(_ context.Context) (*descope.FGASchema, error) {
	return m.LoadSchemaResponse, m.LoadSchemaError
}

func (m *MockFGA) DryRunSchema(_ context.Context, schema *descope.FGASchema) (*descope.FGASchemaDryRunResponse, error) {
	if m.DryRunSchemaAssert != nil {
		m.DryRunSchemaAssert(schema)
	}
	return m.DryRunSchemaResponse, m.DryRunSchemaError
}

func (m *MockFGA) CreateRelations(_ context.Context, relations []*descope.FGARelation) error {
	if m.CreateRelationsAssert != nil {
		m.CreateRelationsAssert(relations)
	}
	return m.CreateRelationsError
}

func (m *MockFGA) DeleteRelations(_ context.Context, relations []*descope.FGARelation) error {
	if m.DeleteRelationsAssert != nil {
		m.DeleteRelationsAssert(relations)
	}
	return m.DeleteRelationsError
}

func (m *MockFGA) Check(_ context.Context, relations []*descope.FGARelation) ([]*descope.FGACheck, error) {
	if m.CheckAssert != nil {
		m.CheckAssert(relations)
	}
	return m.CheckResponse, m.CheckError
}

func (m *MockFGA) LoadMappableSchema(_ context.Context, tenantID string, options *descope.FGAMappableResourcesOptions) (*descope.FGAMappableSchema, error) {
	if m.LoadMappableSchemaAssert != nil {
		m.LoadMappableSchemaAssert(tenantID, options)
	}
	return m.LoadMappableSchemaResponse, m.LoadMappableSchemaError
}

func (m *MockFGA) SearchMappableResources(_ context.Context, tenantID string, resourcesQueries []*descope.FGAMappableResourcesQuery, options *descope.FGAMappableResourcesOptions) ([]*descope.FGAMappableResources, error) {
	if m.SearchMappableResourcesAssert != nil {
		m.SearchMappableResourcesAssert(tenantID, resourcesQueries, options)
	}
	return m.SearchMappableResourcesResponse, m.SearchMappableResourcesError
}

// Mock LoadResourcesDetails calls
func (m *MockFGA) LoadResourcesDetails(_ context.Context, resourceIdentifiers []*descope.ResourceIdentifier) ([]*descope.ResourceDetails, error) {
	if m.LoadResourcesDetailsAssert != nil {
		m.LoadResourcesDetailsAssert(resourceIdentifiers)
	}
	return m.LoadResourcesDetailsResponse, m.LoadResourcesDetailsError
}

// Mock SaveResourcesDetails calls
func (m *MockFGA) SaveResourcesDetails(_ context.Context, resourcesDetails []*descope.ResourceDetails) error {
	if m.SaveResourcesDetailsAssert != nil {
		m.SaveResourcesDetailsAssert(resourcesDetails)
	}
	return m.SaveResourcesDetailsError
}

// Mock Third Party Application
type MockThirdPartyApplication struct {
	UpdateApplicationAssert func(*descope.ThirdPartyApplicationRequest)
	UpdateApplicationError  error

	CreateApplicationAssert         func(*descope.ThirdPartyApplicationRequest)
	CreateApplicationIDResponse     string
	CreateApplicationSecretResponse string
	CreateApplicationError          error

	DeleteApplicationAssert func(id string)
	DeleteApplicationError  error

	LoadApplicationAssert   func(id string)
	LoadApplicationResponse *descope.ThirdPartyApplication
	LoadApplicationError    error

	PatchApplicationAssert func(*descope.ThirdPartyApplicationRequest)
	PatchApplicationError  error

	GetApplicationSecretAssert   func(id string)
	GetApplicationSecretResponse string
	GetApplicationSecretError    error

	RotateApplicationSecretAssert   func(id string)
	RotateApplicationSecretResponse string
	RotateApplicationSecretError    error

	LoadAllApplicationsResponse []*descope.ThirdPartyApplication
	LoadAllApplicationsTotal    int
	LoadAllApplicationsError    error

	DeleteConsentsAssert func(*descope.ThirdPartyApplicationConsentDeleteOptions)
	DeleteConsentsError  error

	DeleteTenantConsentsAssert func(*descope.ThirdPartyApplicationTenantConsentDeleteOptions)
	DeleteTenantConsentsError  error

	SearchConsentsAssert        func(*descope.ThirdPartyApplicationConsentSearchOptions)
	SearchConsentsResponse      []*descope.ThirdPartyApplicationConsent
	SearchConsentsTotalResponse int
	SearchConsentsError         error
}

func (m *MockThirdPartyApplication) CreateApplication(_ context.Context, app *descope.ThirdPartyApplicationRequest) (string, string, error) {
	if m.CreateApplicationAssert != nil {
		m.CreateApplicationAssert(app)
	}
	return m.CreateApplicationIDResponse, m.CreateApplicationSecretResponse, m.CreateApplicationError
}

func (m *MockThirdPartyApplication) UpdateApplication(_ context.Context, app *descope.ThirdPartyApplicationRequest) error {
	if m.UpdateApplicationAssert != nil {
		m.UpdateApplicationAssert(app)
	}
	return m.UpdateApplicationError
}

func (m *MockThirdPartyApplication) DeleteApplication(_ context.Context, id string) error {
	if m.DeleteApplicationAssert != nil {
		m.DeleteApplicationAssert(id)
	}
	return m.DeleteApplicationError
}

func (m *MockThirdPartyApplication) LoadApplication(_ context.Context, id string) (*descope.ThirdPartyApplication, error) {
	if m.LoadApplicationAssert != nil {
		m.LoadApplicationAssert(id)
	}
	return m.LoadApplicationResponse, m.LoadApplicationError
}

func (m *MockThirdPartyApplication) LoadAllApplications(_ context.Context, _ *descope.ThirdPartyApplicationSearchOptions) ([]*descope.ThirdPartyApplication, int, error) {
	return m.LoadAllApplicationsResponse, m.LoadAllApplicationsTotal, m.LoadAllApplicationsError
}

func (m *MockThirdPartyApplication) PatchApplication(_ context.Context, app *descope.ThirdPartyApplicationRequest) error {
	if m.PatchApplicationAssert != nil {
		m.PatchApplicationAssert(app)
	}
	return m.PatchApplicationError
}

func (m *MockThirdPartyApplication) GetApplicationSecret(_ context.Context, id string) (string, error) {
	if m.GetApplicationSecretAssert != nil {
		m.GetApplicationSecretAssert(id)
	}
	return m.GetApplicationSecretResponse, m.GetApplicationSecretError
}

func (m *MockThirdPartyApplication) RotateApplicationSecret(_ context.Context, id string) (string, error) {
	if m.RotateApplicationSecretAssert != nil {
		m.RotateApplicationSecretAssert(id)
	}
	return m.RotateApplicationSecretResponse, m.RotateApplicationSecretError
}

func (m *MockThirdPartyApplication) DeleteConsents(_ context.Context, options *descope.ThirdPartyApplicationConsentDeleteOptions) error {
	if m.DeleteConsentsAssert != nil {
		m.DeleteConsentsAssert(options)
	}
	return m.DeleteConsentsError
}

func (m *MockThirdPartyApplication) DeleteTenantConsents(_ context.Context, options *descope.ThirdPartyApplicationTenantConsentDeleteOptions) error {
	if m.DeleteTenantConsentsAssert != nil {
		m.DeleteTenantConsentsAssert(options)
	}
	return m.DeleteTenantConsentsError
}

func (m *MockThirdPartyApplication) SearchConsents(_ context.Context, options *descope.ThirdPartyApplicationConsentSearchOptions) ([]*descope.ThirdPartyApplicationConsent, int, error) {
	if m.SearchConsentsAssert != nil {
		m.SearchConsentsAssert(options)
	}
	return m.SearchConsentsResponse, m.SearchConsentsTotalResponse, m.SearchConsentsError
}

// Mock Outbound Application
type MockOutboundApplication struct {
	UpdateApplicationAssert   func(*descope.OutboundApp, *string)
	UpdateApplicationError    error
	UpdateApplicationResponse *descope.OutboundApp

	CreateApplicationAssert   func(appRequest *descope.CreateOutboundAppRequest)
	CreateApplicationError    error
	CreateApplicationResponse *descope.OutboundApp

	DeleteApplicationAssert func(id string)
	DeleteApplicationError  error

	LoadApplicationAssert   func(id string)
	LoadApplicationResponse *descope.OutboundApp
	LoadApplicationError    error

	LoadAllApplicationsResponse []*descope.OutboundApp
	LoadAllApplicationsError    error
}

func (m *MockOutboundApplication) CreateApplication(_ context.Context, appRequest *descope.CreateOutboundAppRequest) (app *descope.OutboundApp, err error) {
	if m.CreateApplicationAssert != nil {
		m.CreateApplicationAssert(appRequest)
	}
	return m.CreateApplicationResponse, m.CreateApplicationError
}

func (m *MockOutboundApplication) UpdateApplication(_ context.Context, appRequest *descope.OutboundApp, clientSecret *string) (app *descope.OutboundApp, err error) {
	if m.UpdateApplicationAssert != nil {
		m.UpdateApplicationAssert(appRequest, clientSecret)
	}
	return m.UpdateApplicationResponse, m.UpdateApplicationError
}

func (m *MockOutboundApplication) DeleteApplication(_ context.Context, id string) error {
	if m.DeleteApplicationAssert != nil {
		m.DeleteApplicationAssert(id)
	}
	return m.DeleteApplicationError
}

func (m *MockOutboundApplication) LoadApplication(_ context.Context, id string) (*descope.OutboundApp, error) {
	if m.LoadApplicationAssert != nil {
		m.LoadApplicationAssert(id)
	}
	return m.LoadApplicationResponse, m.LoadApplicationError
}

func (m *MockOutboundApplication) LoadAllApplications(_ context.Context) ([]*descope.OutboundApp, error) {
	return m.LoadAllApplicationsResponse, m.LoadAllApplicationsError
}

// Mock ManagementKey

type MockManagementKey struct {
	CreateAssert        func(name, description string, expiresIn uint64, permittedIPs []string, reBac *descope.MgmtKeyReBac)
	CreateResponseKey   *descope.MgmtKey
	CreateResponseToken string
	CreateError         error

	UpdateAssert   func(id, name, description string, permittedIPs []string, status descope.MgmtKeyStatus)
	UpdateResponse *descope.MgmtKey
	UpdateError    error

	GetAssert   func(id string)
	GetResponse *descope.MgmtKey
	GetError    error

	DeleteAssert   func(ids []string)
	DeleteError    error
	DeleteResponse int

	SearchAssert   func(options *descope.MgmtKeySearchOptions)
	SearchResponse []*descope.MgmtKey
	SearchError    error
}

func (m *MockManagementKey) Create(_ context.Context, name, description string, expiresIn uint64, permittedIPs []string, reBac *descope.MgmtKeyReBac) (*descope.MgmtKey, string, error) {
	if m.CreateAssert != nil {
		m.CreateAssert(name, description, expiresIn, permittedIPs, reBac)
	}
	return m.CreateResponseKey, m.CreateResponseToken, m.CreateError
}

func (m *MockManagementKey) Update(_ context.Context, id, name, description string, permittedIPs []string, status descope.MgmtKeyStatus) (*descope.MgmtKey, error) {
	if m.UpdateAssert != nil {
		m.UpdateAssert(id, name, description, permittedIPs, status)
	}
	return m.UpdateResponse, m.UpdateError
}

func (m *MockManagementKey) Get(_ context.Context, id string) (*descope.MgmtKey, error) {
	if m.GetAssert != nil {
		m.GetAssert(id)
	}
	return m.GetResponse, m.GetError
}

func (m *MockManagementKey) Delete(_ context.Context, ids []string) (int, error) {
	if m.DeleteAssert != nil {
		m.DeleteAssert(ids)
	}
	return m.DeleteResponse, m.DeleteError
}

func (m *MockManagementKey) Search(_ context.Context, options *descope.MgmtKeySearchOptions) ([]*descope.MgmtKey, error) {
	if m.SearchAssert != nil {
		m.SearchAssert(options)
	}
	return m.SearchResponse, m.SearchError
}
