package mocksmgmt

import (
	"context"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/sdk"
)

type MockManagement struct {
	*MockJWT
	*MockSSO
	*MockUser
	*MockAccessKey
	*MockTenant
	*MockPermission
	*MockRole
	*MockGroup
	*MockFlow
	*MockProject
	*MockAudit
	*MockAuthz
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

func (m *MockManagement) Authz() sdk.Authz {
	return m.MockAuthz
}

// Mock JWT

type MockJWT struct {
	UpdateJWTWithCustomClaimsAssert   func(jwt string, customClaims map[string]any)
	UpdateJWTWithCustomClaimsResponse string
	UpdateJWTWithCustomClaimsError    error
}

func (m *MockJWT) UpdateJWTWithCustomClaims(ctx context.Context, jwt string, customClaims map[string]any) (string, error) {
	if m.UpdateJWTWithCustomClaimsAssert != nil {
		m.UpdateJWTWithCustomClaimsAssert(jwt, customClaims)
	}
	return m.UpdateJWTWithCustomClaimsResponse, m.UpdateJWTWithCustomClaimsError
}

// Mock SSO

type MockSSO struct {
	GetSettingsAssert   func(tenantID string)
	GetSettingsResponse *descope.SSOSettingsResponse
	GetSettingsError    error

	DeleteSettingsAssert func(tenantID string)
	DeleteSettingsError  error

	ConfigureSettingsAssert func(tenantID, idpURL, idpCert, entityID, redirectURL, domain string)
	ConfigureSettingsError  error

	ConfigureMetadataAssert func(tenantID, idpMetadataURL, redirectURL, domain string)
	ConfigureMetadataError  error

	ConfigureMappingAssert func(tenantID string, roleMappings []*descope.RoleMapping, attributeMapping *descope.AttributeMapping)
	ConfigureMappingError  error
}

func (m *MockSSO) GetSettings(ctx context.Context, tenantID string) (*descope.SSOSettingsResponse, error) {
	if m.GetSettingsAssert != nil {
		m.GetSettingsAssert(tenantID)
	}
	return m.GetSettingsResponse, m.GetSettingsError
}

func (m *MockSSO) DeleteSettings(ctx context.Context, tenantID string) error {
	if m.DeleteSettingsAssert != nil {
		m.DeleteSettingsAssert(tenantID)
	}
	return m.DeleteSettingsError
}

func (m *MockSSO) ConfigureSettings(ctx context.Context, tenantID, idpURL, idpCert, entityID, redirectURL, domain string) error {
	if m.ConfigureSettingsAssert != nil {
		m.ConfigureSettingsAssert(tenantID, idpURL, idpCert, entityID, redirectURL, domain)
	}
	return m.ConfigureSettingsError
}

func (m *MockSSO) ConfigureMetadata(ctx context.Context, tenantID, idpMetadataURL, redirectURL, domain string) error {
	if m.ConfigureMetadataAssert != nil {
		m.ConfigureMetadataAssert(tenantID, idpMetadataURL, redirectURL, domain)
	}
	return m.ConfigureMetadataError
}

func (m *MockSSO) ConfigureMapping(ctx context.Context, tenantID string, roleMappings []*descope.RoleMapping, attributeMapping *descope.AttributeMapping) error {
	if m.ConfigureMappingAssert != nil {
		m.ConfigureMappingAssert(tenantID, roleMappings, attributeMapping)
	}
	return m.ConfigureMappingError
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

	SearchAllAssert   func(options *descope.UserSearchOptions)
	SearchAllResponse []*descope.UserResponse
	SearchAllError    error

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

	SetPasswordAssert func(loginID, password string)
	SetPasswordError  error

	ExpirePasswordAssert func(loginID string)
	ExpirePasswordError  error

	GetProviderTokenAssert   func(loginID, provider string)
	GetProviderTokenResponse *descope.ProviderTokenResponse
	GetProviderTokenError    error

	GenerateOTPForTestUserAssert   func(method descope.DeliveryMethod, loginID string)
	GenerateOTPForTestUserResponse string
	GenerateOTPForTestUserError    error

	GenerateMagicLinkForTestUserAssert   func(method descope.DeliveryMethod, loginID, URI string)
	GenerateMagicLinkForTestUserResponse string
	GenerateMagicLinkForTestUserError    error

	GenerateEnchantedLinkForTestUserAssert             func(loginID, URI string)
	GenerateEnchantedLinkForTestUserResponseLink       string
	GenerateEnchantedLinkForTestUserResponsePendingRef string
	GenerateEnchantedLinkForTestUserError              error

	GenerateEmbeddedLinkAssert   func(loginID string, customClaims map[string]any)
	GenerateEmbeddedLinkResponse string
	GenerateEmbeddedLinkError    error

	LogoutAssert func(id string)
	LogoutError  error
}

func (m *MockUser) Create(ctx context.Context, loginID string, user *descope.UserRequest) (*descope.UserResponse, error) {
	if m.CreateAssert != nil {
		m.CreateAssert(loginID, user)
	}
	return m.CreateResponse, m.CreateError
}

func (m *MockUser) CreateTestUser(ctx context.Context, loginID string, user *descope.UserRequest) (*descope.UserResponse, error) {
	if m.CreateTestUserAssert != nil {
		m.CreateTestUserAssert(loginID, user)
	}
	return m.CreateTestUserResponse, m.CreateTestUserError
}

func (m *MockUser) CreateBatch(ctx context.Context, users []*descope.BatchUser) (*descope.UsersBatchResponse, error) {
	if m.CreateBatchAssert != nil {
		m.CreateBatchAssert(users)
	}
	return m.CreateBatchResponse, m.CreateBatchError
}

func (m *MockUser) Invite(ctx context.Context, loginID string, user *descope.UserRequest, options *descope.InviteOptions) (*descope.UserResponse, error) {
	if m.InviteAssert != nil {
		m.InviteAssert(loginID, user, options)
	}
	return m.InviteResponse, m.InviteError
}

func (m *MockUser) InviteBatch(ctx context.Context, users []*descope.BatchUser, options *descope.InviteOptions) (*descope.UsersBatchResponse, error) {
	if m.InviteBatchAssert != nil {
		m.InviteBatchAssert(users, options)
	}
	return m.InviteBatchResponse, m.InviteBatchError
}

func (m *MockUser) Update(ctx context.Context, loginID string, user *descope.UserRequest) (*descope.UserResponse, error) {
	if m.UpdateAssert != nil {
		m.UpdateAssert(loginID, user)
	}
	return m.UpdateResponse, m.UpdateError
}

func (m *MockUser) Delete(ctx context.Context, loginID string) error {
	if m.DeleteAssert != nil {
		m.DeleteAssert(loginID)
	}
	return m.DeleteError
}

func (m *MockUser) DeleteAllTestUsers(ctx context.Context) error {
	if m.DeleteAllTestUsersAssert != nil {
		m.DeleteAllTestUsersAssert()
	}
	return m.DeleteAllTestUsersError
}

func (m *MockUser) Import(ctx context.Context, source string, users, hashes []byte, dryrun bool) (*descope.UserImportResponse, error) {
	if m.ImportAssert != nil {
		m.ImportAssert(source, users, hashes, dryrun)
	}
	return m.ImportResponse, m.ImportError
}

func (m *MockUser) Load(ctx context.Context, loginID string) (*descope.UserResponse, error) {
	if m.LoadAssert != nil {
		m.LoadAssert(loginID)
	}
	return m.LoadResponse, m.LoadError
}

func (m *MockUser) LoadByUserID(ctx context.Context, userID string) (*descope.UserResponse, error) {
	if m.LoadAssert != nil {
		m.LoadAssert(userID)
	}
	return m.LoadResponse, m.LoadError
}

func (m *MockUser) LogoutUser(ctx context.Context, loginID string) error {
	if m.LogoutAssert != nil {
		m.LogoutAssert(loginID)
	}
	return m.LogoutError
}

func (m *MockUser) LogoutUserByUserID(ctx context.Context, userID string) error {
	if m.LogoutAssert != nil {
		m.LogoutAssert(userID)
	}
	return m.LogoutError
}

func (m *MockUser) SearchAll(ctx context.Context, options *descope.UserSearchOptions) ([]*descope.UserResponse, error) {
	if m.SearchAllAssert != nil {
		m.SearchAllAssert(options)
	}
	return m.SearchAllResponse, m.SearchAllError
}

func (m *MockUser) Activate(ctx context.Context, loginID string) (*descope.UserResponse, error) {
	if m.ActivateAssert != nil {
		m.ActivateAssert(loginID)
	}
	return m.ActivateResponse, m.ActivateError
}

func (m *MockUser) Deactivate(ctx context.Context, loginID string) (*descope.UserResponse, error) {
	if m.DeactivateAssert != nil {
		m.DeactivateAssert(loginID)
	}
	return m.DeactivateResponse, m.DeactivateError
}

func (m *MockUser) UpdateLoginID(ctx context.Context, loginID, newLoginID string) (*descope.UserResponse, error) {
	if m.UpdateLoginIDAssert != nil {
		m.UpdateLoginIDAssert(loginID, newLoginID)
	}
	return m.UpdateLoginIDResponse, m.UpdateEmailError
}

func (m *MockUser) UpdateEmail(ctx context.Context, loginID, email string, isVerified bool) (*descope.UserResponse, error) {
	if m.UpdateEmailAssert != nil {
		m.UpdateEmailAssert(loginID, email, isVerified)
	}
	return m.UpdateEmailResponse, m.UpdateEmailError
}

func (m *MockUser) UpdatePhone(ctx context.Context, loginID, phone string, isVerified bool) (*descope.UserResponse, error) {
	if m.UpdatePhoneAssert != nil {
		m.UpdatePhoneAssert(loginID, phone, isVerified)
	}
	return m.UpdatePhoneResponse, m.UpdatePhoneError
}

func (m *MockUser) UpdateDisplayName(ctx context.Context, loginID, displayName string) (*descope.UserResponse, error) {
	if m.UpdateDisplayNameAssert != nil {
		m.UpdateDisplayNameAssert(loginID, displayName)
	}
	return m.UpdateDisplayNameResponse, m.UpdateDisplayNameError
}

func (m *MockUser) UpdateUserNames(ctx context.Context, loginID, givenName, middleName, familyName string) (*descope.UserResponse, error) {
	if m.UpdateUserNamesAssert != nil {
		m.UpdateUserNamesAssert(loginID, givenName, middleName, familyName)
	}
	return m.UpdateUserNamesResponse, m.UpdateUserNamesError
}

func (m *MockUser) UpdatePicture(ctx context.Context, loginID, picture string) (*descope.UserResponse, error) {
	if m.UpdatePictureAssert != nil {
		m.UpdatePictureAssert(loginID, picture)
	}
	return m.UpdatePictureResponse, m.UpdatePictureError
}

func (m *MockUser) UpdateCustomAttribute(ctx context.Context, loginID, key string, value any) (*descope.UserResponse, error) {
	if m.UpdateCustomAttributeAssert != nil {
		m.UpdateCustomAttributeAssert(loginID, key, value)
	}
	return m.UpdateCustomAttributeResponse, m.UpdateCustomAttributeError
}

func (m *MockUser) SetRoles(ctx context.Context, loginID string, roles []string) (*descope.UserResponse, error) {
	if m.SetRoleAssert != nil {
		m.SetRoleAssert(loginID, roles)
	}
	return m.SetRoleResponse, m.SetRoleError
}

func (m *MockUser) AddRoles(ctx context.Context, loginID string, roles []string) (*descope.UserResponse, error) {
	if m.AddRoleAssert != nil {
		m.AddRoleAssert(loginID, roles)
	}
	return m.AddRoleResponse, m.AddRoleError
}

func (m *MockUser) RemoveRoles(ctx context.Context, loginID string, roles []string) (*descope.UserResponse, error) {
	if m.RemoveRoleAssert != nil {
		m.RemoveRoleAssert(loginID, roles)
	}
	return m.RemoveRoleResponse, m.RemoveRoleError
}

func (m *MockUser) AddTenant(ctx context.Context, loginID string, tenantID string) (*descope.UserResponse, error) {
	if m.AddTenantAssert != nil {
		m.AddTenantAssert(loginID, tenantID)
	}
	return m.AddTenantResponse, m.AddTenantError
}

func (m *MockUser) RemoveTenant(ctx context.Context, loginID string, tenantID string) (*descope.UserResponse, error) {
	if m.RemoveTenantAssert != nil {
		m.RemoveTenantAssert(loginID, tenantID)
	}
	return m.RemoveTenantResponse, m.RemoveTenantError
}

func (m *MockUser) SetTenantRoles(ctx context.Context, loginID string, tenantID string, roles []string) (*descope.UserResponse, error) {
	if m.SetTenantRoleAssert != nil {
		m.SetTenantRoleAssert(loginID, tenantID, roles)
	}
	return m.SetTenantRoleResponse, m.SetTenantRoleError
}

func (m *MockUser) AddTenantRoles(ctx context.Context, loginID string, tenantID string, roles []string) (*descope.UserResponse, error) {
	if m.AddTenantRoleAssert != nil {
		m.AddTenantRoleAssert(loginID, tenantID, roles)
	}
	return m.AddTenantRoleResponse, m.AddTenantRoleError
}

func (m *MockUser) RemoveTenantRoles(ctx context.Context, loginID string, tenantID string, roles []string) (*descope.UserResponse, error) {
	if m.RemoveTenantRoleAssert != nil {
		m.RemoveTenantRoleAssert(loginID, tenantID, roles)
	}
	return m.RemoveTenantRoleResponse, m.RemoveTenantRoleError
}

func (m *MockUser) SetPassword(ctx context.Context, loginID string, password string) error {
	if m.SetPasswordAssert != nil {
		m.SetPasswordAssert(loginID, password)
	}
	return m.SetPasswordError
}

func (m *MockUser) ExpirePassword(ctx context.Context, loginID string) error {
	if m.ExpirePasswordAssert != nil {
		m.ExpirePasswordAssert(loginID)
	}
	return m.ExpirePasswordError
}

func (m *MockUser) GetProviderToken(ctx context.Context, loginID, provider string) (*descope.ProviderTokenResponse, error) {
	if m.GetProviderTokenAssert != nil {
		m.GetProviderTokenAssert(loginID, provider)
	}
	return m.GetProviderTokenResponse, m.GetProviderTokenError
}

func (m *MockUser) GenerateOTPForTestUser(ctx context.Context, method descope.DeliveryMethod, loginID string) (code string, err error) {
	if m.GenerateOTPForTestUserAssert != nil {
		m.GenerateOTPForTestUserAssert(method, loginID)
	}
	return m.GenerateOTPForTestUserResponse, m.GenerateOTPForTestUserError
}

func (m *MockUser) GenerateMagicLinkForTestUser(ctx context.Context, method descope.DeliveryMethod, loginID, URI string) (link string, err error) {
	if m.GenerateMagicLinkForTestUserAssert != nil {
		m.GenerateMagicLinkForTestUserAssert(method, loginID, URI)
	}
	return m.GenerateMagicLinkForTestUserResponse, m.GenerateMagicLinkForTestUserError
}

func (m *MockUser) GenerateEnchantedLinkForTestUser(ctx context.Context, loginID, URI string) (link, pendingRef string, err error) {
	if m.GenerateEnchantedLinkForTestUserAssert != nil {
		m.GenerateEnchantedLinkForTestUserAssert(loginID, URI)
	}
	return m.GenerateEnchantedLinkForTestUserResponseLink, m.GenerateEnchantedLinkForTestUserResponsePendingRef, m.GenerateEnchantedLinkForTestUserError
}

func (m *MockUser) GenerateEmbeddedLink(ctx context.Context, loginID string, customClaims map[string]any) (string, error) {
	if m.GenerateEmbeddedLinkAssert != nil {
		m.GenerateEmbeddedLinkAssert(loginID, customClaims)
	}
	return m.GenerateEmbeddedLinkResponse, m.GenerateEmbeddedLinkError
}

// Mock Access Key

type MockAccessKey struct {
	CreateAssert     func(name string, expireTime int64, roles []string, keyTenants []*descope.AssociatedTenant)
	CreateResponseFn func() (string, *descope.AccessKeyResponse)
	CreateError      error

	LoadAssert   func(id string)
	LoadResponse *descope.AccessKeyResponse
	LoadError    error

	SearchAllAssert   func(tenantIDs []string)
	SearchAllResponse []*descope.AccessKeyResponse
	SearchAllError    error

	UpdateAssert   func(id, name string)
	UpdateResponse *descope.AccessKeyResponse
	UpdateError    error

	DeactivateAssert func(id string)
	DeactivateError  error

	ActivateAssert func(id string)
	ActivateError  error

	DeleteAssert func(id string)
	DeleteError  error
}

func (m *MockAccessKey) Create(ctx context.Context, name string, expireTime int64, roles []string, keyTenants []*descope.AssociatedTenant) (string, *descope.AccessKeyResponse, error) {
	if m.CreateAssert != nil {
		m.CreateAssert(name, expireTime, roles, keyTenants)
	}
	var cleartext string
	var key *descope.AccessKeyResponse
	if m.CreateResponseFn != nil {
		cleartext, key = m.CreateResponseFn()
	}
	return cleartext, key, m.CreateError
}

func (m *MockAccessKey) Load(ctx context.Context, id string) (*descope.AccessKeyResponse, error) {
	if m.LoadAssert != nil {
		m.LoadAssert(id)
	}
	return m.LoadResponse, m.LoadError
}

func (m *MockAccessKey) SearchAll(ctx context.Context, tenantIDs []string) ([]*descope.AccessKeyResponse, error) {
	if m.SearchAllAssert != nil {
		m.SearchAllAssert(tenantIDs)
	}
	return m.SearchAllResponse, m.SearchAllError
}

func (m *MockAccessKey) Update(ctx context.Context, id, name string) (*descope.AccessKeyResponse, error) {
	if m.UpdateAssert != nil {
		m.UpdateAssert(id, name)
	}
	return m.UpdateResponse, m.UpdateError
}

func (m *MockAccessKey) Deactivate(ctx context.Context, id string) error {
	if m.DeactivateAssert != nil {
		m.DeactivateAssert(id)
	}
	return m.DeactivateError
}

func (m *MockAccessKey) Activate(ctx context.Context, id string) error {
	if m.ActivateAssert != nil {
		m.ActivateAssert(id)
	}
	return m.ActivateError
}

func (m *MockAccessKey) Delete(ctx context.Context, id string) error {
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

	DeleteAssert func(id string)
	DeleteError  error

	LoadAssert   func(id string)
	LoadResponse *descope.Tenant
	LoadError    error

	LoadAllResponse []*descope.Tenant
	LoadAllError    error

	SearchAllResponse []*descope.Tenant
	SearchAllError    error
}

func (m *MockTenant) Create(ctx context.Context, tenantRequest *descope.TenantRequest) (id string, err error) {
	if m.CreateAssert != nil {
		m.CreateAssert(tenantRequest)
	}
	return m.CreateResponse, m.CreateError
}

func (m *MockTenant) CreateWithID(ctx context.Context, id string, tenantRequest *descope.TenantRequest) error {
	if m.CreateWithIDAssert != nil {
		m.CreateWithIDAssert(id, tenantRequest)
	}
	return m.CreateWithIDError
}

func (m *MockTenant) Update(ctx context.Context, id string, tenantRequest *descope.TenantRequest) error {
	if m.UpdateAssert != nil {
		m.UpdateAssert(id, tenantRequest)
	}
	return m.UpdateError
}

func (m *MockTenant) Delete(ctx context.Context, id string) error {
	if m.DeleteAssert != nil {
		m.DeleteAssert(id)
	}
	return m.DeleteError
}

func (m *MockTenant) Load(ctx context.Context, id string) (*descope.Tenant, error) {
	if m.LoadAssert != nil {
		m.LoadAssert(id)
	}
	return m.LoadResponse, m.LoadError
}

func (m *MockTenant) LoadAll(ctx context.Context) ([]*descope.Tenant, error) {
	return m.LoadAllResponse, m.LoadAllError
}

func (m *MockTenant) SearchAll(ctx context.Context, _ *descope.TenantSearchOptions) ([]*descope.Tenant, error) {
	return m.SearchAllResponse, m.SearchAllError
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

func (m *MockPermission) Create(ctx context.Context, name, description string) error {
	if m.CreateAssert != nil {
		m.CreateAssert(name, description)
	}
	return m.CreateError
}

func (m *MockPermission) Update(ctx context.Context, name, newName, description string) error {
	if m.UpdateAssert != nil {
		m.UpdateAssert(name, newName, description)
	}
	return m.UpdateError
}

func (m *MockPermission) Delete(ctx context.Context, name string) error {
	if m.DeleteAssert != nil {
		m.DeleteAssert(name)
	}
	return m.DeleteError
}

func (m *MockPermission) LoadAll(ctx context.Context) ([]*descope.Permission, error) {
	return m.LoadAllResponse, m.LoadAllError
}

// Mock Role

type MockRole struct {
	CreateAssert func(name, description string, permissionNames []string)
	CreateError  error

	UpdateAssert func(name, newName, description string, permissionNames []string)
	UpdateError  error

	DeleteAssert func(name string)
	DeleteError  error

	LoadAllResponse []*descope.Role
	LoadAllError    error
}

func (m *MockRole) Create(ctx context.Context, name, description string, permissionNames []string) error {
	if m.CreateAssert != nil {
		m.CreateAssert(name, description, permissionNames)
	}
	return m.CreateError
}

func (m *MockRole) Update(ctx context.Context, name, newName, description string, permissionNames []string) error {
	if m.UpdateAssert != nil {
		m.UpdateAssert(name, newName, description, permissionNames)
	}
	return m.UpdateError
}

func (m *MockRole) Delete(ctx context.Context, name string) error {
	if m.DeleteAssert != nil {
		m.DeleteAssert(name)
	}
	return m.DeleteError
}

func (m *MockRole) LoadAll(ctx context.Context) ([]*descope.Role, error) {
	return m.LoadAllResponse, m.LoadAllError
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

func (m *MockGroup) LoadAllGroups(ctx context.Context, tenantID string) ([]*descope.Group, error) {
	if m.LoadAllGroupsAssert != nil {
		m.LoadAllGroupsAssert(tenantID)
	}
	return m.LoadAllGroupsResponse, m.LoadAllGroupsError
}

func (m *MockGroup) LoadAllGroupsForMembers(ctx context.Context, tenantID string, userIDs, loginIDs []string) ([]*descope.Group, error) {
	if m.LoadAllGroupsForMembersAssert != nil {
		m.LoadAllGroupsForMembersAssert(tenantID, userIDs, loginIDs)
	}
	return m.LoadAllGroupsForMembersResponse, m.LoadAllGroupsForMembersError
}

func (m *MockGroup) LoadAllGroupMembers(ctx context.Context, tenantID, groupID string) ([]*descope.Group, error) {
	if m.LoadAllGroupMembersAssert != nil {
		m.LoadAllGroupMembersAssert(tenantID, groupID)
	}
	return m.LoadAllGroupMembersResponse, m.LoadAllGroupMembersError
}

// Mock Flows

type MockFlow struct {
	ListFlowsAssert   func()
	ListFlowsResponse *descope.FlowsResponse
	ListFlowsError    error

	ExportFlowAssert   func(flowID string)
	ExportFlowResponse *descope.FlowResponse
	ExportFlowError    error

	ExportThemeAssert   func()
	ExportThemeResponse *descope.Theme
	ExportThemeError    error

	ImportFlowAssert   func(flowID string, flow *descope.Flow, screens []*descope.Screen)
	ImportFlowResponse *descope.FlowResponse
	ImportFlowError    error

	ImportThemeAssert   func(theme *descope.Theme)
	ImportThemeResponse *descope.Theme
	ImportThemeError    error
}

func (m *MockFlow) ListFlows(ctx context.Context) (*descope.FlowsResponse, error) {
	if m.ListFlowsAssert != nil {
		m.ListFlowsAssert()
	}
	return m.ListFlowsResponse, m.ListFlowsError
}

func (m *MockFlow) ExportFlow(ctx context.Context, flowID string) (*descope.FlowResponse, error) {
	if m.ExportFlowAssert != nil {
		m.ExportFlowAssert(flowID)
	}
	return m.ExportFlowResponse, m.ExportFlowError
}

func (m *MockFlow) ExportTheme(ctx context.Context) (*descope.Theme, error) {
	if m.ExportThemeAssert != nil {
		m.ExportThemeAssert()
	}
	return m.ExportThemeResponse, m.ExportThemeError
}

func (m *MockFlow) ImportFlow(ctx context.Context, flowID string, flow *descope.Flow, screens []*descope.Screen) (*descope.FlowResponse, error) {
	if m.ImportFlowAssert != nil {
		m.ImportFlowAssert(flowID, flow, screens)
	}
	return m.ImportFlowResponse, m.ImportFlowError
}

func (m *MockFlow) ImportTheme(ctx context.Context, theme *descope.Theme) (*descope.Theme, error) {
	if m.ImportThemeAssert != nil {
		m.ImportThemeAssert(theme)
	}
	return m.ImportThemeResponse, m.ImportThemeError
}

// Mock Project

type MockProject struct {
	ExportRawResponse map[string]any
	ExportRawError    error

	ImportRawAssert func(files map[string]any)
	ImportRawError  error

	UpdateNameAssert func(name string)
	UpdateNameError  error

	CloneAssert   func(name string, tag descope.ProjectTag)
	CloneResponse *descope.NewProjectResponse
	CloneError    error

	DeleteAssert func()
	DeleteError  error
}

func (m *MockProject) ExportRaw(ctx context.Context) (map[string]any, error) {
	return m.ExportRawResponse, m.ExportRawError
}

func (m *MockProject) ImportRaw(ctx context.Context, files map[string]any) error {
	if m.ImportRawAssert != nil {
		m.ImportRawAssert(files)
	}
	return m.ExportRawError
}

func (m *MockProject) UpdateName(ctx context.Context, name string) error {
	if m.UpdateNameAssert != nil {
		m.UpdateNameAssert(name)
	}

	return m.UpdateNameError
}

func (m *MockProject) Clone(ctx context.Context, name string, tag descope.ProjectTag) (*descope.NewProjectResponse, error) {
	if m.CloneAssert != nil {
		m.CloneAssert(name, tag)
	}
	return m.CloneResponse, m.CloneError
}

func (m *MockProject) Delete(ctx context.Context) error {
	if m.DeleteAssert != nil {
		m.DeleteAssert()
	}
	return m.DeleteError
}

// Mock Audit
type MockAudit struct {
	SearchAssert   func(*descope.AuditSearchOptions)
	SearchResponse []*descope.AuditRecord
	SearchError    error
}

func (m *MockAudit) Search(ctx context.Context, options *descope.AuditSearchOptions) ([]*descope.AuditRecord, error) {
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
}

func (m *MockAuthz) SaveSchema(ctx context.Context, schema *descope.AuthzSchema, upgrade bool) error {
	if m.SaveSchemaAssert != nil {
		m.SaveSchemaAssert(schema, upgrade)
	}
	return m.SaveSchemaError
}

func (m *MockAuthz) DeleteSchema(ctx context.Context) error {
	return m.DeleteSchemaError
}

func (m *MockAuthz) LoadSchema(ctx context.Context) (*descope.AuthzSchema, error) {
	return m.LoadSchemaResponse, m.LoadSchemaError
}

func (m *MockAuthz) SaveNamespace(ctx context.Context, namespace *descope.AuthzNamespace, oldName, schemaName string) error {
	if m.SaveNamespaceAssert != nil {
		m.SaveNamespaceAssert(namespace, oldName, schemaName)
	}
	return m.SaveNamespaceError
}

func (m *MockAuthz) DeleteNamespace(ctx context.Context, name, schemaName string) error {
	if m.DeleteNamespaceAssert != nil {
		m.DeleteNamespaceAssert(name, schemaName)
	}
	return m.DeleteNamespaceError
}

func (m *MockAuthz) SaveRelationDefinition(ctx context.Context, relationDefinition *descope.AuthzRelationDefinition, namespace, oldName, schemaName string) error {
	if m.SaveRelationDefinitionAssert != nil {
		m.SaveRelationDefinitionAssert(relationDefinition, namespace, oldName, schemaName)
	}
	return m.SaveRelationDefinitionError
}

func (m *MockAuthz) DeleteRelationDefinition(ctx context.Context, name, namespace, schemaName string) error {
	if m.DeleteRelationDefinitionAssert != nil {
		m.DeleteRelationDefinitionAssert(name, namespace, schemaName)
	}
	return m.DeleteRelationDefinitionError
}

func (m *MockAuthz) CreateRelations(ctx context.Context, relations []*descope.AuthzRelation) error {
	if m.CreateRelationsAssert != nil {
		m.CreateRelationsAssert(relations)
	}
	return m.CreateRelationsError
}

func (m *MockAuthz) DeleteRelations(ctx context.Context, relations []*descope.AuthzRelation) error {
	if m.DeleteRelationsAssert != nil {
		m.DeleteRelationsAssert(relations)
	}
	return m.DeleteRelationsError
}

func (m *MockAuthz) DeleteRelationsForResources(ctx context.Context, resources []string) error {
	if m.DeleteRelationsForResourcesAssert != nil {
		m.DeleteRelationsForResourcesAssert(resources)
	}
	return m.DeleteRelationsForResourcesError
}

func (m *MockAuthz) HasRelations(ctx context.Context, relationQueries []*descope.AuthzRelationQuery) ([]*descope.AuthzRelationQuery, error) {
	if m.HasRelationsAssert != nil {
		m.HasRelationsAssert(relationQueries)
	}
	return m.HasRelationsResponse, m.HasRelationsError
}

func (m *MockAuthz) WhoCanAccess(ctx context.Context, resource, relationDefinition, namespace string) ([]string, error) {
	if m.WhoCanAccessAssert != nil {
		m.WhoCanAccessAssert(resource, relationDefinition, namespace)
	}
	return m.WhoCanAccessResponse, m.WhoCanAccessError
}

func (m *MockAuthz) ResourceRelations(ctx context.Context, resource string) ([]*descope.AuthzRelation, error) {
	if m.ResourceRelationsAssert != nil {
		m.ResourceRelationsAssert(resource)
	}
	return m.ResourceRelationsResponse, m.ResourceRelationsError
}

func (m *MockAuthz) TargetsRelations(ctx context.Context, targets []string) ([]*descope.AuthzRelation, error) {
	if m.TargetsRelationsAssert != nil {
		m.TargetsRelationsAssert(targets)
	}
	return m.TargetsRelationsResponse, m.TargetsRelationsError
}

func (m *MockAuthz) WhatCanTargetAccess(ctx context.Context, target string) ([]*descope.AuthzRelation, error) {
	if m.WhatCanTargetAccessAssert != nil {
		m.WhatCanTargetAccessAssert(target)
	}
	return m.WhatCanTargetAccessResponse, m.WhatCanTargetAccessError
}
