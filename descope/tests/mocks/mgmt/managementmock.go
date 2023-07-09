package mocksmgmt

import (
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
	*MockAudit
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

func (m *MockManagement) Audit() sdk.Audit {
	return m.MockAudit
}

// Mock JWT

type MockJWT struct {
	UpdateJWTWithCustomClaimsAssert   func(jwt string, customClaims map[string]any)
	UpdateJWTWithCustomClaimsResponse string
	UpdateJWTWithCustomClaimsError    error
}

func (m *MockJWT) UpdateJWTWithCustomClaims(jwt string, customClaims map[string]any) (string, error) {
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

	ConfigureMetadataAssert func(tenantID, idpMetadataURL string)
	ConfigureMetadataError  error

	ConfigureMappingAssert func(tenantID string, roleMappings []*descope.RoleMapping, attributeMapping *descope.AttributeMapping)
	ConfigureMappingError  error
}

func (m *MockSSO) GetSettings(tenantID string) (*descope.SSOSettingsResponse, error) {
	if m.GetSettingsAssert != nil {
		m.GetSettingsAssert(tenantID)
	}
	return m.GetSettingsResponse, m.GetSettingsError
}

func (m *MockSSO) DeleteSettings(tenantID string) error {
	if m.DeleteSettingsAssert != nil {
		m.DeleteSettingsAssert(tenantID)
	}
	return m.DeleteSettingsError
}

func (m *MockSSO) ConfigureSettings(tenantID, idpURL, idpCert, entityID, redirectURL, domain string) error {
	if m.ConfigureSettingsAssert != nil {
		m.ConfigureSettingsAssert(tenantID, idpURL, idpCert, entityID, redirectURL, domain)
	}
	return m.ConfigureSettingsError
}

func (m *MockSSO) ConfigureMetadata(tenantID, idpMetadataURL string) error {
	if m.ConfigureMetadataAssert != nil {
		m.ConfigureMetadataAssert(tenantID, idpMetadataURL)
	}
	return m.ConfigureMetadataError
}

func (m *MockSSO) ConfigureMapping(tenantID string, roleMappings []*descope.RoleMapping, attributeMapping *descope.AttributeMapping) error {
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

	InviteAssert   func(loginID string, user *descope.UserRequest)
	InviteResponse *descope.UserResponse
	InviteError    error

	UpdateAssert   func(loginID string, user *descope.UserRequest)
	UpdateResponse *descope.UserResponse
	UpdateError    error

	DeleteAssert func(loginID string)
	DeleteError  error

	DeleteAllTestUsersAssert func()
	DeleteAllTestUsersError  error

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

	UpdatePictureAssert   func(loginID, picture string)
	UpdatePictureResponse *descope.UserResponse
	UpdatePictureError    error

	UpdateCustomAttributeAssert   func(loginID, key string, value any)
	UpdateCustomAttributeResponse *descope.UserResponse
	UpdateCustomAttributeError    error

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
}

func (m *MockUser) Create(loginID string, user *descope.UserRequest) (*descope.UserResponse, error) {
	if m.CreateAssert != nil {
		m.CreateAssert(loginID, user)
	}
	return m.CreateResponse, m.CreateError
}

func (m *MockUser) CreateTestUser(loginID string, user *descope.UserRequest) (*descope.UserResponse, error) {
	if m.CreateTestUserAssert != nil {
		m.CreateTestUserAssert(loginID, user)
	}
	return m.CreateTestUserResponse, m.CreateTestUserError
}

func (m *MockUser) Invite(loginID string, user *descope.UserRequest) (*descope.UserResponse, error) {
	if m.InviteAssert != nil {
		m.InviteAssert(loginID, user)
	}
	return m.InviteResponse, m.InviteError
}

func (m *MockUser) Update(loginID string, user *descope.UserRequest) (*descope.UserResponse, error) {
	if m.UpdateAssert != nil {
		m.UpdateAssert(loginID, user)
	}
	return m.UpdateResponse, m.UpdateError
}

func (m *MockUser) Delete(loginID string) error {
	if m.DeleteAssert != nil {
		m.DeleteAssert(loginID)
	}
	return m.DeleteError
}

func (m *MockUser) DeleteAllTestUsers() error {
	if m.DeleteAllTestUsersAssert != nil {
		m.DeleteAllTestUsersAssert()
	}
	return m.DeleteAllTestUsersError
}

func (m *MockUser) Load(loginID string) (*descope.UserResponse, error) {
	if m.LoadAssert != nil {
		m.LoadAssert(loginID)
	}
	return m.LoadResponse, m.LoadError
}

func (m *MockUser) LoadByUserID(userID string) (*descope.UserResponse, error) {
	if m.LoadAssert != nil {
		m.LoadAssert(userID)
	}
	return m.LoadResponse, m.LoadError
}

func (m *MockUser) SearchAll(options *descope.UserSearchOptions) ([]*descope.UserResponse, error) {
	if m.SearchAllAssert != nil {
		m.SearchAllAssert(options)
	}
	return m.SearchAllResponse, m.SearchAllError
}

func (m *MockUser) Activate(loginID string) (*descope.UserResponse, error) {
	if m.ActivateAssert != nil {
		m.ActivateAssert(loginID)
	}
	return m.ActivateResponse, m.ActivateError
}

func (m *MockUser) Deactivate(loginID string) (*descope.UserResponse, error) {
	if m.DeactivateAssert != nil {
		m.DeactivateAssert(loginID)
	}
	return m.DeactivateResponse, m.DeactivateError
}

func (m *MockUser) UpdateLoginID(loginID, newLoginID string) (*descope.UserResponse, error) {
	if m.UpdateLoginIDAssert != nil {
		m.UpdateLoginIDAssert(loginID, newLoginID)
	}
	return m.UpdateLoginIDResponse, m.UpdateEmailError
}

func (m *MockUser) UpdateEmail(loginID, email string, isVerified bool) (*descope.UserResponse, error) {
	if m.UpdateEmailAssert != nil {
		m.UpdateEmailAssert(loginID, email, isVerified)
	}
	return m.UpdateEmailResponse, m.UpdateEmailError
}

func (m *MockUser) UpdatePhone(loginID, phone string, isVerified bool) (*descope.UserResponse, error) {
	if m.UpdatePhoneAssert != nil {
		m.UpdatePhoneAssert(loginID, phone, isVerified)
	}
	return m.UpdatePhoneResponse, m.UpdatePhoneError
}

func (m *MockUser) UpdateDisplayName(loginID, displayName string) (*descope.UserResponse, error) {
	if m.UpdateDisplayNameAssert != nil {
		m.UpdateDisplayNameAssert(loginID, displayName)
	}
	return m.UpdateDisplayNameResponse, m.UpdateDisplayNameError
}

func (m *MockUser) UpdatePicture(loginID, picture string) (*descope.UserResponse, error) {
	if m.UpdatePictureAssert != nil {
		m.UpdatePictureAssert(loginID, picture)
	}
	return m.UpdatePictureResponse, m.UpdatePictureError
}

func (m *MockUser) UpdateCustomAttribute(loginID, key string, value any) (*descope.UserResponse, error) {
	if m.UpdateCustomAttributeAssert != nil {
		m.UpdateCustomAttributeAssert(loginID, key, value)
	}
	return m.UpdateCustomAttributeResponse, m.UpdateCustomAttributeError
}

func (m *MockUser) AddRoles(loginID string, roles []string) (*descope.UserResponse, error) {
	if m.AddRoleAssert != nil {
		m.AddRoleAssert(loginID, roles)
	}
	return m.AddRoleResponse, m.AddRoleError
}

func (m *MockUser) RemoveRoles(loginID string, roles []string) (*descope.UserResponse, error) {
	if m.RemoveRoleAssert != nil {
		m.RemoveRoleAssert(loginID, roles)
	}
	return m.RemoveRoleResponse, m.RemoveRoleError
}

func (m *MockUser) AddTenant(loginID string, tenantID string) (*descope.UserResponse, error) {
	if m.AddTenantAssert != nil {
		m.AddTenantAssert(loginID, tenantID)
	}
	return m.AddTenantResponse, m.AddTenantError
}

func (m *MockUser) RemoveTenant(loginID string, tenantID string) (*descope.UserResponse, error) {
	if m.RemoveTenantAssert != nil {
		m.RemoveTenantAssert(loginID, tenantID)
	}
	return m.RemoveTenantResponse, m.RemoveTenantError
}

func (m *MockUser) AddTenantRoles(loginID string, tenantID string, roles []string) (*descope.UserResponse, error) {
	if m.AddTenantRoleAssert != nil {
		m.AddTenantRoleAssert(loginID, tenantID, roles)
	}
	return m.AddTenantRoleResponse, m.AddTenantRoleError
}

func (m *MockUser) RemoveTenantRoles(loginID string, tenantID string, roles []string) (*descope.UserResponse, error) {
	if m.RemoveTenantRoleAssert != nil {
		m.RemoveTenantRoleAssert(loginID, tenantID, roles)
	}
	return m.RemoveTenantRoleResponse, m.RemoveTenantRoleError
}

func (m *MockUser) SetPassword(loginID string, password string) error {
	if m.SetPasswordAssert != nil {
		m.SetPasswordAssert(loginID, password)
	}
	return m.SetPasswordError
}

func (m *MockUser) ExpirePassword(loginID string) error {
	if m.ExpirePasswordAssert != nil {
		m.ExpirePasswordAssert(loginID)
	}
	return m.ExpirePasswordError
}

func (m *MockUser) GetProviderToken(loginID, provider string) (*descope.ProviderTokenResponse, error) {
	if m.GetProviderTokenAssert != nil {
		m.GetProviderTokenAssert(loginID, provider)
	}
	return m.GetProviderTokenResponse, m.GetProviderTokenError
}

func (m *MockUser) GenerateOTPForTestUser(method descope.DeliveryMethod, loginID string) (code string, err error) {
	if m.GenerateOTPForTestUserAssert != nil {
		m.GenerateOTPForTestUserAssert(method, loginID)
	}
	return m.GenerateOTPForTestUserResponse, m.GenerateOTPForTestUserError
}

func (m *MockUser) GenerateMagicLinkForTestUser(method descope.DeliveryMethod, loginID, URI string) (link string, err error) {
	if m.GenerateMagicLinkForTestUserAssert != nil {
		m.GenerateMagicLinkForTestUserAssert(method, loginID, URI)
	}
	return m.GenerateMagicLinkForTestUserResponse, m.GenerateMagicLinkForTestUserError
}

func (m *MockUser) GenerateEnchantedLinkForTestUser(loginID, URI string) (link, pendingRef string, err error) {
	if m.GenerateEnchantedLinkForTestUserAssert != nil {
		m.GenerateEnchantedLinkForTestUserAssert(loginID, URI)
	}
	return m.GenerateEnchantedLinkForTestUserResponseLink, m.GenerateEnchantedLinkForTestUserResponsePendingRef, m.GenerateEnchantedLinkForTestUserError
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

func (m *MockAccessKey) Create(name string, expireTime int64, roles []string, keyTenants []*descope.AssociatedTenant) (string, *descope.AccessKeyResponse, error) {
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

func (m *MockAccessKey) Load(id string) (*descope.AccessKeyResponse, error) {
	if m.LoadAssert != nil {
		m.LoadAssert(id)
	}
	return m.LoadResponse, m.LoadError
}

func (m *MockAccessKey) SearchAll(tenantIDs []string) ([]*descope.AccessKeyResponse, error) {
	if m.SearchAllAssert != nil {
		m.SearchAllAssert(tenantIDs)
	}
	return m.SearchAllResponse, m.SearchAllError
}

func (m *MockAccessKey) Update(id, name string) (*descope.AccessKeyResponse, error) {
	if m.UpdateAssert != nil {
		m.UpdateAssert(id, name)
	}
	return m.UpdateResponse, m.UpdateError
}

func (m *MockAccessKey) Deactivate(id string) error {
	if m.DeactivateAssert != nil {
		m.DeactivateAssert(id)
	}
	return m.DeactivateError
}

func (m *MockAccessKey) Activate(id string) error {
	if m.ActivateAssert != nil {
		m.ActivateAssert(id)
	}
	return m.ActivateError
}

func (m *MockAccessKey) Delete(id string) error {
	if m.DeleteAssert != nil {
		m.DeleteAssert(id)
	}
	return m.DeleteError
}

// Mock Tenant

type MockTenant struct {
	CreateAssert   func(name string, selfProvisioningDomains []string)
	CreateResponse string
	CreateError    error

	CreateWithIDAssert func(id, name string, selfProvisioningDomains []string)
	CreateWithIDError  error

	UpdateAssert func(id, name string, selfProvisioningDomains []string)
	UpdateError  error

	DeleteAssert func(id string)
	DeleteError  error

	LoadAssert   func(id string)
	LoadResponse *descope.Tenant
	LoadError    error

	LoadAllResponse []*descope.Tenant
	LoadAllError    error
}

func (m *MockTenant) Create(name string, selfProvisioningDomains []string) (id string, err error) {
	if m.CreateAssert != nil {
		m.CreateAssert(name, selfProvisioningDomains)
	}
	return m.CreateResponse, m.CreateError
}

func (m *MockTenant) CreateWithID(id, name string, selfProvisioningDomains []string) error {
	if m.CreateWithIDAssert != nil {
		m.CreateWithIDAssert(id, name, selfProvisioningDomains)
	}
	return m.CreateWithIDError
}

func (m *MockTenant) Update(id, name string, selfProvisioningDomains []string) error {
	if m.UpdateAssert != nil {
		m.UpdateAssert(id, name, selfProvisioningDomains)
	}
	return m.UpdateError
}

func (m *MockTenant) Delete(id string) error {
	if m.DeleteAssert != nil {
		m.DeleteAssert(id)
	}
	return m.DeleteError
}

func (m *MockTenant) Load(id string) (*descope.Tenant, error) {
	if m.LoadAssert != nil {
		m.LoadAssert(id)
	}
	return m.LoadResponse, m.LoadError
}

func (m *MockTenant) LoadAll() ([]*descope.Tenant, error) {
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

func (m *MockPermission) Create(name, description string) error {
	if m.CreateAssert != nil {
		m.CreateAssert(name, description)
	}
	return m.CreateError
}

func (m *MockPermission) Update(name, newName, description string) error {
	if m.UpdateAssert != nil {
		m.UpdateAssert(name, newName, description)
	}
	return m.UpdateError
}

func (m *MockPermission) Delete(name string) error {
	if m.DeleteAssert != nil {
		m.DeleteAssert(name)
	}
	return m.DeleteError
}

func (m *MockPermission) LoadAll() ([]*descope.Permission, error) {
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

func (m *MockRole) Create(name, description string, permissionNames []string) error {
	if m.CreateAssert != nil {
		m.CreateAssert(name, description, permissionNames)
	}
	return m.CreateError
}

func (m *MockRole) Update(name, newName, description string, permissionNames []string) error {
	if m.UpdateAssert != nil {
		m.UpdateAssert(name, newName, description, permissionNames)
	}
	return m.UpdateError
}

func (m *MockRole) Delete(name string) error {
	if m.DeleteAssert != nil {
		m.DeleteAssert(name)
	}
	return m.DeleteError
}

func (m *MockRole) LoadAll() ([]*descope.Role, error) {
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

func (m *MockGroup) LoadAllGroups(tenantID string) ([]*descope.Group, error) {
	if m.LoadAllGroupsAssert != nil {
		m.LoadAllGroupsAssert(tenantID)
	}
	return m.LoadAllGroupsResponse, m.LoadAllGroupsError
}

func (m *MockGroup) LoadAllGroupsForMembers(tenantID string, userIDs, loginIDs []string) ([]*descope.Group, error) {
	if m.LoadAllGroupsForMembersAssert != nil {
		m.LoadAllGroupsForMembersAssert(tenantID, userIDs, loginIDs)
	}
	return m.LoadAllGroupsForMembersResponse, m.LoadAllGroupsForMembersError
}

func (m *MockGroup) LoadAllGroupMembers(tenantID, groupID string) ([]*descope.Group, error) {
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

func (m *MockFlow) ListFlows() (*descope.FlowsResponse, error) {
	if m.ListFlowsAssert != nil {
		m.ListFlowsAssert()
	}
	return m.ListFlowsResponse, m.ListFlowsError
}

func (m *MockFlow) ExportFlow(flowID string) (*descope.FlowResponse, error) {
	if m.ExportFlowAssert != nil {
		m.ExportFlowAssert(flowID)
	}
	return m.ExportFlowResponse, m.ExportFlowError
}

func (m *MockFlow) ExportTheme() (*descope.Theme, error) {
	if m.ExportThemeAssert != nil {
		m.ExportThemeAssert()
	}
	return m.ExportThemeResponse, m.ExportThemeError
}

func (m *MockFlow) ImportFlow(flowID string, flow *descope.Flow, screens []*descope.Screen) (*descope.FlowResponse, error) {
	if m.ImportFlowAssert != nil {
		m.ImportFlowAssert(flowID, flow, screens)
	}
	return m.ImportFlowResponse, m.ImportFlowError
}

func (m *MockFlow) ImportTheme(theme *descope.Theme) (*descope.Theme, error) {
	if m.ImportThemeAssert != nil {
		m.ImportThemeAssert(theme)
	}
	return m.ImportThemeResponse, m.ImportThemeError
}

// Mock Audit
type MockAudit struct {
	SearchAssert   func(*descope.AuditSearchOptions)
	SearchResponse []*descope.AuditRecord
	SearchError    error
}

func (m *MockAudit) Search(options *descope.AuditSearchOptions) ([]*descope.AuditRecord, error) {
	if m.SearchAssert != nil {
		m.SearchAssert(options)
	}
	return m.SearchResponse, m.SearchError
}
