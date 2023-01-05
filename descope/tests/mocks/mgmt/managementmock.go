package mocksmgmt

import (
	"github.com/descope/go-sdk/descope/auth"
	"github.com/descope/go-sdk/descope/mgmt"
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
}

func (m *MockManagement) JWT() mgmt.JWT {
	return m.MockJWT
}

func (m *MockManagement) SSO() mgmt.SSO {
	return m.MockSSO
}

func (m *MockManagement) User() mgmt.User {
	return m.MockUser
}

func (m *MockManagement) AccessKey() mgmt.AccessKey {
	return m.MockAccessKey
}

func (m *MockManagement) Tenant() mgmt.Tenant {
	return m.MockTenant
}

func (m *MockManagement) Permission() mgmt.Permission {
	return m.MockPermission
}

func (m *MockManagement) Role() mgmt.Role {
	return m.MockRole
}

func (m *MockManagement) Group() mgmt.Group {
	return m.MockGroup
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
	ConfigureSettingsAssert func(tenantID, idpURL, idpCert, entityID, redirectURL string)
	ConfigureSettingsError  error

	ConfigureMetadataAssert func(tenantID, idpMetadataURL string)
	ConfigureMetadataError  error

	ConfigureMappingAssert func(tenantID string, roleMappings []*mgmt.RoleMapping, attributeMapping *mgmt.AttributeMapping)
	ConfigureMappingError  error
}

func (m *MockSSO) ConfigureSettings(tenantID, idpURL, idpCert, entityID, redirectURL string) error {
	if m.ConfigureSettingsAssert != nil {
		m.ConfigureSettingsAssert(tenantID, idpURL, idpCert, entityID, redirectURL)
	}
	return m.ConfigureSettingsError
}

func (m *MockSSO) ConfigureMetadata(tenantID, idpMetadataURL string) error {
	if m.ConfigureMetadataAssert != nil {
		m.ConfigureMetadataAssert(tenantID, idpMetadataURL)
	}
	return m.ConfigureMetadataError
}

func (m *MockSSO) ConfigureMapping(tenantID string, roleMappings []*mgmt.RoleMapping, attributeMapping *mgmt.AttributeMapping) error {
	if m.ConfigureMappingAssert != nil {
		m.ConfigureMappingAssert(tenantID, roleMappings, attributeMapping)
	}
	return m.ConfigureMappingError
}

// Mock User

type MockUser struct {
	CreateAssert func(loginID, email, phone, displayName string, roles []string, tenants []*mgmt.AssociatedTenant)
	CreateError  error

	UpdateAssert func(loginID, email, phone, displayName string, roles []string, tenants []*mgmt.AssociatedTenant)
	UpdateError  error

	DeleteAssert func(loginID string)
	DeleteError  error

	LoadAssert   func(loginID string)
	LoadResponse *auth.UserResponse
	LoadError    error

	SearchAllAssert   func(tenantIDs, roles []string, limit int32)
	SearchAllResponse []*auth.UserResponse
	SearchAllError    error
}

func (m *MockUser) Create(loginID, email, phone, displayName string, roles []string, tenants []*mgmt.AssociatedTenant) error {
	if m.CreateAssert != nil {
		m.CreateAssert(loginID, email, phone, displayName, roles, tenants)
	}
	return m.CreateError
}

func (m *MockUser) Update(loginID, email, phone, displayName string, roles []string, tenants []*mgmt.AssociatedTenant) error {
	if m.UpdateAssert != nil {
		m.UpdateAssert(loginID, email, phone, displayName, roles, tenants)
	}
	return m.UpdateError
}

func (m *MockUser) Delete(loginID string) error {
	if m.DeleteAssert != nil {
		m.DeleteAssert(loginID)
	}
	return m.DeleteError
}

func (m *MockUser) Load(loginID string) (*auth.UserResponse, error) {
	if m.LoadAssert != nil {
		m.LoadAssert(loginID)
	}
	return m.LoadResponse, m.LoadError
}

func (m *MockUser) LoadByUserID(userID string) (*auth.UserResponse, error) {
	if m.LoadAssert != nil {
		m.LoadAssert(userID)
	}
	return m.LoadResponse, m.LoadError
}

func (m *MockUser) SearchAll(tenantIDs, roles []string, limit int32) ([]*auth.UserResponse, error) {
	if m.SearchAllAssert != nil {
		m.SearchAllAssert(tenantIDs, roles, limit)
	}
	return m.SearchAllResponse, m.SearchAllError
}

// Mock Access Key

type MockAccessKey struct {
	CreateAssert     func(name string, expireTime int64, roles []string, keyTenants []*mgmt.AssociatedTenant)
	CreateResponseFn func() (string, *auth.AccessKeyResponse)
	CreateError      error

	LoadAssert   func(id string)
	LoadResponse *auth.AccessKeyResponse
	LoadError    error

	SearchAllAssert   func(tenantIDs []string)
	SearchAllResponse []*auth.AccessKeyResponse
	SearchAllError    error

	UpdateAssert   func(id, name string)
	UpdateResponse *auth.AccessKeyResponse
	UpdateError    error

	DeactivateAssert func(id string)
	DeactivateError  error

	ActivateAssert func(id string)
	ActivateError  error

	DeleteAssert func(id string)
	DeleteError  error
}

func (m *MockAccessKey) Create(name string, expireTime int64, roles []string, keyTenants []*mgmt.AssociatedTenant) (string, *auth.AccessKeyResponse, error) {
	if m.CreateAssert != nil {
		m.CreateAssert(name, expireTime, roles, keyTenants)
	}
	var cleartext string
	var key *auth.AccessKeyResponse
	if m.CreateResponseFn != nil {
		cleartext, key = m.CreateResponseFn()
	}
	return cleartext, key, m.CreateError
}

func (m *MockAccessKey) Load(id string) (*auth.AccessKeyResponse, error) {
	if m.LoadAssert != nil {
		m.LoadAssert(id)
	}
	return m.LoadResponse, m.LoadError
}

func (m *MockAccessKey) SearchAll(tenantIDs []string) ([]*auth.AccessKeyResponse, error) {
	if m.SearchAllAssert != nil {
		m.SearchAllAssert(tenantIDs)
	}
	return m.SearchAllResponse, m.SearchAllError
}

func (m *MockAccessKey) Update(id, name string) (*auth.AccessKeyResponse, error) {
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

	LoadAllResponse []*auth.Tenant
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

func (m *MockTenant) LoadAll() ([]*auth.Tenant, error) {
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

	LoadAllResponse []*auth.Permission
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

func (m *MockPermission) LoadAll() ([]*auth.Permission, error) {
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

	LoadAllResponse []*auth.Role
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

func (m *MockRole) LoadAll() ([]*auth.Role, error) {
	return m.LoadAllResponse, m.LoadAllError
}

// Mock Group

type MockGroup struct {
	LoadAllGroupsAssert   func(tenantID string)
	LoadAllGroupsResponse []*auth.Group
	LoadAllGroupsError    error

	LoadAllGroupsForMembersAssert   func(tenantID string, userIDs, loginIDs []string)
	LoadAllGroupsForMembersResponse []*auth.Group
	LoadAllGroupsForMembersError    error

	LoadAllGroupMembersAssert   func(tenantID, groupID string)
	LoadAllGroupMembersResponse []*auth.Group
	LoadAllGroupMembersError    error
}

func (m *MockGroup) LoadAllGroups(tenantID string) ([]*auth.Group, error) {
	if m.LoadAllGroupsAssert != nil {
		m.LoadAllGroupsAssert(tenantID)
	}
	return m.LoadAllGroupsResponse, m.LoadAllGroupsError
}

func (m *MockGroup) LoadAllGroupsForMembers(tenantID string, userIDs, loginIDs []string) ([]*auth.Group, error) {
	if m.LoadAllGroupsForMembersAssert != nil {
		m.LoadAllGroupsForMembersAssert(tenantID, userIDs, loginIDs)
	}
	return m.LoadAllGroupsForMembersResponse, m.LoadAllGroupsForMembersError
}

func (m *MockGroup) LoadAllGroupMembers(tenantID, groupID string) ([]*auth.Group, error) {
	if m.LoadAllGroupMembersAssert != nil {
		m.LoadAllGroupMembersAssert(tenantID, groupID)
	}
	return m.LoadAllGroupMembersResponse, m.LoadAllGroupMembersError
}
