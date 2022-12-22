package mocksmgmt

import (
	"github.com/descope/go-sdk/descope/auth"
	"github.com/descope/go-sdk/descope/mgmt"
)

type MockManagement struct {
	*MockJWT
	*MockSSO
	*MockUser
	*MockTenant
	*MockPermission
	*MockRole
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

func (m *MockManagement) Tenant() mgmt.Tenant {
	return m.MockTenant
}

func (m *MockManagement) Permission() mgmt.Permission {
	return m.MockPermission
}

func (m *MockManagement) Role() mgmt.Role {
	return m.MockRole
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

	ConfigureMappingAssert func(tenantID string, roleMappings []mgmt.RoleMapping, attributeMapping *mgmt.AttributeMapping)
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

func (m *MockSSO) ConfigureMapping(tenantID string, roleMappings []mgmt.RoleMapping, attributeMapping *mgmt.AttributeMapping) error {
	if m.ConfigureMappingAssert != nil {
		m.ConfigureMappingAssert(tenantID, roleMappings, attributeMapping)
	}
	return m.ConfigureMappingError
}

// Mock User

type MockUser struct {
	CreateAssert func(identifier, email, phone, displayName string, roles []string, tenants []mgmt.UserTenants)
	CreateError  error

	UpdateAssert func(identifier, email, phone, displayName string, roles []string, tenants []mgmt.UserTenants)
	UpdateError  error

	DeleteAssert      func(identifier string)
	DeleteAssertError error

	LoadAssert   func(identifier string)
	LoadResponse *auth.UserResponse
	LoadError    error

	SearchAllAssert   func(tenantIDs, roleNames []string, limit int32)
	SearchAllResponse []*auth.UserResponse
	SearchAllError    error
}

func (m *MockUser) Create(identifier, email, phone, displayName string, roles []string, tenants []mgmt.UserTenants) error {
	if m.CreateAssert != nil {
		m.CreateAssert(identifier, email, phone, displayName, roles, tenants)
	}
	return m.CreateError
}

func (m *MockUser) Update(identifier, email, phone, displayName string, roles []string, tenants []mgmt.UserTenants) error {
	if m.UpdateAssert != nil {
		m.UpdateAssert(identifier, email, phone, displayName, roles, tenants)
	}
	return m.UpdateError
}

func (m *MockUser) Delete(identifier string) error {
	if m.DeleteAssert != nil {
		m.DeleteAssert(identifier)
	}
	return m.DeleteAssertError
}

func (m *MockUser) Load(identifier string) (*auth.UserResponse, error) {
	if m.LoadAssert != nil {
		m.LoadAssert(identifier)
	}
	return m.LoadResponse, m.LoadError
}

func (m *MockUser) SearchAll(tenantIDs, roleNames []string, limit int32) ([]*auth.UserResponse, error) {
	if m.SearchAllAssert != nil {
		m.SearchAllAssert(tenantIDs, roleNames, limit)
	}
	return m.SearchAllResponse, m.SearchAllError
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

	DeleteAssert      func(name string)
	DeleteAssertError error

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
	return m.DeleteAssertError
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

	DeleteAssert      func(name string)
	DeleteAssertError error

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
	return m.DeleteAssertError
}

func (m *MockRole) LoadAll() ([]*auth.Role, error) {
	return m.LoadAllResponse, m.LoadAllError
}
