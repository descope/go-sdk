package mgmt

// Provides functions for managing tenants in a project.
type Tenant interface {
	// Create a new tenant with the given name.
	//
	// selfProvisioningDomains is an optional list of domains that are associated with this
	// tenant. Users authenticating from these domains will be associated with this tenant.
	//
	// The tenant name must be unique per project. The tenant ID is generated automatically
	// for the tenant.
	Create(name string, selfProvisioningDomains []string) (id string, err error)

	// Create a new tenant with the given name and ID.
	//
	// selfProvisioningDomains is an optional list of domains that are associated with this
	// tenant. Users authenticating from these domains will be associated with this tenant.
	//
	// Both the name and ID must be unique per project.
	CreateWithID(id, name string, selfProvisioningDomains []string) error

	// Update an existing tenant's name and domains.
	//
	// IMPORTANT: All parameters are required and will override whatever value is currently
	// set in the existing tenant. Use carefully.
	Update(id, name string, selfProvisioningDomains []string) error

	// Delete an existing tenant.
	//
	// IMPORTANT: This action is irreversible. Use carefully.
	Delete(id string) error
}

// Represents a tenant association for a User. The tenant ID is required to denote
// which tenant the user belongs to. Roles is an optional list of roles for the
// user in this specific tenant.
type UserTenants struct {
	TenantID string
	Roles    []string
}

// Provides functions for managing users in a project.
type User interface {
	// Create a new user.
	//
	// The identifier is required and will determine what the user will use to
	// sign in. All other fields are optional.
	//
	// The roles parameter is an optional list of the user's roles for users that
	// aren't associated with a tenant, while the tenants parameter can be used
	// to specify which tenants to associate the user with and what roles the
	// user has in each one.
	Create(identifier, email, phone, displayName string, roles []string, tenants []UserTenants) error

	// Update an existing user.
	//
	// The parameters follow the same convention as those for the Create function.
	//
	// IMPORTANT: All parameters will override whatever values are currently set
	// in the existing user. Use carefully.
	Update(identifier, email, phone, displayName string, roles []string, tenants []UserTenants) error

	// Delete an existing user.
	//
	// IMPORTANT: This action is irreversible. Use carefully.
	Delete(identifier string) error
}

// Represents a mapping between a set of groups of users and a role that will be assigned to them.
type RoleMapping struct {
	Groups []string
	Role   string
}

// Provides functions for configuring SSO for a project.
type SSO interface {
	// Configure SSO setting for a tenant manually.
	//
	// All parameters are required. The idpURL is the URL for the identity provider and idpCert
	// is the certificated provided by the identity provider.
	ConfigureSettings(tenantID string, enabled bool, idpURL, idpCert, entityID, redirectURL string) error

	// Configure SSO setting for a tenant by fetching SSO settings from an IDP metadata URL.
	ConfigureMetadata(tenantID string, enabled bool, idpMetadataURL string) error

	// Configure SSO role mapping from the IDP groups to the Descope roles.
	ConfigureRoleMapping(tenantID string, roleMappings []RoleMapping) error
}

// Provide functions for manipulating valid JWT
type JWT interface {
	// Update a valid JWT with the custom claims provided
	// The new JWT will be returned
	UpdateJWTWithCustomClaims(jwt string, customClaims map[string]any) (string, error)
}

// Provides various APIs for managing a Descope project programmatically. A management key must
// be provided in the DecopeClient configuration or by setting the DESCOPE_MANAGEMENT_KEY
// environment variable. Management keys can be generated in the Descope console.
type Management interface {
	// Provides functions for managing tenants in a project.
	Tenant() Tenant

	// Provides functions for managing users in a project.
	User() User

	// Provides functions for configuring SSO for a project.
	SSO() SSO

	// Provide functions for manipulating valid JWT
	JWT() JWT
}
