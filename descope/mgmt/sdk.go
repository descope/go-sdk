package mgmt

import "github.com/descope/go-sdk/descope/auth"

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

	// Load all project tenants
	LoadAll() ([]*auth.Tenant, error)
}

// Represents a tenant association for a User or an Access Key. The tenant ID is required
// to denote which tenant the user / access key belongs to. Roles is an optional list of
// roles for the user / access key in this specific tenant.
type AssociatedTenant struct {
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
	Create(identifier, email, phone, displayName string, roles []string, tenants []*AssociatedTenant) error

	// Update an existing user.
	//
	// The parameters follow the same convention as those for the Create function.
	//
	// IMPORTANT: All parameters will override whatever values are currently set
	// in the existing user. Use carefully.
	Update(identifier, email, phone, displayName string, roles []string, tenants []*AssociatedTenant) error

	// Delete an existing user.
	//
	// IMPORTANT: This action is irreversible. Use carefully.
	Delete(identifier string) error

	// Load an existing user.
	//
	// The identifier is required and the user will be fetched according to it.
	Load(identifier string) (*auth.UserResponse, error)

	// Load an existing user by JWT subject. The JWT subject can be found
	// on the user's JWT.
	//
	// The jwtSubject is required and the user will be fetched according to it.
	LoadByJWTSubject(jwtSubject string) (*auth.UserResponse, error)

	// Search all users according to given filters
	//
	// The tenantIDs parameter is an optional array of tenant IDs to filter by.
	//
	// The roles parameter is an optional array of role names to filter by.
	//
	// The limit parameter limits the number of returned users. Leave at 0 to return the
	// default amount.
	SearchAll(tenantIDs, roles []string, limit int32) ([]*auth.UserResponse, error)
}

// Provides functions for managing access keys in a project.
type AccessKey interface {
	// Create a new access key.
	// IMPORTANT: The access key cleartext will be returned only when first created.
	// 			  Make sure to save it in a secure manner.
	//
	// The name parameter is required. It doesn't have to be unique.
	//
	// The expireTime parameter is required, and it should contain when the key should expire,
	// or 0 to make it indefinite.
	//
	// The roles parameter is an optional list of the access key's roles for access keys that
	// aren't associated with a tenant, while the keyTenants parameter can be used
	// to specify which tenants to associate the access key with and what roles the
	// access key has in each one.
	Create(name string, expireTime int64, roles []string, keyTenants []*AssociatedTenant) (string, *auth.AccessKeyResponse, error)

	// Load an existing access key.
	//
	// The id parameter is required and the access key will be fetched according to it.
	Load(id string) (*auth.AccessKeyResponse, error)

	// Search all access keys according to given filters
	//
	// The tenantIDs parameter is an optional array of tenant IDs to filter by.
	SearchAll(tenantIDs []string) ([]*auth.AccessKeyResponse, error)

	// Update an existing access key.
	//
	// The parameters follow the same convention as those for the Create function.
	// Only the name is settable for the time being.
	//
	// IMPORTANT: All parameters will override whatever values are currently set
	// in the existing access key. Use carefully.
	Update(id, name string) (*auth.AccessKeyResponse, error)

	// Deactivate an existing access key.
	//
	// IMPORTANT: This deactivated key will not be usable from this stage. It will, however,
	// persist, and can be activated again if needed.
	Deactivate(id string) error

	// Activate an existing access key.
	//
	// IMPORTANT: Only deactivated keys can be activated again, and become usable once more. New access keys
	// are active by default.
	Activate(id string) error

	// Delete an existing access key.
	//
	// IMPORTANT: This action is irreversible. Use carefully.
	Delete(id string) error
}

// Represents a mapping between a set of groups of users and a role that will be assigned to them.
type RoleMapping struct {
	Groups []string
	Role   string
}

// Represents a mapping between Descope and IDP user attributes
type AttributeMapping struct {
	Name        string `json:"name,omitempty"`
	Email       string `json:"email,omitempty"`
	PhoneNumber string `json:"phoneNumber,omitempty"`
	Group       string `json:"group,omitempty"`
}

// Provides functions for configuring SSO for a project.
type SSO interface {
	// Configure SSO setting for a tenant manually.
	//
	// All parameters are required. The idpURL is the URL for the identity provider and idpCert
	// is the certificated provided by the identity provider.
	ConfigureSettings(tenantID, idpURL, idpCert, entityID, redirectURL string) error

	// Configure SSO setting for a tenant by fetching SSO settings from an IDP metadata URL.
	ConfigureMetadata(tenantID, idpMetadataURL string) error

	// Configure SSO IDP mapping including groups to the Descope roles and user attributes.
	ConfigureMapping(tenantID string, roleMappings []*RoleMapping, attributeMapping *AttributeMapping) error
}

// Provide functions for manipulating valid JWT
type JWT interface {
	// Update a valid JWT with the custom claims provided
	// The new JWT will be returned
	UpdateJWTWithCustomClaims(jwt string, customClaims map[string]any) (string, error)
}

// Provides functions for managing permissions in a project.
type Permission interface {
	// Create a new permission.
	//
	// The name is required to uniquely identify a permission.
	//
	// The description parameter is an optional description to briefly explain
	// what this permission allows.
	Create(name, description string) error

	// Update an existing permission.
	//
	// The parameters follow the same convention as those for the Create function, with
	// the distinction where `name` identifies the permission and `newName` holds the updated
	// name value.
	//
	// IMPORTANT: All parameters will override whatever values are currently set
	// in the existing permission. Use carefully.
	Update(name, newName, description string) error

	// Delete an existing permission.
	//
	// IMPORTANT: This action is irreversible. Use carefully.
	Delete(name string) error

	// Load all permissions.
	LoadAll() ([]*auth.Permission, error)
}

// Provides functions for managing roles in a project.
type Role interface {
	// Create a new role.
	//
	// The name is required to uniquely identify a role.
	//
	// The description parameter is an optional description to briefly explain
	// what this role allows.
	// The permissionNames parameter denotes which permissions are included in this role.
	Create(name, description string, permissionNames []string) error

	// Update an existing role.
	//
	// The parameters follow the same convention as those for the Create function, with
	// the distinction where `name` identifies the role and `newName` holds the updated
	// name value.
	//
	// IMPORTANT: All parameters will override whatever values are currently set
	// in the existing role. Use carefully.
	Update(name, newName, description string, permissionNames []string) error

	// Delete an existing role.
	//
	// IMPORTANT: This action is irreversible. Use carefully.
	Delete(name string) error

	// Load all roles.
	LoadAll() ([]*auth.Role, error)
}

// Provides functions for querying SSO groups in a project's tenant.
type Group interface {
	// Load all groups for a specific tenant id.
	LoadAllGroups(tenantID string) ([]*auth.Group, error)

	// Load all groups for the provided user JWT subjects or identifiers.
	//
	// JWT subject is with the format of "U2J5ES9S8TkvCgOvcrkpzUgVTEBM" (example), which can be found on the user's JWT.
	// identifier is the actual user identifier used for sign in.
	LoadAllGroupsForMembers(tenantID string, jwtSubjects, identifiers []string) ([]*auth.Group, error)

	// Load all members of the provided group id.
	LoadAllGroupMembers(tenantID, groupID string) ([]*auth.Group, error)
}

// Provides various APIs for managing a Descope project programmatically. A management key must
// be provided in the DecopeClient configuration or by setting the DESCOPE_MANAGEMENT_KEY
// environment variable. Management keys can be generated in the Descope console.
type Management interface {
	// Provides functions for managing tenants in a project.
	Tenant() Tenant

	// Provides functions for managing users in a project.
	User() User

	// Provides functions for managing access keys in a project.
	AccessKey() AccessKey

	// Provides functions for configuring SSO for a project.
	SSO() SSO

	// Provide functions for manipulating valid JWT
	JWT() JWT

	// Provide functions for managing permissions in a project
	Permission() Permission

	// Provide functions for managing roles in a project
	Role() Role

	// Provide functions for querying SSO groups in a project
	Group() Group
}
