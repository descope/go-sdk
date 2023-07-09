package sdk

import "github.com/descope/go-sdk/descope"

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

	// Load project tenant by id
	Load(id string) (*descope.Tenant, error)

	// Load all project tenants
	LoadAll() ([]*descope.Tenant, error)
}

// Provides functions for managing users in a project.
type User interface {
	// Create a new user.
	//
	// The loginID is required and will determine what the user will use to
	// sign in. user is optional, and if provided, all attributes within it are optional
	//
	// The roles parameter is an optional list of the user's roles for users that
	// aren't associated with a tenant, while the tenants parameter can be used
	// to specify which tenants to associate the user with and what roles the
	// user has in each one.
	Create(loginID string, user *descope.UserRequest) (*descope.UserResponse, error)

	// Create a new test user.
	//
	// The loginID is required and will determine what the user will use to
	// sign in, make sure the login id is unique for test. user is optional, and if provided,
	// all attributes within it are optional
	//
	// You can later generate OTP, Magic link and enchanted link to use in the test without the need
	// of 3rd party messaging services
	// Those users are not counted as part of the monthly active users
	CreateTestUser(loginID string, user *descope.UserRequest) (*descope.UserResponse, error)

	// Create a new user and invite them via an email message.
	//
	// Functions exactly the same as the Create function with the additional invitation
	// behavior. See the documentation above for the general creation behavior.
	//
	// IMPORTANT: Since the invitation is sent by email, make sure either
	// the email is explicitly set, or the loginID itself is an email address.
	// You must configure the invitation URL in the Descope console prior to
	// calling the method.
	Invite(loginID string, user *descope.UserRequest) (*descope.UserResponse, error)

	// Update an existing user.
	//
	// The parameters follow the same convention as those for the Create function.
	//
	// IMPORTANT: All parameters will override whatever values are currently set
	// in the existing user. Use carefully.
	Update(loginID string, user *descope.UserRequest) (*descope.UserResponse, error)

	// Delete an existing user.
	//
	// IMPORTANT: This action is irreversible. Use carefully.
	Delete(loginID string) error

	// Delete all test users in the project.
	//
	// IMPORTANT: This action is irreversible. Use carefully.
	DeleteAllTestUsers() error

	// Load an existing user.
	//
	// The loginID is required and the user will be fetched according to it.
	Load(loginID string) (*descope.UserResponse, error)

	// Load an existing user by User ID. The user ID can be found
	// on the user's JWT.
	//
	// The userID is required and the user will be fetched according to it.
	LoadByUserID(userID string) (*descope.UserResponse, error)

	// Search all users according to given filters
	//
	// The options optional parameter allows to fine-tune the search filters
	// and results. Using nil will result in a filter-less query with a set amount of
	// results.
	SearchAll(options *descope.UserSearchOptions) ([]*descope.UserResponse, error)

	// Activate an existing user.
	Activate(loginID string) (*descope.UserResponse, error)

	// Deactivate an existing user.
	Deactivate(loginID string) (*descope.UserResponse, error)

	// Change current loginID to new one
	// Leave empty to remove the current login ID
	// Pay attention that if this is the only login ID, it cannot be removed
	UpdateLoginID(loginID string, newLoginID string) (*descope.UserResponse, error)

	// Update the email address for an existing user.
	//
	// The email parameter can be empty in which case the email will be removed.
	//
	// The isVerified flag must be true for the user to be able to login with
	// the email address.
	UpdateEmail(loginID, email string, isVerified bool) (*descope.UserResponse, error)

	// Update the phone number for an existing user.
	//
	// The phone parameter can be empty in which case the phone will be removed.
	//
	// The isVerified flag must be true for the user to be able to login with
	// the phone number.
	UpdatePhone(loginID, phone string, isVerified bool) (*descope.UserResponse, error)

	// Update an existing user's display name (i.e., their full name).
	//
	// The displayName parameter can be empty in which case the name will be removed.
	UpdateDisplayName(loginID, displayName string) (*descope.UserResponse, error)

	// Update an existing user's picture (i.e., url to the avatar).
	//
	// The picture parameter can be empty in which case the picture will be removed.
	UpdatePicture(loginID, picture string) (*descope.UserResponse, error)

	// Update an existing user's custom attribute.
	//
	// key should be a custom attribute that was already declared in the Descope console app.
	// value should match the type of the declared attribute
	UpdateCustomAttribute(loginID, key string, value any) (*descope.UserResponse, error)

	// Add roles for a user without tenant association. Use AddTenantRoles for users
	// that are part of a multi-tenant project.
	AddRoles(loginID string, roles []string) (*descope.UserResponse, error)

	// Remove roles from a user without tenant association. Use RemoveTenantRoles for
	// users that are part of a multi-tenant project.
	RemoveRoles(loginID string, roles []string) (*descope.UserResponse, error)

	// Add a tenant association for an existing user.
	AddTenant(loginID string, tenantID string) (*descope.UserResponse, error)

	// Remove a tenant association from an existing user.
	RemoveTenant(loginID string, tenantID string) (*descope.UserResponse, error)

	// Add roles for a user in a specific tenant.
	AddTenantRoles(loginID string, tenantID string, roles []string) (*descope.UserResponse, error)

	// Remove roles from a user in a specific tenant.
	RemoveTenantRoles(loginID string, tenantID string, roles []string) (*descope.UserResponse, error)

	// Set a password for the given login ID.
	// Note: The password will automatically be set as expired.
	// The user will not be able to log-in with this password, and will be required to replace it on next login.
	// See also: ExpirePassword
	SetPassword(loginID string, password string) error

	// Expire the password for the given login ID.
	// Note: user sign-in with an expired password, the user will get `errors.ErrPasswordExpired` error.
	// Use the `ResetPassword` or `ReplacePassword` methods to reset/replace the password.
	ExpirePassword(loginID string) error

	// Get the provider token for the given login ID.
	// Only users that sign-in using social providers will have token.
	// Note: The 'Manage tokens from provider' setting must be enabled.
	GetProviderToken(loginID, provider string) (*descope.ProviderTokenResponse, error)

	// Generate OTP for the given login ID of a test user.
	// Choose the selected delivery method for verification. (see auth/DeliveryMethod)
	// It returns the code for the login (exactly as it sent via Email or SMS)
	// This is useful when running tests and don't want to use 3rd party messaging services
	// The redirect URI is optional. If provided however, it will be used instead of any global configuration.
	GenerateOTPForTestUser(method descope.DeliveryMethod, loginID string) (code string, err error)

	// Generate Magic Link for the given login ID of a test user.
	// Choose the selected delivery method for verification. (see auth/DeliveryMethod)
	// It returns the link for the login (exactly as it sent via Email)
	// This is useful when running tests and don't want to use 3rd party messaging services
	// The redirect URI is optional. If provided however, it will be used instead of any global configuration.
	GenerateMagicLinkForTestUser(method descope.DeliveryMethod, loginID, URI string) (link string, err error)

	// Generate Enchanted Link for the given login ID of a test user.
	// It returns the link for the login (exactly as it sent via Email) and pendingRef which is used to poll for a valid session
	// This is useful when running tests and don't want to use 3rd party messaging services
	// The redirect URI is optional. If provided however, it will be used instead of any global configuration.
	GenerateEnchantedLinkForTestUser(loginID, URI string) (link, pendingRef string, err error)
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
	Create(name string, expireTime int64, roles []string, keyTenants []*descope.AssociatedTenant) (string, *descope.AccessKeyResponse, error)

	// Load an existing access key.
	//
	// The id parameter is required and the access key will be fetched according to it.
	Load(id string) (*descope.AccessKeyResponse, error)

	// Search all access keys according to given filters
	//
	// The tenantIDs parameter is an optional array of tenant IDs to filter by.
	SearchAll(tenantIDs []string) ([]*descope.AccessKeyResponse, error)

	// Update an existing access key.
	//
	// The parameters follow the same convention as those for the Create function.
	// Only the name is settable for the time being.
	//
	// IMPORTANT: All parameters will override whatever values are currently set
	// in the existing access key. Use carefully.
	Update(id, name string) (*descope.AccessKeyResponse, error)

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

// Provides functions for configuring SSO for a project.
type SSO interface {
	// Get SSO setting for a tenant.
	//
	// tenantID is required.
	GetSettings(tenantID string) (*descope.SSOSettingsResponse, error)

	// tenantID is required.
	DeleteSettings(tenantID string) error
	// Configure SSO setting for a tenant manually.
	//
	// tenantID, idpURL, idpCert, entityID, are required. The idpURL is the URL for the identity provider and idpCert
	// is the certificated provided by the identity provider.
	// redirectURL is optional, however if not given it has to be set when starting an SSO authentication via the request.
	// domain is optional, it is used to map users to this tenant when authenticating via SSO.
	ConfigureSettings(tenantID, idpURL, idpCert, entityID, redirectURL, domain string) error

	// Configure SSO setting for a tenant by fetching SSO settings from an IDP metadata URL.
	ConfigureMetadata(tenantID, idpMetadataURL string) error

	// Configure SSO IDP mapping including groups to the Descope roles and user attributes.
	ConfigureMapping(tenantID string, roleMappings []*descope.RoleMapping, attributeMapping *descope.AttributeMapping) error
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
	LoadAll() ([]*descope.Permission, error)
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
	LoadAll() ([]*descope.Role, error)
}

// Provides functions for querying SSO groups in a project's tenant.
type Group interface {
	// Load all groups for a specific tenant id.
	LoadAllGroups(tenantID string) ([]*descope.Group, error)

	// Load all groups for the provided user IDs or login IDs.
	//
	// userIDs have a format of "U2J5ES9S8TkvCgOvcrkpzUgVTEBM" (example), which can be found on the user's JWT.
	// loginID is how the user identifies when logging in.
	LoadAllGroupsForMembers(tenantID string, userIDs, loginIDs []string) ([]*descope.Group, error)

	// Load all members of the provided group id.
	LoadAllGroupMembers(tenantID, groupID string) ([]*descope.Group, error)
}

// Provides functions for flow and theme management including export and import by ID.
type Flow interface {
	// Returns metadata of all project flows
	ListFlows() (*descope.FlowsResponse, error)
	// Export a flow and its screens by the flow id.
	ExportFlow(flowID string) (*descope.FlowResponse, error)

	// Import a flow and its screens as a given flow id. This will override the existing flow.
	// Returns the new flow and screens after a successful import or an error on failure.
	//
	// IMPORTANT: This action is irreversible. Use carefully.
	ImportFlow(flowID string, flow *descope.Flow, screens []*descope.Screen) (*descope.FlowResponse, error)

	// Export the project theme.
	ExportTheme() (*descope.Theme, error)

	// Import a given theme. This will override the existing project theme.
	// Returns the new theme after a successful import or an error on failure.
	//
	// IMPORTANT: This action is irreversible. Use carefully.
	ImportTheme(theme *descope.Theme) (*descope.Theme, error)
}

// Provides search project audit trail
type Audit interface {
	Search(*descope.AuditSearchOptions) ([]*descope.AuditRecord, error)
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

	// Provide functions for managing flows and theme in a project
	Flow() Flow

	// Provides search project audit trail
	Audit() Audit
}
