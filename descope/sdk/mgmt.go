package sdk

import (
	"context"
	"time"

	"github.com/descope/go-sdk/descope"
)

// Provides functions for managing tenants in a project.
type Tenant interface {
	// Create a new tenant with the given name.
	//
	// tenantRequest.SelfProvisioningDomains is an optional list of domains that are associated with this
	// tenant. Users authenticating from these domains will be associated with this tenant.
	//
	// The tenant tenantRequest.Name must be unique per project. The tenant ID is generated automatically
	// for the tenant.
	Create(ctx context.Context, tenantRequest *descope.TenantRequest) (id string, err error)

	// Create a new tenant with the given name and ID.
	//
	// tenantRequest.SelfProvisioningDomains is an optional list of domains that are associated with this
	// tenant. Users authenticating from these domains will be associated with this tenant.
	//
	// Both the tenantRequest.Name and ID must be unique per project.
	CreateWithID(ctx context.Context, id string, tenantRequest *descope.TenantRequest) error

	// Update an existing tenant's name and domains.
	//
	// IMPORTANT: All parameters are required and will override whatever value is currently
	// set in the existing tenant. Use carefully.
	Update(ctx context.Context, id string, tenantRequest *descope.TenantRequest) error

	// Delete an existing tenant.
	// Pass true on `cascade` in case you want to delete all users/keys associated only with this tenant
	//
	// IMPORTANT: This action is irreversible. Use carefully.
	Delete(ctx context.Context, id string, cascade bool) error

	// Load project tenant by id
	Load(ctx context.Context, id string) (*descope.Tenant, error)

	// Load all project tenants
	LoadAll(ctx context.Context) ([]*descope.Tenant, error)

	// Search all tenants according to given filters
	//
	// The options optional parameter allows to fine-tune the search filters
	// and results. Using nil will result in a filter-less query with a set amount of
	// results.
	SearchAll(ctx context.Context, options *descope.TenantSearchOptions) ([]*descope.Tenant, error)

	// Get tenant settings for a tenant by id.  Tenant ID is required.
	GetSettings(ctx context.Context, tenantID string) (*descope.TenantSettings, error)

	// Configure tenant settings for a tenant. Tenant ID is required.
	// All settings arguments are required and will override whatever is currently set even if left default.
	ConfigureSettings(ctx context.Context, tenantID string, settings *descope.TenantSettings) error
}

// Provides functions for managing SSO applications in a project.
type SSOApplication interface {
	// Create a new OIDC SSO application with the given name.
	//
	// OIDCApplicationRequest fields:
	// ID: Optional sso application ID.
	// Name: The sso application's name.
	// Description: Optional sso application description.
	// Enabled: Optional set the sso application as enabled or disabled.
	// Logo: Optional sso application logo.
	// LoginPageURL: The URL where login page is hosted.
	// ForceAuthentication: Optional determine if the IdP should force the user to re-authenticate.
	//
	// The argument appRequest.Id value is optional and will be auto generated if provided with empty value
	// The argument appRequest.Id and appRequest.Name must be unique per project.
	CreateOIDCApplication(ctx context.Context, appRequest *descope.OIDCApplicationRequest) (id string, err error)

	// Create a new SAML SSO application with the given name.
	//
	// SAMLApplicationRequest fields:
	// ID: Optional sso application ID.
	// Name: The sso application's name.
	// Description: Optional sso application description.
	// Enabled: Optional set the sso application as enabled or disabled.
	// Logo: Optional sso application logo.
	// LoginPageURL: The URL where login page is hosted.
	// UseMetadataInfo: Optional determine if SP info should be automatically fetched from metadata_url or by specified it by the entity_id, acs_url, certificate parameters.
	// MetadataURL: Optional (must be set if UseMetadataInfo is True) SP metadata url which include all the SP SAML info.
	// EntityID: Optional (must be set if UseMetadataInfo is False) SP entity id.
	// AcsURL: Optional (must be set if UseMetadataInfo is False) SP ACS (saml callback) url.
	// Certificate: Optional (must be set if UseMetadataInfo is False)SP certificate, relevant only when SAML request must be signed.
	// AttributeMapping: Optional list of Descope (IdP) attributes to SP mapping.
	// GroupsMapping: Optional list of Descope (IdP) roles that will be mapped to SP groups.
	// AcsAllowedCallbacks: Optional list of urls wildcards strings represents the allowed ACS urls that will be accepted while arriving on the SAML request as SP callback urls.
	// DefaultRelayState: Optional default relay state value that will be used in the SAML request.
	// SubjectNameIDType: Optional define the SAML Assertion subject name type, leave empty for using Descope user-id or set to "email"/"phone".
	// SubjectNameIDFormat: Optional define the SAML Assertion subject name format, leave empty for using "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified".
	// ForceAuthentication: Optional determine if the IdP should force the user to re-authenticate.
	// LogoutRedirectURL: Optional Target URL to which the user will be redirected upon logout completion.
	//
	// The argument appRequest.Id value is optional and will be auto generated if provided with empty value
	// The argument appRequest.Id and appRequest.Name must be unique per project.
	CreateSAMLApplication(ctx context.Context, appRequest *descope.SAMLApplicationRequest) (id string, err error)

	// Update an existing OIDC sso application.
	//
	// IMPORTANT: All parameters are required and will override whatever value is currently
	// set in the existing sso application. Use carefully.
	UpdateOIDCApplication(ctx context.Context, appRequest *descope.OIDCApplicationRequest) error

	// Update an existing SAML sso application.
	//
	// IMPORTANT: All parameters are required and will override whatever value is currently
	// set in the existing sso application. Use carefully.
	UpdateSAMLApplication(ctx context.Context, appRequest *descope.SAMLApplicationRequest) error

	// Delete an existing sso application.
	//
	// IMPORTANT: This action is irreversible. Use carefully.
	Delete(ctx context.Context, id string) error

	// Load project sso application by id
	Load(ctx context.Context, id string) (*descope.SSOApplication, error)

	// Load all project sso applications
	LoadAll(ctx context.Context) ([]*descope.SSOApplication, error)
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
	Create(ctx context.Context, loginID string, user *descope.UserRequest) (*descope.UserResponse, error)

	// Create a new test user.
	//
	// The loginID is required and will determine what the user will use to
	// sign in, make sure the login id is unique for test. user is optional, and if provided,
	// all attributes within it are optional
	//
	// You can later generate OTP, Magic link and enchanted link to use in the test without the need
	// of 3rd party messaging services
	// Those users are not counted as part of the monthly active users
	CreateTestUser(ctx context.Context, loginID string, user *descope.UserRequest) (*descope.UserResponse, error)

	// Create users in batch.
	//
	// Functions exactly the same as the Create function with the additional behavior that
	// users can be created with a cleartext or hashed password.
	CreateBatch(ctx context.Context, users []*descope.BatchUser) (*descope.UsersBatchResponse, error)

	// Create a new user and invite via an email / text message.
	//
	// Functions exactly the same as the Create function with the additional invitation
	// behavior. See the documentation above for the general creation behavior.
	//
	// IMPORTANT: Since the invitation is sent by email / phone, make sure either
	// the email / phone is explicitly set, or the loginID itself is an email address / phone number.
	// You must configure the invitation URL in the Descope console prior to
	// calling the method.
	Invite(ctx context.Context, loginID string, user *descope.UserRequest, options *descope.InviteOptions) (*descope.UserResponse, error)

	// Create users in batch and invite them via an email / text message.
	//
	// Functions exactly the same as the Create function with the additional invitation
	// behavior. See the documentation above for the general creation behavior.
	//
	// IMPORTANT: Since the invitation is sent by email / phone, make sure either
	// the email / phone is explicitly set, or the loginID itself is an email address / phone number.
	// You must configure the invitation URL in the Descope console prior to
	// calling the method.
	InviteBatch(ctx context.Context, users []*descope.BatchUser, options *descope.InviteOptions) (*descope.UsersBatchResponse, error)

	// Update an existing user.
	//
	// The parameters follow the same convention as those for the Create function.
	//
	// IMPORTANT: All parameters will override whatever values are currently set
	// in the existing user. Use carefully.
	// Instead, use Patch if you don't want to pass all parameters.
	Update(ctx context.Context, loginID string, user *descope.UserRequest) (*descope.UserResponse, error)

	// Patches an existing user.
	//
	// Only the fields that are set in the request will be updated.
	Patch(ctx context.Context, loginID string, user *descope.PatchUserRequest) (*descope.UserResponse, error)

	// Delete an existing user.
	//
	// IMPORTANT: This action is irreversible. Use carefully.
	Delete(ctx context.Context, loginID string) error

	// Delete an existing user by User ID. The user ID can be found
	// on the user's JWT.
	//
	// IMPORTANT: This action is irreversible. Use carefully.
	DeleteByUserID(ctx context.Context, userID string) error

	// Delete all test users in the project.
	//
	// IMPORTANT: This action is irreversible. Use carefully.
	DeleteAllTestUsers(ctx context.Context) error

	// Imports a batch of users and/or password hashes.
	//
	// This API is intentionally loosely specified to support multiple types of sources,
	// and the exact format of the data and the supported features differ depending on
	// which source the data is from.
	//
	// Note that there's a limit on the number of users that can be imported in each batch.
	Import(ctx context.Context, source string, users, hashes []byte, dryrun bool) (*descope.UserImportResponse, error)

	// Load an existing user.
	//
	// The loginID is required and the user will be fetched according to it.
	Load(ctx context.Context, loginID string) (*descope.UserResponse, error)

	// Load an existing user by User ID. The user ID can be found
	// on the user's JWT.
	//
	// The userID is required and the user will be fetched according to it.
	LoadByUserID(ctx context.Context, userID string) (*descope.UserResponse, error)

	// Search all users according to given filters
	//
	// The options optional parameter allows to fine-tune the search filters
	// and results. Using nil will result in a filter-less query with a set amount of
	// results.
	// Returns slice of users and total number of users for the query
	SearchAll(ctx context.Context, options *descope.UserSearchOptions) ([]*descope.UserResponse, int, error)

	// Activate an existing user.
	Activate(ctx context.Context, loginID string) (*descope.UserResponse, error)

	// Deactivate an existing user.
	Deactivate(ctx context.Context, loginID string) (*descope.UserResponse, error)

	// Logout given user from all their devices, by login ID
	LogoutUser(ctx context.Context, loginID string) error

	// Logout given user from all their devices, by user ID
	LogoutUserByUserID(ctx context.Context, userID string) error

	// Change current loginID to new one
	// Leave empty to remove the current login ID
	// Pay attention that if this is the only login ID, it cannot be removed
	UpdateLoginID(ctx context.Context, loginID string, newLoginID string) (*descope.UserResponse, error)

	// Update the email address for an existing user.
	//
	// The email parameter can be empty in which case the email will be removed.
	//
	// The isVerified flag must be true for the user to be able to login with
	// the email address.
	UpdateEmail(ctx context.Context, loginID, email string, isVerified bool) (*descope.UserResponse, error)

	// Update the phone number for an existing user.
	//
	// The phone parameter can be empty in which case the phone will be removed.
	//
	// The isVerified flag must be true for the user to be able to login with
	// the phone number.
	UpdatePhone(ctx context.Context, loginID, phone string, isVerified bool) (*descope.UserResponse, error)

	// Update an existing user's display name (i.e., their full name).
	//
	// The displayName parameter can be empty in which case the name will be removed.
	UpdateDisplayName(ctx context.Context, loginID, displayName string) (*descope.UserResponse, error)

	// Update an existing user's first/last/middle name.
	//
	// An empty parameter, means that this value will be removed.
	UpdateUserNames(ctx context.Context, loginID, givenName, middleName, familyName string) (*descope.UserResponse, error)

	// Update an existing user's picture (i.e., url to the avatar).
	//
	// The picture parameter can be empty in which case the picture will be removed.
	UpdatePicture(ctx context.Context, loginID, picture string) (*descope.UserResponse, error)

	// Update an existing user's custom attribute.
	//
	// key should be a custom attribute that was already declared in the Descope console app.
	// value should match the type of the declared attribute
	UpdateCustomAttribute(ctx context.Context, loginID, key string, value any) (*descope.UserResponse, error)

	// Set roles for a user without tenant association. Use SetTenantRoles for users
	// that are part of a multi-tenant project.
	SetRoles(ctx context.Context, loginID string, roles []string) (*descope.UserResponse, error)

	// Add roles for a user without tenant association. Use AddTenantRoles for users
	// that are part of a multi-tenant project.
	AddRoles(ctx context.Context, loginID string, roles []string) (*descope.UserResponse, error)

	// Remove roles from a user without tenant association. Use RemoveTenantRoles for
	// users that are part of a multi-tenant project.
	RemoveRoles(ctx context.Context, loginID string, roles []string) (*descope.UserResponse, error)

	// Associate SSO application for a user.
	AddSSOApps(ctx context.Context, loginID string, ssoAppIDs []string) (*descope.UserResponse, error)

	// Set (associate) SSO applications for a user.
	SetSSOApps(ctx context.Context, loginID string, ssoAppIDs []string) (*descope.UserResponse, error)

	// Remove SSO application association from a user.
	RemoveSSOApps(ctx context.Context, loginID string, ssoAppIDs []string) (*descope.UserResponse, error)

	// Add a tenant association for an existing user.
	AddTenant(ctx context.Context, loginID string, tenantID string) (*descope.UserResponse, error)

	// Remove a tenant association from an existing user.
	RemoveTenant(ctx context.Context, loginID string, tenantID string) (*descope.UserResponse, error)

	// Set roles for a user in a specific tenant.
	SetTenantRoles(ctx context.Context, loginID string, tenantID string, roles []string) (*descope.UserResponse, error)

	// Add roles for a user in a specific tenant.
	AddTenantRoles(ctx context.Context, loginID string, tenantID string, roles []string) (*descope.UserResponse, error)

	// Remove roles from a user in a specific tenant.
	RemoveTenantRoles(ctx context.Context, loginID string, tenantID string, roles []string) (*descope.UserResponse, error)

	// Set a temporary password for the given login ID.
	// Note: The password will automatically be set as expired.
	// The user will not be able to log-in with this password, and will be required to replace it on next login.
	// See also: ExpirePassword
	SetTemporaryPassword(ctx context.Context, loginID string, password string) error

	// Set a password for the given login ID.
	// The password will not be expired on the next login
	SetActivePassword(ctx context.Context, loginID string, password string) error

	// Set a password for the given login ID.
	// Note: The password will automatically be set as expired.
	// The user will not be able to log-in with this password, and will be required to replace it on next login.
	// See also: ExpirePassword
	// Deprecated: Use SetTemporaryPassword instead
	SetPassword(ctx context.Context, loginID string, password string) error

	// Expire the password for the given login ID.
	// Note: user sign-in with an expired password, the user will get `errors.ErrPasswordExpired` error.
	// Use the `SendPasswordReset` or `ReplaceUserPassword` methods to reset/replace the password.
	ExpirePassword(ctx context.Context, loginID string) error

	// Removes all registered passkeys (WebAuthn devices) for the user with the given login ID.
	// Note: The user might not be able to login anymore if they have no other authentication
	// methods or a verified email/phone.
	RemoveAllPasskeys(ctx context.Context, loginID string) error

	// Get the provider token for the given login ID.
	// Only users that sign-in using social providers will have token.
	// Note: The 'Manage tokens from provider' setting must be enabled.
	GetProviderToken(ctx context.Context, loginID, provider string) (*descope.ProviderTokenResponse, error)

	// Get the provider token for the given login ID with additional options.
	// Only users that sign-in using social providers will have token.
	// Note: The 'Manage tokens from provider' setting must be enabled.
	// The providerTokenOptions is optional. It can be used with the following options:
	// 	withRefreshToken - to include the refresh token in the response
	//	forceRefresh - force to refresh the token
	GetProviderTokenWithOptions(ctx context.Context, loginID, provider string, options *descope.ProviderTokenOptions) (*descope.ProviderTokenResponse, error)

	// Generate OTP for the given login ID of a test user.
	// Choose the selected delivery method for verification. (see auth/DeliveryMethod)
	// It returns the code for the login (exactly as it sent via Email or SMS)
	// This is useful when running tests and don't want to use 3rd party messaging services
	// The redirect URI is optional. If provided however, it will be used instead of any global configuration.
	GenerateOTPForTestUser(ctx context.Context, method descope.DeliveryMethod, loginID string, loginOptions *descope.LoginOptions) (code string, err error)

	// Generate Magic Link for the given login ID of a test user.
	// Choose the selected delivery method for verification. (see auth/DeliveryMethod)
	// It returns the link for the login (exactly as it sent via Email)
	// This is useful when running tests and don't want to use 3rd party messaging services
	// The redirect URI is optional. If provided however, it will be used instead of any global configuration.
	GenerateMagicLinkForTestUser(ctx context.Context, method descope.DeliveryMethod, loginID, URI string, loginOptions *descope.LoginOptions) (link string, err error)

	// Generate Enchanted Link for the given login ID of a test user.
	// It returns the link for the login (exactly as it sent via Email) and pendingRef which is used to poll for a valid session
	// This is useful when running tests and don't want to use 3rd party messaging services
	// The redirect URI is optional. If provided however, it will be used instead of any global configuration.
	GenerateEnchantedLinkForTestUser(ctx context.Context, loginID, URI string, loginOptions *descope.LoginOptions) (link, pendingRef string, err error)

	// Generate an embedded link token, later can be used to authenticate via magiclink verify method
	// or via flow verify step
	GenerateEmbeddedLink(ctx context.Context, loginID string, customClaims map[string]any) (string, error)

	// Use to retrieve users' authentication history, by the given user's ids.
	// returns slice of users' authentication history.
	History(ctx context.Context, userIDs []string) ([]*descope.UserHistoryResponse, error)
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
	// If userID is supplied, then authorization would be ignored, and access key would be bound to the users authorization
	// The customClaims parameter is an optional map of claims and their values, and if it's provided then
	// those claims will be present in the JWT returned by calls to ExchangeAccessKey.
	// The description parameter is an optional text providing a brief summary about the access key.
	// The permittedIPs parameter is an optional list of IP addresses or CIDR ranges that are allowed to use this access key.
	// If not provided, all IPs are allowed.
	Create(ctx context.Context, name string, description string, expireTime int64, roles []string, keyTenants []*descope.AssociatedTenant, userID string, customClaims map[string]any, permittedIPs []string) (string, *descope.AccessKeyResponse, error)

	// Load an existing access key.
	//
	// The id parameter is required and the access key will be fetched according to it.
	Load(ctx context.Context, id string) (*descope.AccessKeyResponse, error)

	// Search all access keys according to given filters
	//
	// The tenantIDs parameter is an optional array of tenant IDs to filter by.
	SearchAll(ctx context.Context, tenantIDs []string) ([]*descope.AccessKeyResponse, error)

	// Update an existing access key.
	//
	// The parameters follow the same convention as those for the Create function.
	// Only the name and description are settable for the time being.
	//
	// IMPORTANT: id and name are mandatory parameters.
	Update(ctx context.Context, id, name string, description *string) (*descope.AccessKeyResponse, error)

	// Deactivate an existing access key.
	//
	// IMPORTANT: This deactivated key will not be usable from this stage. It will, however,
	// persist, and can be activated again if needed.
	Deactivate(ctx context.Context, id string) error

	// Activate an existing access key.
	//
	// IMPORTANT: Only deactivated keys can be activated again, and become usable once more. New access keys
	// are active by default.
	Activate(ctx context.Context, id string) error

	// Delete an existing access key.
	//
	// IMPORTANT: This action is irreversible. Use carefully.
	Delete(ctx context.Context, id string) error
}

// Provides functions for configuring SSO for a project.
type SSO interface {
	// Load all tenant SSO setting.
	//
	// tenantID is required.
	LoadSettings(ctx context.Context, tenantID string) (*descope.SSOTenantSettingsResponse, error)

	// Configure SSO SAML settings for a tenant manually.
	//
	// tenantID, settings are required (all settings parameters are required).
	//
	// redirectURL is optional, however if not given it has to be set when starting an SSO authentication via the request.
	// domains is optional, it is used to map users to this tenant when authenticating via SSO.
	//
	// Both optional values will override whatever is currently set even if left empty.
	ConfigureSAMLSettings(ctx context.Context, tenantID string, settings *descope.SSOSAMLSettings, redirectURL string, domains []string) error

	// Configure SSO SAML settings for a tenant by fetching them from an IDP metadata URL.
	//
	// tenantID, settings are required (all settings parameters are required).
	//
	// redirectURL is optional, however if not given it has to be set when starting an SSO authentication via the request.
	// domains is optional, it is used to map users to this tenant when authenticating via SSO.
	//
	// Both optional values will override whatever is currently set even if left empty.
	ConfigureSAMLSettingsByMetadata(ctx context.Context, tenantID string, settings *descope.SSOSAMLSettingsByMetadata, redirectURL string, domains []string) error

	// Configure SSO OIDC settings for a tenant manually.
	//
	// tenantID, settings are required.
	//
	// domains is optional, it is used to map users to this tenant when authenticating via SSO.
	//
	// Optional value will override whatever is currently set even if left empty.
	ConfigureOIDCSettings(ctx context.Context, tenantID string, settings *descope.SSOOIDCSettings, domains []string) error

	// tenantID is required.
	DeleteSettings(ctx context.Context, tenantID string) error

	// *** Deprecated ***

	//* Deprecated (use LoadSettings() instead) *//
	// Get SAML SSO setting for a tenant.
	//
	// tenantID is required.
	GetSettings(ctx context.Context, tenantID string) (*descope.SSOSettingsResponse, error)

	//* Deprecated (use ConfigureSAMLSettings() instead) *//
	// Configure SSO settings for a tenant manually.
	//
	// tenantID, idpURL, idpCert, entityID, are required. The idpURL is the URL for the identity provider and idpCert
	// is the certificated provided by the identity provider.
	//
	// redirectURL is optional, however if not given it has to be set when starting an SSO authentication via the request.
	// domains is optional, it is used to map users to this tenant when authenticating via SSO.
	//
	// Both optional values will override whatever is currently set even if left empty.
	ConfigureSettings(ctx context.Context, tenantID, idpURL, idpCert, entityID, redirectURL string, domains []string) error

	//* Deprecated (use ConfigureSAMLSettingsByMetadata() instead) *//
	// Configure SSO settings for a tenant by fetching them from an IDP metadata URL.
	//
	// redirectURL is optional, however if not given it has to be set when starting an SSO authentication via the request.
	// domains is optional, it is used to map users to this tenant when authenticating via SSO.
	//
	// Both optional values will override whatever is currently set even if left empty.
	ConfigureMetadata(ctx context.Context, tenantID, idpMetadataURL, redirectURL string, domains []string) error

	//* Deprecated (use ConfigureSAMLSettings() or ConfigureSAMLSettingsByMetadata() instead) *//
	// Configure SSO IDP mapping including groups to the Descope roles and user attributes.
	ConfigureMapping(ctx context.Context, tenantID string, roleMappings []*descope.RoleMapping, attributeMapping *descope.AttributeMapping) error
}

// Provides functions for managing password policy for a project or a tenant.
type PasswordManagement interface {
	// Get password settings for a project or tenant.
	GetSettings(ctx context.Context, tenantID string) (*descope.PasswordSettings, error)

	// Configure Password settings for a project or a tenant manually.
	// Tenant ID can be left empty to apply changes to project password policy.
	// All other arguments are required and will override whatever is currently set even if left default.
	ConfigureSettings(ctx context.Context, tenantID string, settings *descope.PasswordSettings) error
}

// Provide functions for manipulating valid JWT
type JWT interface {
	// Update a valid JWT with the custom claims provided
	// The new JWT will be returned
	UpdateJWTWithCustomClaims(ctx context.Context, jwt string, customClaims map[string]any) (string, error)

	// Impersonate another user
	// The impersonator user must have `impersonation` permission in order for this request to work
	// The response would be a refresh JWT of the impersonated user
	Impersonate(ctx context.Context, impersonatorID string, loginID string, validateConcent bool) (string, error)
}

// Provides functions for managing permissions in a project.
type Permission interface {
	// Create a new permission.
	//
	// The name is required to uniquely identify a permission.
	//
	// The description parameter is an optional description to briefly explain
	// what this permission allows.
	Create(ctx context.Context, name, description string) error

	// Update an existing permission.
	//
	// The parameters follow the same convention as those for the Create function, with
	// the distinction where `name` identifies the permission and `newName` holds the updated
	// name value.
	//
	// IMPORTANT: All parameters will override whatever values are currently set
	// in the existing permission. Use carefully.
	Update(ctx context.Context, name, newName, description string) error

	// Delete an existing permission.
	//
	// IMPORTANT: This action is irreversible. Use carefully.
	Delete(ctx context.Context, name string) error

	// Load all permissions.
	LoadAll(ctx context.Context) ([]*descope.Permission, error)
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
	// tenantID is an optional field to tie this role to a specific tenant
	Create(ctx context.Context, name, description string, permissionNames []string, tenantID string) error

	// Update an existing role.
	//
	// The parameters follow the same convention as those for the Create function, with
	// the distinction where `name` identifies the role and `newName` holds the updated
	// name value.
	//
	// IMPORTANT: All parameters will override whatever values are currently set
	// in the existing role. Use carefully.
	Update(ctx context.Context, name, tenantID, newName, description string, permissionNames []string) error

	// Delete an existing role.
	//
	// IMPORTANT: This action is irreversible. Use carefully.
	Delete(ctx context.Context, name, tenantID string) error

	// Load all roles.
	LoadAll(ctx context.Context) ([]*descope.Role, error)

	Search(ctx context.Context, options *descope.RoleSearchOptions) ([]*descope.Role, error)
}

// Provides functions for querying SSO groups in a project's tenant.
type Group interface {
	// Load all groups for a specific tenant id.
	LoadAllGroups(ctx context.Context, tenantID string) ([]*descope.Group, error)

	// Load all groups for the provided user IDs or login IDs.
	//
	// userIDs have a format of "U2J5ES9S8TkvCgOvcrkpzUgVTEBM" (example), which can be found on the user's JWT.
	// loginID is how the user identifies when logging in.
	LoadAllGroupsForMembers(ctx context.Context, tenantID string, userIDs, loginIDs []string) ([]*descope.Group, error)

	// Load all members of the provided group id.
	LoadAllGroupMembers(ctx context.Context, tenantID, groupID string) ([]*descope.Group, error)
}

// Provides functions for flow and theme management including export and import by ID.
type Flow interface {
	// Returns metadata of all project flows
	ListFlows(ctx context.Context) (*descope.FlowsResponse, error)

	// Delete flows by flow ids.
	//
	// IMPORTANT: This action is irreversible. Use carefully.
	DeleteFlows(ctx context.Context, flowIDs []string) error

	// Export a flow and its screens by the flow id.
	ExportFlow(ctx context.Context, flowID string) (*descope.FlowResponse, error)

	// Import a flow and its screens as a given flow id. This will override the existing flow.
	// Returns the new flow and screens after a successful import or an error on failure.
	//
	// IMPORTANT: This action is irreversible. Use carefully.
	ImportFlow(ctx context.Context, flowID string, flow *descope.Flow, screens []*descope.Screen) (*descope.FlowResponse, error)

	// Export the project theme.
	ExportTheme(ctx context.Context) (*descope.Theme, error)

	// Import a given theme. This will override the existing project theme.
	// Returns the new theme after a successful import or an error on failure.
	//
	// IMPORTANT: This action is irreversible. Use carefully.
	ImportTheme(ctx context.Context, theme *descope.Theme) (*descope.Theme, error)
}

// Provides functions for exporting and importing project settings, flows, styles, etc.
type Project interface {
	// Lists all projects for a company.
	//
	// IMPORTANT: Requires a company management key that's not limited to specific projects.
	ListProjects(ctx context.Context) ([]*descope.Project, error)

	// Clone the current project, including its settings and configurations.
	// - This action is supported only with a pro license or above.
	// - Users, tenants and access keys are not cloned.
	// Returns The new project details (name, id, and tag).
	Clone(ctx context.Context, name string, tag descope.ProjectTag) (*descope.CloneProjectResponse, error)

	// Update the current project name.
	UpdateName(ctx context.Context, name string) error

	// Delete the current project.
	Delete(ctx context.Context) error

	// Exports a snapshot of all the settings and configurations for a project and returns
	// the raw JSON files response as a map.
	//
	// Note: The values for secrets such as tokens and keys are left blank in the snapshot.
	// When a snapshot is imported into a project, the secrets for entities that already
	// exist such as connectors or OAuth providers are preserved if the matching values
	// in the snapshot are left blank. See below for more details.
	//
	// This API is meant to be used via the 'descopecli' command line tool that can be
	// found at https://github.com/descope/descopecli
	ExportSnapshot(ctx context.Context) (*descope.ExportSnapshotResponse, error)

	// Imports a snapshot of all settings and configurations into a project, overriding any
	// current configuration.
	//
	// The input is expected to be a request with a raw JSON map of files in the same format
	// as the one returned by calls to ExportSnapshot.
	//
	// Note: The values for secrets such as tokens and keys are left blank in exported
	// snapshots. When a snapshot is imported into a project, the secrets for entities that
	// already exist such as connectors or OAuth providers are preserved if the matching values
	// in the snapshot are left blank. However, new entities that need to be created during
	// the import operation must any required secrets provided in the request, otherwise the
	// import operation will fail. The ValidateImport method can be used to get a human and
	// machine readable JSON of missing secrets that be passed to the ImportSnapshot call.
	//
	// This API is meant to be used via the 'descopecli' command line tool that can be
	// found at https://github.com/descope/descopecli
	ImportSnapshot(ctx context.Context, req *descope.ImportSnapshotRequest) error

	// Validates a snapshot by performing an import dry run and reporting any validation
	// failures or missing data. This should be called right before ImportSnapshot to
	// minimize the risk of the import failing.
	//
	// The response will have `Ok: true` if the validation passed. Otherise, a list of
	// failures will be provided in the `Failures` field, and any missing secrets will
	// be listed along with details about which entity requires them.
	//
	// Validation can be retried by set the required cleartext secret values in the
	// `Value` field of each missing secret and setting this object as the `InputSecrets`
	// field of the import request.
	//
	// This API is meant to be used via the 'descopecli' command line tool that can be
	// found at https://github.com/descope/descopecli
	ValidateSnapshot(ctx context.Context, req *descope.ValidateSnapshotRequest) (*descope.ValidateSnapshotResponse, error)
}

// Provides search project audit trail
type Audit interface {
	Search(ctx context.Context, options *descope.AuditSearchOptions) ([]*descope.AuditRecord, error)
	CreateEvent(ctx context.Context, options *descope.AuditCreateOptions) error
}

// Provides authorization ReBAC capabilities
type Authz interface {
	// SaveSchema creating or updating it.
	// In case of update, will update only given namespaces and will not delete namespaces unless upgrade flag is true.
	// Schema name can be used for projects to track versioning.
	SaveSchema(ctx context.Context, schema *descope.AuthzSchema, upgrade bool) error

	// DeleteSchema for the project which will also delete all relations.
	DeleteSchema(ctx context.Context) error

	// LoadSchema for the project.
	LoadSchema(ctx context.Context) (*descope.AuthzSchema, error)

	// SaveNamespace creating or updating the given namespace
	// Will not delete relation definitions not mentioned in the namespace.
	// oldName is used if we are changing the namespace name
	// schemaName is optional and can be used to track the current schema version.
	SaveNamespace(ctx context.Context, namespace *descope.AuthzNamespace, oldName, schemaName string) error

	// DeleteNamespace will also delete the relevant relations.
	// schemaName is optional and used to track the current schema version.
	DeleteNamespace(ctx context.Context, name, schemaName string) error

	// SaveRelationDefinition creating or updating the given relation definition.
	// Provide oldName if we are changing the relation definition name, what was the old name we are updating.
	// schemaName is optional and can be used to track the current schema version.
	SaveRelationDefinition(ctx context.Context, relationDefinition *descope.AuthzRelationDefinition, namespace, oldName, schemaName string) error

	// DeleteRelationDefinition will also delete the relevant relations.
	// schemaName is optional and can be used to track the current schema version.
	DeleteRelationDefinition(ctx context.Context, name, namespace, schemaName string) error

	// CreateRelations based on the existing schema
	CreateRelations(ctx context.Context, relations []*descope.AuthzRelation) error

	// DeleteRelations based on the existing schema
	DeleteRelations(ctx context.Context, relations []*descope.AuthzRelation) error

	// DeleteRelationsForResources will delete all relations to the given resources
	DeleteRelationsForResources(ctx context.Context, resources []string) error

	// HasRelations check queries given relations to see if they exist returning true if they do
	HasRelations(ctx context.Context, relationQueries []*descope.AuthzRelationQuery) ([]*descope.AuthzRelationQuery, error)

	// WhoCanAccess the given resource returns the list of targets with the given relation definition
	WhoCanAccess(ctx context.Context, resource, relationDefinition, namespace string) ([]string, error)

	// ResourceRelations returns the list of all defined relations (not recursive) on the given resource.
	ResourceRelations(ctx context.Context, resource string) ([]*descope.AuthzRelation, error)

	// TargetRelations returns the list of all defined relations (not recursive) for the given targets.
	TargetsRelations(ctx context.Context, targets []string) ([]*descope.AuthzRelation, error)

	// WhatCanTargetAccess returns the list of all relations for the given target including derived relations from the schema tree.
	WhatCanTargetAccess(ctx context.Context, target string) ([]*descope.AuthzRelation, error)

	// WhatCanTargetAccessWithRelation returns the list of all resources that the target has the given relation to including all derived relations
	WhatCanTargetAccessWithRelation(ctx context.Context, target, relationDefinition, namespace string) ([]*descope.AuthzRelation, error)

	// GetModified list of targets and resources changed since the given date
	// Should be used to invalidate local caches
	GetModified(ctx context.Context, since time.Time) (*descope.AuthzModified, error)
}

// Provides various APIs for managing a Descope project programmatically. A management key must
// be provided in the DecopeClient configuration or by setting the DESCOPE_MANAGEMENT_KEY
// environment variable. Management keys can be generated in the Descope console.
type Management interface {
	// Provides functions for managing tenants in a project.
	Tenant() Tenant

	// Provides functions for managing sso applications in a project.
	SSOApplication() SSOApplication

	// Provides functions for managing users in a project.
	User() User

	// Provides functions for managing access keys in a project.
	AccessKey() AccessKey

	// Provides functions for configuring SSO for a project.
	SSO() SSO

	// Provides functions for password settings for a project or tenant.
	Password() PasswordManagement

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

	// Provides functions for managing audit
	Audit() Audit

	// Provide functions for managing projects
	Project() Project

	// Provides functions for ReBAC authz management
	Authz() Authz
}
