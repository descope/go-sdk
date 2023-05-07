[![CI](https://github.com/descope/go-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/descope/go-sdk/actions/workflows/ci.yml)

# Descope SDK for Go

The Descope SDK for Go provides convenient access to the Descope user management and authentication API
for a backend written in Go. You can read more on the [Descope Website](https://descope.com).

## Requirements

The SDK supports Go version 1.18 and above.

## Installing the SDK

Install the package with:

```bash
go get -u github.com/descope/go-sdk
```

## Setup

A Descope `Project ID` is required to initialize the SDK. Find it on the
[project page in the Descope Console](https://app.descope.com/settings/project).

```go
import "github.com/descope/go-sdk/descope/client"

// Initialized after setting the DESCOPE_PROJECT_ID env var
descopeClient := client.New()

// ** Or directly **
descopeClient := client.NewWithConfig(&client.Config{ProjectID: projectID})
```

## Authentication Functions

These sections show how to use the SDK to perform various authentication/authorization functions:

1. [OTP Authentication](#otp-authentication)
2. [Magic Link](#magic-link)
3. [Enchanted Link](#enchanted-link)
4. [OAuth](#oauth)
5. [SSO/SAML](#ssosaml)
6. [TOTP Authentication](#totp-authentication)
7. [Passwords](#passwords)
8. [Session Validation](#session-validation)
9. [Roles & Permission Validation](#roles--permission-validation)
10. [Logging Out](#logging-out)

## Management Functions

These sections show how to use the SDK to perform API management functions. Before using any of them, you will need to create a Management Key. The instructions for this can be found under [Setup](#setup-1).

1. [Manage Tenants](#manage-tenants)
2. [Manage Users](#manage-users)
3. [Manage Access Keys](#manage-access-keys)
4. [Manage SSO Setting](#manage-sso-setting)
5. [Manage Permissions](#manage-permissions)
6. [Manage Roles](#manage-roles)
7. [Query SSO Groups](#query-sso-groups)
8. [Manage Flows](#manage-flows)
9. [Manage JWTs](#manage-jwts)

If you wish to run any of our code samples and play with them, check out our [Code Examples](#code-examples) section.

If you're developing unit tests, see how you can use our mocks package underneath the [Unit Testing and Data Mocks](#unit-testing-and-data-mocks) section.

If you're performing end-to-end testing, check out the [Utils for your end to end (e2e) tests and integration tests](#utils-for-your-end-to-end-e2e-tests-and-integration-tests) section. You will need to use the `descopeClient` object created under [Setup](#setup-1) guide.

For rate limiting information, please confer to the [API Rate Limits](#api-rate-limits) section.

---

### OTP Authentication

Send a user a one-time password (OTP) using your preferred delivery method (_email / SMS_). An email address or phone number must be provided accordingly.

The user can either `sign up`, `sign in` or `sign up or in`

```go
// Every user must have a loginID. All other user information is optional
loginID := "desmond@descope.com"
user := &descope.User{
    Name: "Desmond Copeland",
    Phone: "212-555-1234",
    Email: loginID,
}
maskedAddress, err := descopeClient.Auth.OTP().SignUp(descope.MethodEmail, loginID, user)
if err != nil {
    if errors.Is(err, descope.ErrUserAlreadyExists) {
        // user already exists with this loginID
    }
    // handle other error cases
}
```

The user will receive a code using the selected delivery method. Verify that code using:

```go
// The optional `w http.ResponseWriter` adds the session and refresh cookies to the response automatically.
// Otherwise they're available via authInfo
authInfo, err := descopeClient.Auth.OTP().VerifyCode(descope.MethodEmail, loginID, code, w)
if err != nil {
    if errors.Is(err, descope.ErrInvalidOneTimeCode) {
        // the code was invalid
    }
    if descope.IsUnauthorizedError(err) {
        // login failed for some other reason
    }
    // handle other error cases
}
```

The session and refresh JWTs should be returned to the caller, and passed with every request in the session. Read more on [session validation](#session-validation)

### Magic Link

Send a user a Magic Link using your preferred delivery method (_email / SMS_).
The Magic Link will redirect the user to page where the its token needs to be verified.
This redirection can be configured in code, or globally in the [Descope Console](https://app.descope.com/settings/authentication/magiclink)

The user can either `sign up`, `sign in` or `sign up or in`

```go
// If configured globally, the redirect URI is optional. If provided however, it will be used
// instead of any global configuration
maskedAddress, err := descopeClient.Auth.MagicLink().SignUpOrIn(descope.MethodEmail, "desmond@descope.com", "http://myapp.com/verify-magic-link")
if err {
    // handle error
}
```

To verify a magic link, your redirect page must call the validation function on the token (`t`) parameter (`https://your-redirect-address.com/verify?t=<token>`):

```go
// The optional `w http.ResponseWriter` adds the session and refresh cookies to the response automatically.
// Otherwise they're available via authInfo
authInfo, err := descopeClient.Auth.MagicLink().Verify(token, w)
if err != nil {
    // handle error
}
```

The session and refresh JWTs should be returned to the caller, and passed with every request in the session. Read more on [session validation](#session-validation)

### Enchanted Link

Using the Enchanted Link APIs enables users to sign in by clicking a link
delivered to their email address. The email will include 3 different links,
and the user will have to click the right one, based on the 2-digit number that is
displayed when initiating the authentication process.

This method is similar to [Magic Link](#magic-link) but differs in two major ways:

- The user must choose the correct link out of the three, instead of having just one
  single link.
- This supports cross-device clicking, meaning the user can try to log in on one device,
  like a computer, while clicking the link on another device, for instance a mobile phone.

The Enchanted Link will redirect the user to page where the its token needs to be verified.
This redirection can be configured in code per request, or set globally in the [Descope Console](https://app.descope.com/settings/authentication/enchantedlink).

The user can either `sign up`, `sign in` or `sign up or in`

```go
// If configured globally, the redirect URI is optional. If provided however, it will be used
// instead of any global configuration.
res, err := descopeClient.Auth.EnchantedLink().SignIn(loginID, "http://myapp.com/verify-enchanted-link", nil, nil)
if err != nil {
    // handle error
}
res.LinkID // should be displayed to the user so they can click the corresponding link in the email
res.PendingRef // Used to poll for a valid session
```

After sending the link, you must poll to receive a valid session using the `PendingRef` from
the previous step. A valid session will be returned only after the user clicks the right link.

```go
// Poll for a certain number of tries / time frame
for i := retriesCount; i > 0; i-- {
    authInfo, err := descopeClient.Auth.EnchantedLink().GetSession(res.PendingRef, w)
    if err == nil {
        // The user successfully authenticated using the correct link
        // The optional `w http.ResponseWriter` adds the session and refresh cookies to the response automatically.
        // Otherwise they're available via authInfo
        break
    }
    if errors.Is(err, descope.ErrEnchantedLinkUnauthorized) && i > 1 {
        // poll again after X seconds
        time.Sleep(time.Second * time.Duration(retryInterval))
        continue
    }
    if err != nil {
        // handle error
        break
    }
}
```

To verify an enchanted link, your redirect page must call the validation function on the token (`t`) parameter (`https://your-redirect-address.com/verify?t=<token>`). Once the token is verified, the session polling will receive a valid response.

```go
if err := descopeClient.Auth.EnchantedLink().Verify(token); err != nil {
    // token is invalid
} else {
    // token is valid
}
```

The session and refresh JWTs should be returned to the caller, and passed with every request in the session. Read more on [session validation](#session-validation)

### OAuth

Users can authenticate using their social logins, using the OAuth protocol. Configure your OAuth settings on the [Descope console](https://app.descope.com/settings/authentication/social). To start a flow call:

```go
// Choose an oauth provider out of the supported providers
// If configured globally, the return URL is optional. If provided however, it will be used
// instead of any global configuration.
// Redirect the user to the returned URL to start the OAuth redirect chain
url, err := descopeClient.Auth.OAuth().Start("google", "https://my-app.com/handle-oauth", nil, nil, w)
if err != nil {
    // handle error
}
```

The user will authenticate with the authentication provider, and will be redirected back to the redirect URL, with an appended `code` HTTP URL parameter. Exchange it to validate the user:

```go
// The optional `w http.ResponseWriter` adds the session and refresh cookies to the response automatically.
// Otherwise they're available via authInfo
authInfo, err := descopeClient.Auth.OAuth().ExchangeToken(code, w)
if err != nil {
    // handle error
}
```

The session and refresh JWTs should be returned to the caller, and passed with every request in the session. Read more on [session validation](#session-validation)

### SSO/SAML

Users can authenticate to a specific tenant using SAML or Single Sign On. Configure your SSO/SAML settings on the [Descope console](https://app.descope.com/settings/authentication/sso). To start a flow call:

```go
// Choose which tenant to log into
// If configured globally, the return URL is optional. If provided however, it will be used
// instead of any global configuration.
// Redirect the user to the returned URL to start the SSO/SAML redirect chain
url, err := descopeClient.Auth.SAML().Start("my-tenant-ID", "https://my-app.com/handle-saml", nil, nil, w)
if err != nil {
    // handle error
}
```

The user will authenticate with the authentication provider configured for that tenant, and will be redirected back to the redirect URL, with an appended `code` HTTP URL parameter. Exchange it to validate the user:

```go
// The optional `w http.ResponseWriter` adds the session and refresh cookies to the response automatically.
// Otherwise they're available via authInfo
authInfo, err := descopeClient.Auth.SAML().ExchangeToken(code, w)
if err != nil {
    // handle error
}
```

The session and refresh JWTs should be returned to the caller, and passed with every request in the session. Read more on [session validation](#session-validation)

### TOTP Authentication

The user can authenticate using an authenticator app, such as Google Authenticator.
Sign up like you would using any other authentication method. The sign up response
will then contain a QR code `Image` that can be displayed to the user to scan using
their mobile device camera app, or the user can enter the `Key` manually or click
on the link provided by the `ProvisioningURL`.

Existing users can add TOTP using the `update` function.

```go
// Every user must have a loginID. All other user information is optional
loginID := "desmond@descope.com"
user := &descope.User{
    Name: "Desmond Copeland",
    Phone: "212-555-1234",
    Email: loginID,
}
totpResponse, err := descopeClient.Auth.TOTP().SignUp(loginID, user)
if err != nil {
    // handle error
}
// Use one of the provided options to have the user add their credentials to the authenticator
// totpResponse.ProvisioningURL
// totpResponse.Image
// totpResponse.Key
```

There are 3 different ways to allow the user to save their credentials in
their authenticator app - either by clicking the provisioning URL, scanning the QR
image or inserting the key manually. After that, signing in is done using the code
the app produces.

```go
// The optional `w http.ResponseWriter` adds the session and refresh cookies to the response automatically.
// Otherwise they're available via authInfo
authInfo, err := descopeClient.Auth.TOTP().SignInCode(loginID, code, nil, nil, w)
if err != nil {
    // handle error
}
```

The session and refresh JWTs should be returned to the caller, and passed with every request in the session. Read more on [session validation](#session-validation)

### Passwords

The user can also authenticate with a password, though it's recommended to
prefer passwordless authentication methods if possible. Sign up requires the
caller to provide a valid password that meets all the requirements configured
for the [password authentication method](https://app.descope.com/settings/authentication/password) in the Descope console.

```go
// Every user must have a loginID. All other user information is optional
loginID := "desmond@descope.com"
password := "qYlvi65KaX"
user := &descope.User{
    Name: "Desmond Copeland",
    Email: loginID,
}
authInfo, err := descopeClient.Auth.Password().SignUp(loginID, user, password, nil)
if err != nil {
    // handle error
}
```

The user can later sign in using the same loginID and password.

```go
// The optional `w http.ResponseWriter` adds the session and refresh cookies to the response automatically.
// Otherwise they're available via authInfo
authInfo, err := descopeClient.Auth.Password().SignIn(loginID, password, w)
if err != nil {
    // handle error
}
```

The session and refresh JWTs should be returned to the caller, and passed with every request in the session. Read more on [session validation](#session-validation)

In case the user needs to update their password, one of two methods are available: Resetting their password or replacing their password

**Changing Passwords**

_NOTE: SendPasswordReset will only work if the user has a validated email address. Otherwise password reset prompts cannot be sent._

In the [password authentication method](https://app.descope.com/settings/authentication/password) in the Descope console, it is possible to define which alternative authentication method can be used in order to authenticate the user, in order to reset and update their password.

```go
// Start the reset process by sending a password reset prompt. In this example we'll assume
// that magic link is configured as the reset method. The optional redirect URL is used in the
// same way as in regular magic link authentication.
loginID := "desmond@descope.com"
redirectURL := "https://myapp.com/password-reset"
err := descopeClient.Auth.Password().SendPasswordReset(loginID, redirectURL)
```

The magic link, in this case, must then be verified like any other magic link (see the [magic link section](#magic-link) for more details). However, after verifying the user, it is expected
to allow them to provide a new password instead of the old one. Since the user is now authenticated, this is possible via:

```go
// The request (r) is required to make sure the user is authenticated.
err := descopeClient.Auth.Password().UpdateUserPassword(loginID, newPassword, r)
```

`UpdateUserPassword` can always be called when the user is authenticated and has a valid session.

Alternatively, it is also possible to replace an existing active password with a new one.

```go
// Replaces the user's current password with a new one
err := descopeClient.Auth.Password().ReplaceUserPassword(loginID, oldPassword, newPassword)
```

### Session Validation

Every secure request performed between your client and server needs to be validated. The client sends
the session and refresh tokens with every request, and they are validated using one of the following:

When using cookies you can call:

```go
// Validate the session. Will return an error if expired
if authorized, sessionToken, err := descopeClient.Auth.ValidateSessionWithRequest(r, w); !authorized {
    // unauthorized error
}

// If ValidateSessionWithRequest raises an exception, you will need to refresh the session using
if authorized, sessionToken, err := descopeClient.Auth.RefreshSessionWithRequest(r, w); !authorized {
    // unauthorized error
}

// Alternatively, you could combine the two and
// have the session validated and automatically refreshed when expired
if authorized, sessionToken, err := descopeClient.Auth.ValidateAndRefreshSessionWithRequest(r, w); !authorized {
    // unauthorized error
}
```

Alternatively, tokens can be validated directly:

```go
// Validate the session. Will return an error if expired
if authorized, sessionToken, err := descopeClient.Auth.ValidateSessionWithToken(sessionToken); !authorized {
    // unauthorized error
}

// If ValidateSessionWithRequest raises an exception, you will need to refresh the session using
if authorized, sessionToken, err := descopeClient.Auth.RefreshSessionWithToken(refreshToken); !authorized {
    // unauthorized error
}

// Alternatively, you could combine the two and
// have the session validated and automatically refreshed when expired
if authorized, sessionToken, err := descopeClient.Auth.ValidateAndRefreshSessionWithTokens(sessionToken, refreshToken); !authorized {
    // unauthorized error
}
```

Choose the right session validation and refresh combination that suits your needs.

Refreshed sessions return the same response as is returned when users first sign up / log in,
Make sure to return the session token from the response to the client if tokens are validated directly.

Usually, the tokens can be passed in and out via HTTP headers or via a cookie.
The implementation can defer according to your implementation. See our [examples](#code-examples) for a few examples.

If Roles & Permissions are used, validate them immediately after validating the session. See the [next section](#roles--permission-validation)
for more information.

#### Session Validation Using Middleware

Alternatively, you can validate the session using any supported builtin Go middleware (for example Chi or Mux)
instead of using the ValidateSessions function. This middleware will automatically detect the cookies from the
request and save the current user ID in the context for further usage. On failure, it will respond with `401 Unauthorized`.

```go
import "github.com/descope/go-sdk/descope/sdk"

// ...

r.Use(sdk.AuthenticationMiddleware(descopeClient.Auth, nil, nil))
```

### Roles & Permission Validation

When using Roles & Permission, it's important to validate the user has the required
authorization immediately after making sure the session is valid. Taking the `sessionToken`
received by the [session validation](#session-validation), call the following functions:

For multi-tenant uses:

```go
// You can validate specific permissions
if !descopeClient.Auth.ValidateTenantPermissions(sessionToken, "my-tenant-ID", []string{"Permission to validate"}) {
    // Deny access
}

// Or validate roles directly
if !descopeClient.Auth.ValidateTenantRoles(sessionToken, "my-tenant-ID", []string{"Role to validate"}) {
    // Deny access
}
```

When not using tenants use:

```go
// You can validate specific permissions
if !descopeClient.Auth.ValidatePermissions(sessionToken, []string{"Permission to validate"}) {
    // Deny access
}

// Or validate roles directly
if !descopeClient.Auth.ValidateRoles(sessionToken, []string{"Role to validate"}) {
    // Deny access
}
```

### Logging Out

You can log out a user from an active session by providing their `refreshToken` for that session.
After calling this function, you must invalidate or remove any cookies you have created. Providing
a `http.ResponseWriter` will do this automatically.

```go
// Refresh token will be taken from the request header or cookies automatically
// If provided, the optional `w http.ResponseWriter` will empty out the session cookies automatically.
descopeClient.Auth.Logout(request, w)
```

It is also possible to sign the user out of all the devices they are currently signed-in with. Calling `logoutAll` will
invalidate all user's refresh tokens. After calling this function, you must invalidate or remove any cookies you have created.

```go
// Refresh token will be taken from the request header or cookies automatically
// If provided, the optional `w http.ResponseWriter` will empty out the session cookies automatically.
descopeClient.Auth.LogoutAll(request, w)
```

## Management Functions

It is very common for some form of management or automation to be required. These can be performed
using the management functions. Please note that these actions are more sensitive as they are administrative
in nature. Please use responsibly.

### Setup

To use the management API you'll need a `Management Key` along with your `Project ID`.
Create one in the [Descope Console](https://app.descope.com/settings/company/managementkeys).

```go
import "github.com/descope/go-sdk/descope/client"

// Initialized after setting the DESCOPE_PROJECT_ID and the DESCOPE_MANAGEMENT_KEY env vars
descopeClient := client.New()

// ** Or directly **
descopeClient := client.NewWithConfig(&client.Config{
    ProjectID: "project-ID",
    ManagementKey: "management-key",
})
```

### Manage Tenants

You can create, update, delete or load tenants:

```go
// The self provisioning domains or optional. If given they'll be used to associate
// Users logging in to this tenant
err := descopeClient.Management.Tenant().Create("My Tenant", []string{"domain.com"})

// You can optionally set your own ID when creating a tenant
err := descopeClient.Management.Tenant().CreateWithID("my-custom-id", "My Tenant", []string{"domain.com"})

// Update will override all fields as is. Use carefully.
err := descopeClient.Management.Tenant().Update("my-custom-id", "My Tenant", []string{"domain.com", "another-domain.com"})

// Tenant deletion cannot be undone. Use carefully.
err := descopeClient.Management.Tenant().Delete("my-custom-id")

// Load all tenants
res, err := descopeClient.Management.Tenant().LoadAll()
if err == nil {
    for _, tenant := range res {
        // Do something
    }
}
```

### Manage Users

You can create, update, delete or load users, as well as search according to filters:

```go
// A user must have a loginID, other fields are optional.
// Roles should be set directly if no tenants exist, otherwise set
// on a per-tenant basis.
userReq := &descope.UserRequest{}
userReq.Email = "desmond@descope.com"
userReq.Name = "Desmond Copeland"
userReq.Tenants = []*descope.AssociatedTenant{
    {TenantID: "tenant-ID1", Roles: []string{"role-name1"}},
    {TenantID: "tenant-ID2"},
}
user, err := descopeClient.Management.User().Create("desmond@descope.com", userReq)

// Alternatively, a user can be created and invited via an email message.
// Make sure to configure the invite URL in the Descope console prior to using this function,
// and that an email address is provided in the information.
userReqInvite := &descope.UserRequest{}
userReqInvite.Email = "desmond@descope.com"
userReqInvite.Name = "Desmond Copeland"
userReqInvite.Tenants = []*descope.AssociatedTenant{
    {TenantID: "tenant-ID1", Roles: []string{"role-name1"}},
    {TenantID: "tenant-ID2"},
}
err := descopeClient.Management.User().Invite("desmond@descope.com", userReqInvite)

// Update will override all fields as is. Use carefully.
userReqUpdate := &descope.UserRequest{}
userReqUpdate.Email = "desmond@descope.com"
userReqUpdate.Name = "Desmond Copeland"
userReqUpdate.Tenants = []*descope.AssociatedTenant{
    {TenantID: "tenant-ID1", Roles: []string{"role-name1"}},
    {TenantID: "tenant-ID2"},
}
err := descopeClient.Management.User().Update("desmond@descope.com", userReqUpdate)

// User deletion cannot be undone. Use carefully.
err := descopeClient.Management.User().Delete("desmond@descope.com")

// Load specific user
userRes, err := descopeClient.Management.User().Load("desmond@descope.com")

// If needed, users can be loaded using their ID as well
userRes, err := descopeClient.Management.User().LoadByUserID("<user-id>")

// Search all users, optionally according to tenant and/or role filter
// Results can be paginated using the limit and page parameters
usersResp, err := descopeClient.Management.User().SearchAll(&descope.UserSearchOptions{TenantIDs: []string{"my-tenant-id"}})
if err == nil {
    for _, user := range usersResp {
        // Do something
    }
}
```

### Manage Access Keys

You can create, update, delete or load access keys, as well as search according to filters:

```go
// An access key must have a name and expireTime, other fields are optional.
// Roles should be set directly if no tenants exist, otherwise set
// on a per-tenant basis.
res, err := descopeClient.Management.AccessKey().Create("access-key-1", 0, nil, []*descope.AssociatedTenant{
    {TenantID: "tenant-ID1", RoleNames: []string{"role-name1"}},
    {TenantID: "tenant-ID2"},
})

// Load specific user
res, err := descopeClient.Management.AccessKey().Load("access-key-id")

// Search all users, optionally according to tenant and/or role filter
accessKeysResp = err := descopeClient.Management.AccessKey().SearchAll([]string{"my-tenant-id"})
if err == nil {
    for _, accessKey := range accessKeysResp {
        // Do something
    }
}

// Update will override all fields as is. Use carefully.
res, err := descopeClient.Management.AccessKey().Update("access-key-id", "updated-name")

// Access keys can be deactivated to prevent usage. This can be undone using "activate".
err := descopeClient.Management.AccessKey().Deactivate("access-key-id")

// Disabled access keys can be activated once again.
err := descopeClient.Management.AccessKey().Activate("access-key-id")

// Access key deletion cannot be undone. Use carefully.
err := descopeClient.Management.AccessKey().Delete("access-key-id")
```

### Manage SSO Setting

You can manage SSO settings and map SSO group roles and user attributes.

```go
// You can get SSO settings for a specific tenant ID
ssoSettings, err := descopeClient.Management.SSO().GetSettings("tenant-id")

// You can configure SSO settings manually by setting the required fields directly
tenantID := "tenant-id" // Which tenant this configuration is for
idpURL := "https://idp.com"
entityID := "my-idp-entity-id"
idpCert := "<your-cert-here>"
redirectURL := "https://my-app.com/handle-saml" // Global redirect URL for SSO/SAML
domain := "domain.com" // Users logging in from this domain will be logged in to this tenant
err := descopeClient.Management.SSO().ConfigureSettings(tenantID, idpURL, entityID, idpCert, redirectURL, domain)

// Alternatively, configure using an SSO metadata URL
err := descopeClient.Management.SSO().ConfigureMetadata(tenantID, "https://idp.com/my-idp-metadata")

// Map IDP groups to Descope roles, or map user attributes.
// This function overrides any previous mapping (even when empty). Use carefully.
roleMapping := []*descope.RoleMapping{
    {Groups: []string{"IDP_ADMIN"}, Role: "Tenant Admin"},
}
attributeMapping := &descope.AttributeMapping {
    Name: "IDP_NAME",
    PhoneNumber: "IDP_PHONE",
}
err := descopeClient.Management.SSO().ConfigureMapping(tenantID, roleMapping, attributeMapping)
```

Note: Certificates should have a similar structure to:

```
-----BEGIN CERTIFICATE-----
Certifcate contents
-----END CERTIFICATE-----
```

### Manage Permissions

You can create, update, delete or load permissions:

```go
// You can optionally set a description for a permission.
name := "My Permission"
description := "Optional description to briefly explain what this permission allows."
err := descopeClient.Management.Permission().create(name, description)

// Update will override all fields as is. Use carefully.
newName := "My Updated Permission"
description = "A revised description",
err := descopeClient.Management.Permission().Update(name, newName, description)

// Permission deletion cannot be undone. Use carefully.
descopeClient.Management.Permission().Delete(newName)

// Load all permissions
res, err := descopeClient.Management.Permission().LoadAll()
if err == nil {
    for _, permission := range res {
        // Do something
    }
}
```

### Manage Roles

You can create, update, delete or load roles:

```go
// You can optionally set a description and associated permission for a roles.
name := "My Role"
description := "Optional description to briefly explain what this role allows."
permissionNames := []string{"My Updated Permission"},
descopeClient.Management.Role().Create(name, description, permissionNames)

// Update will override all fields as is. Use carefully.
newName := "My Updated Role"
description = "A revised description",
permissionNames = append(permissionNames, "Another Permission")
descopeClient.Management.Role().Update(name, newName, description, permissionNames)

// Role deletion cannot be undone. Use carefully.
descopeClient.Management.Role().Delete(newName)

// Load all roles
res, err := descopeClient.Management.Role().LoadAll()
if err == nil {
    for _, permission := range res {
        // Do something
    }
}
```

### Query SSO Groups

You can query SSO groups:

```go
// Load all groups for a given tenant id
res, err := descopeClient.Management.Group().LoadAllGroups("tenant-id")
if err == nil {
    for _, group := range res {
        // Do something
    }
}

// Load all groups for the given user IDs (can be found in the user's JWT)
res, err := descopeClient.Management.Group().LoadAllGroupsForMembers("tenant-id", []string{"user-id-1", "user-id-2"}, nil)
if err == nil {
    for _, group := range res {
        // Do something
    }
}

// Load all groups for the given user's loginIDs (used for sign-in)
res, err := descopeClient.Management.Group().LoadAllGroupsForMembers("tenant-id", nil, []string{"login-id-1", "login-id-2"})
if err == nil {
    for _, group := range res {
        // Do something
    }
}

// Load all group's members by the given group id
res, err := descopeClient.Management.Group().LoadAllGroupMembers("tenant-id", "group-id")
if err == nil {
    for _, group := range res {
        // Do something with group.members
    }
}
```

### Manage Flows

You can import and export flows and screens, or the project theme:

```go
// Export the flow and it's matching screens based on the given id
res, err := descopeClient.Management.Flow().ExportFlow("sign-up")
if err == nil {
    fmt.Println(res.Flow)
    fmt.Println(res.Screens)
}

// Import the given flow and screens as the given id
res, err := descopeClient.Management.Group().ImportFlow("sign-up", flow, screens)
if err == nil {
    fmt.Println(res.Flow)
    fmt.Println(res.Screens)
}

// Export the current theme of the project
res, err := descopeClient.Management.Group().ExportTheme()
if err == nil {
    fmt.Println(res)
}

// Import the given theme to the project
res, err := descopeClient.Management.Group().ImportTheme(theme)
if err == nil {
    fmt.Println(res)
}
```

### Manage JWTs

You can add custom claims to a valid JWT.

```go
updatedJWT, err := descopeClient.Management.JWT().UpdateJWTWithCustomClaims("original-jwt", map[string]any{
    "custom-key1": "custom-value1",
    "custom-key2": "custom-value2",
})
if err != nil {
    // handle error
}
```

## Code Examples

You can find various usage examples in the [examples folder](https://github.com/descope/go-sdk/blob/main/examples).

### Setup

To run the examples, set your `Project ID` by setting the `DESCOPE_PROJECT_ID` env var or directly
in the sample code.
Find your Project ID in the [Descope console](https://app.descope.com/settings/project).

```bash
export DESCOPE_PROJECT_ID=<ProjectID>
```

### Run an example

1. Run this command in your project to build the examples.

   ```bash
   make build
   ```

2. Run a specific example

   ```bash
   # Gin web app
   make run-gin-example

   # Gorilla Mux web app
   make run-example
   ```

### Using Visual Studio Code

To run Run and Debug using Visual Studio Code "Run Example: Gorilla Mux Web App" or "Run Example: Gin Web App"

The examples run on TLS at the following URL: [https://localhost:8085](https://localhost:8085).

## Unit Testing and Data Mocks

Simplify your unit testing by using our mocks package for testing your app without the need of going out to Descope services. By that, you can simply mock responses and errors and have assertion for the incoming data of each SDK method. You can find all mocks [here](https://github.com/descope/go-sdk/blob/main/descope/tests/mocks).

Mock usage examples:

- [Authentication](https://github.com/descope/go-sdk/blob/main/descope/tests/mocks/auth/authenticationmock_test.go)
- [Management](https://github.com/descope/go-sdk/blob/main/descope/tests/mocks/mgmt/managementmock_test.go)

In the following snippet we mocked the Descope Authentication and Management SDKs, and have assertions to check the actual inputs passed to the SDK:

```go
updateJWTWithCustomClaimsCalled := false
validateSessionResponse := "test1"
updateJWTWithCustomClaimsResponse := "test2"
api := DescopeClient{
    Auth: &mocksauth.MockAuthentication{
        MockSession: mocksauth.MockSession{
            ValidateSessionResponseSuccess: false,
            ValidateSessionResponse:        &descope.Token{JWT: validateSessionResponse},
            ValidateSessionError:           descope.ErrPublicKey,
        },
    },
    Management: &mocksmgmt.MockManagement{
        MockJWT: &mocksmgmt.MockJWT{
            UpdateJWTWithCustomClaimsResponse: updateJWTWithCustomClaimsResponse,
            UpdateJWTWithCustomClaimsAssert: func(jwt string, customClaims map[string]any) {
                updateJWTWithCustomClaimsCalled = true
                assert.EqualValues(t, "some jwt", jwt)
            },
        },
    },
}
ok, info, err := api.Auth.ValidateAndRefreshSessionWithRequest(nil, nil)
assert.False(t, ok)
assert.NotEmpty(t, info)
assert.EqualValues(t, validateSessionResponse, info.JWT)
assert.ErrorIs(t, err, descope.ErrPublicKey)

res, err := api.Management.JWT().UpdateJWTWithCustomClaims("some jwt", nil)
require.NoError(t, err)
assert.True(t, updateJWTWithCustomClaimsCalled)
assert.EqualValues(t, updateJWTWithCustomClaimsResponse, res)
```

### Utils for your end to end (e2e) tests and integration tests

To ease your e2e tests, we exposed dedicated management methods,
that way, you don't need to use 3rd party messaging services in order to receive sign-in/up Emails or SMS, and avoid the need of parsing the code and token from them.

```go
// User for test can be created, this user will be able to generate code/link without
// the need of 3rd party messaging services.
// Test user must have a loginID, other fields are optional.
// Roles should be set directly if no tenants exist, otherwise set
// on a per-tenant basis.
user, err := descopeClient.Management.User().CreateTestUser("desmond@descope.com", "desmond@descope.com", "", "Desmond Copeland", nil, []*descope.AssociatedTenant{
    {TenantID: "tenant-ID1", RoleNames: []string{"role-name1"}},
    {TenantID: "tenant-ID2"},
})

// Now test user got created, and this user will be available until you delete it,
// you can use any management operation for test user CRUD.
// You can also delete all test users.
err = descopeClient.Management.User().DeleteAllTestUsers()

// OTP code can be generated for test user, for example:
code, err := descopeClient.Management.User().GenerateOTPForTestUser(descope.MethodEmail, "desmond@descope.com")
// Now you can verify the code is valid (using descopeClient.Auth.OTP().VerifyCode for example)

// Same as OTP, magic link can be generated for test user, for example:
link, err := descopeClient.Management.User().GenerateMagicLinkForTestUser(descope.MethodEmail, "desmond@descope.com", "")
// Now you can verify the link is valid (using descopeClient.Auth.MagicLink().Verify for example)

// Enchanted link can be generated for test user, for example:
link, pendingRef, err := descopeClient.Management.User().GenerateEnchantedLinkForTestUser("desmond@descope.com", "")
// Now you can verify the link is valid (using descopeClient.Auth.EnchantedLink().Verify for example)

// Note 1: The generate code/link methods, work only for test users, will not work for regular users.
// Note 2: In case of testing sign-in / sign-up methods with test users, need to make sure to generate the code prior calling the sign-in / sign-up methods (such as: descopeClient.Auth.MagicLink().SignUpOrIn)
```

# API Rate Limits

Handle API rate limits by comparing the error to the ErrRateLimitExceeded error, which includes the Info map with the key "RateLimitExceededRetryAfter." This key indicates how many seconds until the next valid API call can take place.

```go
err := descopeClient.Auth.MagicLink().SignUpOrIn(descope.MethodEmail, "desmond@descope.com", "http://myapp.com/verify-magic-link")
if err != nil {
    if errors.Is(err, descope.ErrRateLimitExceeded) {
        if rateLimitErr, ok := err.(*descope.Error); ok {
            if retryAfterSeconds, ok := rateLimitErr.Info[descope.ErrorInfoKeys.RateLimitExceededRetryAfter].(int); ok {
                // This variable indicates how many seconds until the next valid API call can take place.
            }
        }
    }
     // handle other error cases
}
```

## Learn More

To learn more please see the [Descope Documentation and API reference page](https://docs.descope.com/).

## Contact Us

If you need help you can email [Descope Support](mailto:support@descope.com)

## License

The Descope SDK for Go is licensed for use under the terms and conditions of the [MIT license Agreement](https://github.com/descope/go-sdk/blob/main/LICENSE).
