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
descopeClient, err := client.New()

// ** Or directly **
descopeClient, err := client.NewWithConfig(&client.Config{ProjectID: projectID})
```

## Authentication Functions

These sections show how to use the SDK to perform various authentication/authorization functions:

1. [OTP Authentication](#otp-authentication)
2. [Magic Link](#magic-link)
3. [Enchanted Link](#enchanted-link)
4. [OAuth](#oauth)
5. [SSO (SAML / OIDC)](#sso-saml--oidc)
6. [TOTP Authentication](#totp-authentication)
7. [Passwords](#passwords)
8. [Session Validation](#session-validation)
9. [Roles & Permission Validation](#roles--permission-validation)
10. [Tenant selection](#tenant-selection)
11. [Logging Out](#logging-out)
12. [History](#history)

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
10. [Search Audit](#search-audit)
11. [Embedded Links](#embedded-links)
12. [Manage ReBAC Authz](#manage-rebac-authz)
13. [Manage Project](#manage-project)
14. [Manage SSO Applications](#manage-sso-applications)

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
    GivenName: "Desmond",
    FamilyName: "Copeland",
    Phone: "212-555-1234",
    Email: loginID,
}
maskedAddress, err := descopeClient.Auth.OTP().SignUp(context.Background(), descope.MethodEmail, loginID, user, nil)
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
authInfo, err := descopeClient.Auth.OTP().VerifyCode(context.Background(), descope.MethodEmail, loginID, code, w)
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
maskedAddress, err := descopeClient.Auth.MagicLink().SignUpOrIn(context.Background(), descope.MethodEmail, "desmond@descope.com", "http://myapp.com/verify-magic-link", nil)
if err {
    // handle error
}
```

To verify a magic link, your redirect page must call the validation function on the token (`t`) parameter (`https://your-redirect-address.com/verify?t=<token>`):

```go
// The optional `w http.ResponseWriter` adds the session and refresh cookies to the response automatically.
// Otherwise they're available via authInfo
authInfo, err := descopeClient.Auth.MagicLink().Verify(context.Background(), token, w)
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
res, err := descopeClient.Auth.EnchantedLink().SignIn(context.Background(), loginID, "http://myapp.com/verify-enchanted-link", nil, nil)
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
    authInfo, err := descopeClient.Auth.EnchantedLink().GetSession(context.Background(), res.PendingRef, w)
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
if err := descopeClient.Auth.EnchantedLink().Verify(context.Background(), token); err != nil {
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
url, err := descopeClient.Auth.OAuth().Start(context.Background(), "google", "https://my-app.com/handle-oauth", nil, nil, w)
if err != nil {
    // handle error
}
```

The user will authenticate with the authentication provider, and will be redirected back to the redirect URL, with an appended `code` HTTP URL parameter. Exchange it to validate the user:

```go
// The optional `w http.ResponseWriter` adds the session and refresh cookies to the response automatically.
// Otherwise they're available via authInfo
authInfo, err := descopeClient.Auth.OAuth().ExchangeToken(context.Background(), code, w)
if err != nil {
    // handle error
}
```

The session and refresh JWTs should be returned to the caller, and passed with every request in the session. Read more on [session validation](#session-validation)

### SSO (SAML / OIDC)

Users can authenticate to a specific tenant using SAML or OIDC. Configure your SSO (SAML / OIDC) settings on the [Descope console](https://app.descope.com/settings/authentication/sso). To start a flow call:

```go
// Choose which tenant to log into
// If configured globally, the return URL is optional. If provided however, it will be used
// instead of any global configuration.
// Redirect the user to the returned URL to start the SSO SAML/OIDC redirect chain
url, err := descopeClient.Auth.SSO().Start("my-tenant-ID", "https://my-app.com/handle-saml", nil, nil, w)
if err != nil {
    // handle error
}
```


```go
//* Deprecated (use Auth.SSO().Start(..) instead) *//
//
// Choose which tenant to log into
// If configured globally, the return URL is optional. If provided however, it will be used
// instead of any global configuration.
// Redirect the user to the returned URL to start the SSO/SAML redirect chain
url, err := descopeClient.Auth.SAML().Start(context.Background(), "my-tenant-ID", "https://my-app.com/handle-saml", nil, nil, w)
if err != nil {
    // handle error
}
```

The user will authenticate with the authentication provider configured for that tenant, and will be redirected back to the redirect URL, with an appended `code` HTTP URL parameter. Exchange it to validate the user:

```go
// The optional `w http.ResponseWriter` adds the session and refresh cookies to the response automatically.
// Otherwise they're available via authInfo
authInfo, err := descopeClient.Auth.SSO().ExchangeToken(context.Background(), code, w)
if err != nil {
    // handle error
}
```

```go
//* Deprecated (use Auth.SSO().ExchangeToken(..) instead) *//
//
// The optional `w http.ResponseWriter` adds the session and refresh cookies to the response automatically.
// Otherwise they're available via authInfo
authInfo, err := descopeClient.Auth.SAML().ExchangeToken(context.Background(), code, w)
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
    GivenName: "Desmond",
    FamilyName: "Copeland",
    Phone: "212-555-1234",
    Email: loginID,
}
totpResponse, err := descopeClient.Auth.TOTP().SignUp(context.Background(), loginID, user)
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
authInfo, err := descopeClient.Auth.TOTP().SignInCode(context.Background(), loginID, code, nil, nil, w)
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
    GivenName: "Desmond",
    FamilyName: "Copeland",
    Email: loginID,
}
authInfo, err := descopeClient.Auth.Password().SignUp(context.Background(), loginID, user, password, nil)
if err != nil {
    // handle error
}
```

The user can later sign in using the same loginID and password.

```go
// The optional `w http.ResponseWriter` adds the session and refresh cookies to the response automatically.
// Otherwise they're available via authInfo
authInfo, err := descopeClient.Auth.Password().SignIn(context.Background(), loginID, password, w)
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
err := descopeClient.Auth.Password().SendPasswordReset(context.Background(), loginID, redirectURL, nil)
```

The magic link, in this case, must then be verified like any other magic link (see the [magic link section](#magic-link) for more details). However, after verifying the user, it is expected
to allow them to provide a new password instead of the old one. Since the user is now authenticated, this is possible via:

```go
// The request (r) is required to make sure the user is authenticated.
err := descopeClient.Auth.Password().UpdateUserPassword(context.Background(), loginID, newPassword, r)
```

`UpdateUserPassword` can always be called when the user is authenticated and has a valid session.

Alternatively, it is also possible to replace an existing active password with a new one.

```go
// Replaces the user's current password with a new one
authInfo, err := descopeClient.Auth.Password().ReplaceUserPassword(context.Background(), loginID, oldPassword, newPassword, w)
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
if authorized, sessionToken, err := descopeClient.Auth.ValidateSessionWithToken(context.Background(), sessionToken); !authorized {
    // unauthorized error
}

// If ValidateSessionWithRequest raises an exception, you will need to refresh the session using
if authorized, sessionToken, err := descopeClient.Auth.RefreshSessionWithToken(context.Background(), refreshToken); !authorized {
    // unauthorized error
}

// Alternatively, you could combine the two and
// have the session validated and automatically refreshed when expired
if authorized, sessionToken, err := descopeClient.Auth.ValidateAndRefreshSessionWithTokens(context.Background(), sessionToken, refreshToken); !authorized {
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
if !descopeClient.Auth.ValidateTenantPermissions(context.Background(), sessionToken, "my-tenant-ID", []string{"Permission to validate"}) {
    // Deny access
}

// Or validate roles directly
if !descopeClient.Auth.ValidateTenantRoles(context.Background(), sessionToken, "my-tenant-ID", []string{"Role to validate"}) {
    // Deny access
}

matchedTenantRoles := descopeClient.Auth.GetTenantRoles(context.Background(), sessionToken, "my-tenant-ID", []string{"role-name1", "role-name2"})

matchedTenantPermissions := descopeClient.Auth.GetTenantPermissions(context.Background(), sessionToken, "my-tenant-ID", []string{"permission-name1", "permission-name2"})
```

When not using tenants use:

```go
// You can validate specific permissions
if !descopeClient.Auth.ValidatePermissions(context.Background(), sessionToken, []string{"Permission to validate"}) {
    // Deny access
}

// Or validate roles directly
if !descopeClient.Auth.ValidateRoles(context.Background(), sessionToken, []string{"Role to validate"}) {
    // Deny access
}

// Or get the matched roles/permissions
matchedRoles := descopeClient.Auth.GetMatchedRoles(context.Background(), sessionToken, []string{"role-name1", "role-name2"})

matchedPermissions := descopeClient.Auth.GetMatchedPermissions(context.Background(), sessionToken, []string{"permission-name1", "permission-name2"})
```

### Tenant selection

For a user that has permissions to multiple tenants, you can set a specific tenant as the current selected one
This will add an extra attribute to the refresh JWT and the session JWT with the selected tenant ID

```go
tenantID := "t1"
info, err := descopeClient.Auth.SelectTenantWithRequest(context.Background(), tenantID, r, w)
if err != nil {
    // failed to select a tenant
}
```

Or alternatively, work directly with refresh token

```go
tenantID := "t1"
refreshToken := "<a valid refresh token>"
info, err := descopeClient.Auth.SelectTenantWithToken(context.Background(), tenantID, refreshToken)
if err != nil {
    // failed to select a tenant
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

### History

You can get the current session user history.
The request requires a valid refresh token.

```go
// Refresh token will be taken from the request header or cookies automatically
loginHistoryRes, err := descopeClient.Auth.History(request, r)
if err == nil {
    for i := range loginHistoryRes {
        fmt.Println(loginHistoryRes[i].UserID)
        fmt.Println(loginHistoryRes[i].City)
        fmt.Println(loginHistoryRes[i].Country)
        fmt.Println(loginHistoryRes[i].IP)
        fmt.Println(loginHistoryRes[i].LoginTime)
    }
}
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
descopeClient, err := client.New()

// ** Or directly **
descopeClient, err := client.NewWithConfig(&client.Config{
    ProjectID: "project-ID",
    ManagementKey: "management-key",
})
```

### Manage Tenants

You can create, update, delete or load tenants:

```go
// The self provisioning domains or optional. If given they'll be used to associate
// Users logging in to this tenant

// Creating and updating tenants takes the &descope.TenantRequest type. This is an example of a &descope.TenantRequest
tenantRequest := &descope.TenantRequest{}
tenantRequest.Name = []string{"My Tenant"}
tenantRequest.SelfProvisioningDomains = []string{"domain.com"}
tenantRequest.CustomAttributes = map[string]any{"mycustomattribute": "Test"}

// Create tenant
err := descopeClient.Management.Tenant().Create(context.Background(), "My Tenant", tenantRequest)

// You can optionally set your own ID when creating a tenant
err := descopeClient.Management.Tenant().CreateWithID(context.Background(), "my-custom-id", "My Tenant", tenantRequest)

// Update will override all fields as is. Use carefully.
err := descopeClient.Management.Tenant().Update(context.Background(), "my-custom-id", "My Tenant", tenantRequest)

// Tenant deletion cannot be undone. Use carefully.
err := descopeClient.Management.Tenant().Delete(context.Background(), "my-custom-id")

// Load tenant by id
tenant, err := descopeClient.Management.Tenant().Load(context.Background(), "my-custom-id")

// Load all tenants
res, err := descopeClient.Management.Tenant().LoadAll(context.Background())
if err == nil {
    for _, tenant := range res {
        // Do something
    }
}

// Search tenants - takes the &descope.TenantSearchOptions type. This is an example of a &descope.TenantSearchOptions
searchOptions := &descope.TenantSearchOptions{}
searchOptions.IDs = []string{"my-custom-id"}
searchOptions.Names = []string{"My Tenant"}
searchOptions.SelfProvisioningDomains = []string{"domain.com", "company.com"}
searchOptions.CustomAttributes = map[string]any{"mycustomattribute": "Test"}
res, err := descopeClient.Management.Tenant().SearchAll(context.Background(), searchOptions)
if err == nil {
  for _, tenant := range res {
        // Do something
    }
}

// Load tenant settings by a tenant id
settings, err := descopeClient.Management.Tenant().GetSettings(context.Background())

settingsRequest := &descope.TenantSettings{}
settingsRequest.SelfProvisioningDomains = []string{"domain.com", "company.com"}
settingsRequest.RefreshTokenExpiration = 30
settingsRequest.RefreshTokenExpirationUnit = "days"
settingsRequest.SessionTokenExpiration = 30
settingsRequest.SessionTokenExpirationUnit = "minutes"
settingsRequest.EnableInactivity = true
settingsRequest.InactivityTime = 2
settingsRequest.InactivityTimeUnit = "days"

// update the tenant settings
err := descopeClient.Management.Tenant().ConfigureSettings(context.Background(), "My Tenant", settingsRequest)

```

### Manage Users

You can create, update, delete, logout, get user history and load users, as well as search according to filters:

```go
// A user must have a loginID, other fields are optional.
// Roles should be set directly if no tenants exist, otherwise set
// on a per-tenant basis.
userReq := &descope.UserRequest{}
userReq.Email = "desmond@descope.com"
userReq.Name = "Desmond Copeland"
userReq.GivenName = "Desmond"
userReq.FamilyName = "Copeland"
userReq.Tenants = []*descope.AssociatedTenant{
    {TenantID: "tenant-ID1", Roles: []string{"role-name1"}},
    {TenantID: "tenant-ID2"},
}
userReq.SSOAppIDs = []string{"appId1", "appId2"}
user, err := descopeClient.Management.User().Create(context.Background(), "desmond@descope.com", userReq)

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
userReqInvite.SSOAppIDs = []string{"appId1", "appId2"}
// options can be nil, and in this case, value will be taken from project settings page
options := &descope.InviteOptions{InviteURL: "https://sub.domain.com"}
err := descopeClient.Management.User().Invite(context.Background(), "desmond@descope.com", userReqInvite, options)

// Invite multiple users with InviteBatch
options := &descope.InviteOptions{InviteURL: "https://sub.domain.com"}
batchUsers := []*descope.BatchUser{}
u1 := &descope.BatchUser{}
u1.LoginID = "one"
u1.Email = "one@one.com"
u1.Roles = []string{"one"}
u1.SSOAppIDs = []string{"appId1", "appId2"}

u2 := &descope.BatchUser{}
u2.LoginID = "two"
u2.Email = "two@two.com"
u2.Roles = []string{"two"}

batchUsers = append(batchUsers, u1, u2)
users, err := descopeClient.Management.User().InviteBatch(context.Background(), batchUsers, options)

// Import users from another service by calling CreateBatch with each user's password hash
user := &descope.BatchUser{
    LoginID: "desmond@descope.com",
    Password: &descope.BatchUserPassword{
        Hashed: &descope.BatchUserPasswordHashed{
            Bcrypt: &descope.BatchUserPasswordBcrypt{
                Hash: "$2a$...",
            },
        },
    },
}
users, err := descopeClient.Management.User().CreateBatch(context.Background(), []*descope.BatchUser{user})

// Update will override all fields as is. Use carefully.
userReqUpdate := &descope.UserRequest{}
userReqUpdate.Email = "desmond@descope.com"
userReqUpdate.Name = "Desmond Copeland"
userReqUpdate.Tenants = []*descope.AssociatedTenant{
    {TenantID: "tenant-ID1", Roles: []string{"role-name1"}},
    {TenantID: "tenant-ID2"},
}
userReqUpdate.SSOAppIDs = []string{"appId3"}
err := descopeClient.Management.User().Update(context.Background(), "desmond@descope.com", userReqUpdate)

// Update loginID of a user, or remove a login ID (last login ID cannot be removed)
err := descopeClient.Management.User().UpdateLoginID(context.Background(), "desmond@descope.com", "bane@descope.com")

// Associate SSO application for a user.
user, err := descopeClient.Management.User().AddSSOApps(context.Background(), "desmond@descope.com",[]string{"appId1"})

// Set (associate) SSO application for a user.
user, err := descopeClient.Management.User().SetSSOApps(context.Background(), "desmond@descope.com",[]string{"appId1", "appId2"})

// Remove SSO application association from a user.
user, err := descopeClient.Management.User().RemoveSSOApps(context.Background(), "desmond@descope.com",[]string{"appId2"})

// User deletion cannot be undone. Use carefully.
err := descopeClient.Management.User().Delete(context.Background(), "desmond@descope.com")

// Load specific user
userRes, err := descopeClient.Management.User().Load(context.Background(), "desmond@descope.com")

// If needed, users can be loaded using their ID as well
userRes, err := descopeClient.Management.User().LoadByUserID(context.Background(), "<user-id>")

// Search all users, optionally according to tenant and/or role filter
// Results can be paginated using the limit and page parameters
usersResp, err := descopeClient.Management.User().SearchAll(context.Background(), &descope.UserSearchOptions{TenantIDs: []string{"my-tenant-id"}})
if err == nil {
    for _, user := range usersResp {
        // Do something
    }
}

// Logout given user from all its devices, by login ID
err := descopeClient.Management.User().LogoutUser(context.Background(), "<login id>")

// Logout given user from all its devices, by user ID
err := descopeClient.Management.User().LogoutUserByUserID(context.Background(), "<user id>")

// Get users' authentication history
loginHistoryRes, err := descopeClient.Management.User().History(context.Background(), []string{"<user id 1>", "<user id 2>"})
if err == nil {
    for i := range loginHistoryRes {
        fmt.Println(loginHistoryRes[i].UserID)
        fmt.Println(loginHistoryRes[i].City)
        fmt.Println(loginHistoryRes[i].Country)
        fmt.Println(loginHistoryRes[i].IP)
        fmt.Println(loginHistoryRes[i].LoginTime)
    }
}
```

#### Set or Expire User Password

You can set (temporary/active) or expire a user's password.
Note: When using SetTemporaryPassword password will automatically be set as expired.
The user will not be able log-in using an expired password, and will be required replace it on next login.

```go
// Set a user's temporary password
err := descopeClient.Management.User().SetTemporaryPassword(context.Background(), "<login-id>", "<some-password>")

// Set a user's password
err := descopeClient.Management.User().SetActivePassword(context.Background(), "<login-id>", "<some-password>")

// Or alternatively, expire a user password
err := descopeClient.Management.User().ExpirePassword(context.Background(), "<login-id>")

// Later, if the user is signing in with an expired password, the returned error will be ErrPasswordExpired
authInfo, err := descopeClient.Auth.Password().SignIn(context.Background(), "<login-id>", "<some-password>", w)
if err != nil {
     if errors.Is(err, descope.ErrPasswordExpired) {
        // Handle a case when the error is expired, the user should replace/reset the password
        // Use descopeClient.Auth.Password().ReplaceUserPassword(context.Background(), "<login-id>", "<some-password>", "<new-password>", w)
     }
     // Handle other errors
}
```

### Manage Access Keys

You can create, update, delete or load access keys, as well as search according to filters:

```go
// An access key must have a name and expireTime, other fields are optional.
// Roles should be set directly if no tenants exist, otherwise set
// on a per-tenant basis.
// If userID is supplied, then authorization would be ignored, and access key would be bound to the users authorization
res, err := descopeClient.Management.AccessKey().Create(context.Background(), "access-key-1", 0, nil, []*descope.AssociatedTenant{
    {TenantID: "tenant-ID1", RoleNames: []string{"role-name1"}},
    {TenantID: "tenant-ID2"},
}, "")

// Load specific user
res, err := descopeClient.Management.AccessKey().Load(context.Background(), "access-key-id")

// Search all users, optionally according to tenant and/or role filter
accessKeysResp = err := descopeClient.Management.AccessKey().SearchAll(context.Background(), []string{"my-tenant-id"})
if err == nil {
    for _, accessKey := range accessKeysResp {
        // Do something
    }
}

// Update will override all fields as is. Use carefully.
res, err := descopeClient.Management.AccessKey().Update(context.Background(), "access-key-id", "updated-name")

// Access keys can be deactivated to prevent usage. This can be undone using "activate".
err := descopeClient.Management.AccessKey().Deactivate(context.Background(), "access-key-id")

// Disabled access keys can be activated once again.
err := descopeClient.Management.AccessKey().Activate(context.Background(), "access-key-id")

// Access key deletion cannot be undone. Use carefully.
err := descopeClient.Management.AccessKey().Delete(context.Background(), "access-key-id")
```

### Manage SSO Setting

You can manage SSO (SAML or OIDC) settings for a specific tenant.

```go
// Load all tenant SSO settings
ssoSettings, err := cc.HC.DescopeClient().Management.SSO().LoadSettings(context.Background(), "tenant-id")

//* Deprecated (use LoadSettings(..) instead) *//
ssoSettings, err := descopeClient.Management.SSO().GetSettings(context.Background(), "tenant-id")

// Configure tenant SSO by OIDC settings

oidcSettings := &descope.SSOOIDCSettings{..}
err = cc.HC.DescopeClient().Management.SSO().ConfigureOIDCSettings("tenant-id", oidcSettings, "")
// OR
// Load all tenant SSO settings and use them for configure OIDC settings
ssoSettings, err := cc.HC.DescopeClient().Management.SSO().LoadSettings("tenant-id")
ssoSettings.Oidc.Name = "my prOvider"
ssoSettings.Oidc.AuthURL = authorizeEndpoint
...
ssoSettings.Oidc.Scope = []string{"openid", "profile", "email"}
err = cc.HC.DescopeClient().Management.SSO().ConfigureOIDCSettings("tenant-id", ssoSettings.Oidc, "")

// Configure tenant SSO by SAML settings
tenantID := "tenant-id" // Which tenant this configuration is for
idpURL := "https://idp.com"
entityID := "my-idp-entity-id"
idpCert := "<your-cert-here>"
redirectURL := "https://my-app.com/handle-saml" // Global redirect URL for SSO/SAML
domain := "domain.com" // Users logging in from this domain will be logged in to this tenant
samlSettings := &descope.SSOSAMLSettings{
	IdpURL: idpURL,
	IdpEntityID: entityID,
	IdpCert: idpCert,
	AttributeMapping: &descope.AttributeMapping{Email: "myEmail", ..},
	RoleMappings: []*RoleMapping{{..}},
}
err = cc.HC.DescopeClient().Management.SSO().ConfigureSAMLSettings(context.Background(), tenantID, samlSettings, redirectURL, domain)

//* Deprecated (use ConfigureSAMLSettings(..) instead) *//
err := descopeClient.Management.SSO().ConfigureSettings(context.Background(), tenantID, idpURL, entityID, idpCert, redirectURL, domain)

// Alternatively, configure using an SSO SAML metadata URL
samlSettings := &descope.SSOSAMLSettingsByMetadata{
	IdpMetadataURL: "https://idp.com/my-idp-metadata",
	AttributeMapping: &descope.AttributeMapping{Email: "myEmail", ..},
	RoleMappings: []*RoleMapping{{..}},
}
err = cc.HC.DescopeClient().Management.SSO().ConfigureSAMLSettingsByMetadata(context.Background(), tenantID, samlSettings, redirectURL, domain)

//* Deprecated (use ConfigureSAMLSettingsByMetadata(..) instead) *//
err := descopeClient.Management.SSO().ConfigureMetadata(tenantID, "https://idp.com/my-idp-metadata", redirectURL, domain)

//* Deprecated (use Management.SSO().ConfigureSAMLSettings(..) or Management.SSO().ConfigureSAMLSettingsByMetadata(..) instead) *//
// Map IDP groups to Descope roles, or map user attributes.
// This function overrides any previous mapping (even when empty). Use carefully.
roleMapping := []*descope.RoleMapping{
    {Groups: []string{"IDP_ADMIN"}, Role: "Tenant Admin"},
}
attributeMapping := &descope.AttributeMapping {
    Name: "IDP_NAME",
    PhoneNumber: "IDP_PHONE",
}
err := descopeClient.Management.SSO().ConfigureMapping(context.Background(), tenantID, roleMapping, attributeMapping)

// To delete SSO settings, call the following method
err := descopeClient.Management.SSO().DeleteSettings(context.Background(), "tenant-id")
```

Note: Certificates should have a similar structure to:

```
-----BEGIN CERTIFICATE-----
Certifcate contents
-----END CERTIFICATE-----
```

### Manage Password Setting

You can manage password settings for tenants and projects.

```go
// You can get password settings for a specific tenant ID. Tenant ID is required.
settings, err := descopeClient.Management.Password().GetSettings(context.Background(), "tenant-id")

// You can configure password settings by setting the required fields directly and provide the tenant ID to update.
tenantID := "tenant-id" // Which tenant this configuration is for
settingsToUpdate := &descope.PasswordSettings{
    Enabled:               true,
    MinLength:             8,
    Lowercase:             true,
    Uppercase:             true,
    Number:                true,
    NonAlphanumeric:       true,
    Expiration:            true,
    ExpirationWeeks:       3,
    Reuse:                 true,
    ReuseAmount:           3,
    Lock:                  true,
    LockAttempts:          5,
}
err := descopeClient.Management.Password().ConfigureSettings(context.Background(), tenantID, settingsToUpdate)
```

### Manage Permissions

You can create, update, delete or load permissions:

```go
// You can optionally set a description for a permission.
name := "My Permission"
description := "Optional description to briefly explain what this permission allows."
err := descopeClient.Management.Permission().Create(context.Background(), name, description)

// Update will override all fields as is. Use carefully.
newName := "My Updated Permission"
description = "A revised description",
err := descopeClient.Management.Permission().Update(context.Background(), name, newName, description)

// Permission deletion cannot be undone. Use carefully.
descopeClient.Management.Permission().Delete(context.Background(), newName)

// Load all permissions
res, err := descopeClient.Management.Permission().LoadAll(context.Background())
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
tenantID := "" // set here tenant ID value in order to create a role for a specific tenant
descopeClient.Management.Role().Create(context.Background(), name, description, permissionNames, tenantID)

// Update will override all fields as is. Use carefully.
newName := "My Updated Role"
description = "A revised description",
permissionNames = append(permissionNames, "Another Permission")
descopeClient.Management.Role().Update(context.Background(), name, tenantID, newName, description, permissionNames)

// Role deletion cannot be undone. Use carefully.
descopeClient.Management.Role().Delete(context.Background(), newName, tenantID)

// Load all roles
res, err := descopeClient.Management.Role().LoadAll(context.Background())
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
res, err := descopeClient.Management.Group().LoadAllGroups(context.Background(), "tenant-id")
if err == nil {
    for _, group := range res {
        // Do something
    }
}

// Load all groups for the given user IDs (can be found in the user's JWT)
res, err := descopeClient.Management.Group().LoadAllGroupsForMembers(context.Background(), "tenant-id", []string{"user-id-1", "user-id-2"}, nil)
if err == nil {
    for _, group := range res {
        // Do something
    }
}

// Load all groups for the given user's loginIDs (used for sign-in)
res, err := descopeClient.Management.Group().LoadAllGroupsForMembers(context.Background(), "tenant-id", nil, []string{"login-id-1", "login-id-2"})
if err == nil {
    for _, group := range res {
        // Do something
    }
}

// Load all group's members by the given group id
res, err := descopeClient.Management.Group().LoadAllGroupMembers(context.Background(), "tenant-id", "group-id")
if err == nil {
    for _, group := range res {
        // Do something with group.members
    }
}
```

### Manage Flows

You can list, import and export flows and screens, or the project theme:

```go
// List all your flows
res, err := descopeClient.Management.Flow().ListFlows(context.Background())
if err == nil {
    fmt.Println(res.Total)
    fmt.Println(res.Flows[0].ID)
}

// Delete flows by ids
err := descopeClient.Management.Flow().DeleteFlows(context.Background(), []string{"flow-1", "flow-2"})

// Export the flow and it's matching screens based on the given id
res, err := descopeClient.Management.Flow().ExportFlow(context.Background(), "sign-up")
if err == nil {
    fmt.Println(res.Flow)
    fmt.Println(res.Screens)
}

// Import the given flow and screens as the given id
res, err := descopeClient.Management.Group().ImportFlow(context.Background(), "sign-up", flow, screens)
if err == nil {
    fmt.Println(res.Flow)
    fmt.Println(res.Screens)
}

// Export the current theme of the project
res, err := descopeClient.Management.Group().ExportTheme(context.Background())
if err == nil {
    fmt.Println(res)
}

// Import the given theme to the project
res, err := descopeClient.Management.Group().ImportTheme(context.Background(), theme)
if err == nil {
    fmt.Println(res)
}
```

### Manage JWTs

You can add custom claims to a valid JWT.

```go
updatedJWT, err := descopeClient.Management.JWT().UpdateJWTWithCustomClaims(context.Background(), "original-jwt", map[string]any{
    "custom-key1": "custom-value1",
    "custom-key2": "custom-value2",
})
if err != nil {
    // handle error
}
```

### Embedded links

```go
// Embedded links can be created to directly receive a verifiable token without sending it.
// This token can then be verified using the magic link 'verify' function, either directly or through a flow.
token, err := descopeClient.Management.User().GenerateEmbeddedLink(context.Background(), "desmond@descope.com", map[string]any{"key1":"value1"})
```

### Search Audit

You can perform an audit search for either specific values or full-text across the fields. Audit search is limited to the last 30 days.

```go
// Full text search on the last 10 days
res, err := descopeClient.Management.Audit().Search(context.Background(), &descope.AuditSearchOptions{From: time.Now().AddDate(0, 0, -10), Text: "some-text"})
if err == nil {
    fmt.Println(res)
}

// Search successful logins in the last 30 days
res, err := descopeClient.Management.Audit().Search(context.Background(), &descope.AuditSearchOptions{Actions: []string{"LoginSucceed"}})
if err == nil {
    fmt.Println(res)
}
```

### Manage ReBAC Authz

Descope supports full relation based access control (ReBAC) using a zanzibar like schema and operations.
A schema is comprized of namespaces (entities like documents, folders, orgs, etc.) and each namespace has relation definitions to define relations.
Each relation definition can be simple (either you have it or not) or complex (union of nodes).

A simple example for a file system like schema would be:

```yaml
# Example schema for the authz tests
name: Files
namespaces:
  - name: org
    relationDefinitions:
      - name: parent
      - name: member
        complexDefinition:
          nType: union
          children:
            - nType: child
              expression:
                neType: self
            - nType: child
              expression:
                neType: relationLeft
                relationDefinition: parent
                relationDefinitionNamespace: org
                targetRelationDefinition: member
                targetRelationDefinitionNamespace: org
  - name: folder
    relationDefinitions:
      - name: parent
      - name: owner
        complexDefinition:
          nType: union
          children:
            - nType: child
              expression:
                neType: self
            - nType: child
              expression:
                neType: relationRight
                relationDefinition: parent
                relationDefinitionNamespace: folder
                targetRelationDefinition: owner
                targetRelationDefinitionNamespace: folder
      - name: editor
        complexDefinition:
          nType: union
          children:
            - nType: child
              expression:
                neType: self
            - nType: child
              expression:
                neType: relationRight
                relationDefinition: parent
                relationDefinitionNamespace: folder
                targetRelationDefinition: editor
                targetRelationDefinitionNamespace: folder
            - nType: child
              expression:
                neType: targetSet
                targetRelationDefinition: owner
                targetRelationDefinitionNamespace: folder
      - name: viewer
        complexDefinition:
          nType: union
          children:
            - nType: child
              expression:
                neType: self
            - nType: child
              expression:
                neType: relationRight
                relationDefinition: parent
                relationDefinitionNamespace: folder
                targetRelationDefinition: viewer
                targetRelationDefinitionNamespace: folder
            - nType: child
              expression:
                neType: targetSet
                targetRelationDefinition: editor
                targetRelationDefinitionNamespace: folder
  - name: doc
    relationDefinitions:
      - name: parent
      - name: owner
        complexDefinition:
          nType: union
          children:
            - nType: child
              expression:
                neType: self
            - nType: child
              expression:
                neType: relationRight
                relationDefinition: parent
                relationDefinitionNamespace: doc
                targetRelationDefinition: owner
                targetRelationDefinitionNamespace: folder
      - name: editor
        complexDefinition:
          nType: union
          children:
            - nType: child
              expression:
                neType: self
            - nType: child
              expression:
                neType: relationRight
                relationDefinition: parent
                relationDefinitionNamespace: doc
                targetRelationDefinition: editor
                targetRelationDefinitionNamespace: folder
            - nType: child
              expression:
                neType: targetSet
                targetRelationDefinition: owner
                targetRelationDefinitionNamespace: doc
      - name: viewer
        complexDefinition:
          nType: union
          children:
            - nType: child
              expression:
                neType: self
            - nType: child
              expression:
                neType: relationRight
                relationDefinition: parent
                relationDefinitionNamespace: doc
                targetRelationDefinition: viewer
                targetRelationDefinitionNamespace: folder
            - nType: child
              expression:
                neType: targetSet
                targetRelationDefinition: editor
                targetRelationDefinitionNamespace: doc
```

Descope SDK allows you to fully manage the schema and relations as well as perform simple (and not so simple) checks regarding the existence of relations.

```go
// Load the existing schema
schema, err := descopeClient.Management.Authz().LoadSchema(context.Background())
if err != nil {
    // handle error
}

// Save schema and make sure to remove all namespaces not listed
err := descopeClient.Management.Authz().SaveSchema(context.Background(), schema, true)

// Create a relation between a resource and user
err := descopeClient.Management.Authz().CreateRelations(context.Background(), []*descope.AuthzRelation {
    {
        resource: "some-doc",
        relationDefinition: "owner",
        namespace: "doc",
        target: "u1",
    },
})

// Check if target has the relevant relation
// The answer should be true because an owner is also a viewer
relations, err := descopeClient.Management.Authz().HasRelations(context.Background(), []*descope.AuthzRelationQuery{
    {
        resource: "some-doc",
        relationDefinition: "viewer",
        namespace: "doc",
        target: "u1",
    }
})
```

### Manage Project

You can update project name, as well as to clone the current project to a new one:

```go

// Update project name
descopeClient.Management.Project().UpdateName(context.Background(), "new-project-name")

// Clone the current project to a new one
// Note that this action is supported only with a pro license or above.
res, err := descopeClient.Management.Project().Clone(context.Background(), "new-project-name", "")
if err == nil {
		fmt.Println(cloneRes)
}

// Delete the current project. Kindly note that following calls on the `descopeClient` are most likely to fail because the current project has been deleted 
err := descopeClient.Management.Project().Delete(context.Background())
```

### Manage SSO Applications

You can create, update, delete or load sso applications:

```go
// Create OIDC SSO application
req := &descope.OIDCApplicationRequest{Name: "My OIDC App", Enabled: true, LoginPageURL: "http://dummy.com"}
appID, err = descopeClient.Management.SSOApplication().CreateOIDCApplication(context.Background(), req)

//Create SAML SSO application
req := &descope.SAMLApplicationRequest{
	ID:               samlAppID,
	Name:             "samlApp",
	Enabled:          true,
	LoginPageURL:     "http://dummy.com",
	EntityID:         "eId11",
	AcsURL:           "http://dummy.com/acs",
	Certificate:      "cert",
	AttributeMapping: []descope.SAMLIDPAttributeMappingInfo{{Name: "attrName1", Type: "attrType1", Value: "attrValue1"}},
	GroupsMapping: []descope.SAMLIDPGroupsMappingInfo{
		{
			Name:       "grpName1",
			Type:       "grpType1",
			FilterType: "grpFilterType1",
			Value:      "grpValue1",
			Roles:      []descope.SAMLIDPRoleGroupMappingInfo{{ID: "rl1", Name: "rlName1"}},
		},
	},
}
appID, err = descopeClient.Management.SSOApplication().CreateSAMLApplication(context.Background(), req)

// Update OIDC SSO application
// Update will override all fields as is. Use carefully.
err = tc.DescopeClient().Management.SSOApplication().UpdateOIDCApplication(context.TODO(), 
	&descope.OIDCApplicationRequest{ID: oidcAppID, Name: "oidcNewAppName"
})

// Update SAML SSO application
// Update will override all fields as is. Use carefully.
req = &descope.SAMLApplicationRequest{
	ID: samlAppID, Name: "samlNewAppName",
	Enabled:      false,
	LoginPageURL: "http://dummyyyy.com",
	EntityID:     "eId22",
	AcsURL:       "http://dummy.com/acs",
	Certificate:  "cert",
}
err = tc.DescopeClient().Management.SSOApplication().UpdateSAMLApplication(context.Background(), req)

// Load SSO application by id
app, err = tc.DescopeClient().Management.SSOApplication().Load(context.Background(), "appId")

// Load all SSO applications
apps, err = tc.DescopeClient().Management.SSOApplication().LoadAll(context.Background())

// SSO application deletion cannot be undone. Use carefully.
descopeClient.DescopeClient().Management.SSOApplication().Delete(context.Background(), "appId")
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
user, err := descopeClient.Management.User().CreateTestUser(context.Background(), "desmond@descope.com", "desmond@descope.com", "", "Desmond Copeland", nil, []*descope.AssociatedTenant{
    {TenantID: "tenant-ID1", RoleNames: []string{"role-name1"}},
    {TenantID: "tenant-ID2"},
})

// Now test user got created, and this user will be available until you delete it,
// you can use any management operation for test user CRUD.
// You can also delete all test users.
err = descopeClient.Management.User().DeleteAllTestUsers(context.Background())

// OTP code can be generated for test user, for example:
code, err := descopeClient.Management.User().GenerateOTPForTestUser(context.Background(), descope.MethodEmail, "desmond@descope.com", nil)
// Now you can verify the code is valid (using descopeClient.Auth.OTP().VerifyCode for example)

// Same as OTP, magic link can be generated for test user, for example:
link, err := descopeClient.Management.User().GenerateMagicLinkForTestUser(context.Background(), descope.MethodEmail, "desmond@descope.com", "", nil)
// Now you can verify the link is valid (using descopeClient.Auth.MagicLink().Verify for example)

// Enchanted link can be generated for test user, for example:
link, pendingRef, err := descopeClient.Management.User().GenerateEnchantedLinkForTestUser(context.Background(), "desmond@descope.com", "", nil)
// Now you can verify the link is valid (using descopeClient.Auth.EnchantedLink().Verify for example)
// *descope.LoginOptions can be provided to provide custom claims to the generated jwt.

// Note 1: The generate code/link methods, work only for test users, will not work for regular users.
// Note 2: In case of testing sign-in / sign-up methods with test users, need to make sure to generate the code prior calling the sign-in / sign-up methods (such as: descopeClient.Auth.MagicLink().SignUpOrIn)

```

# API Rate Limits

Handle API rate limits by comparing the error to the ErrRateLimitExceeded error, which includes the Info map with the key "RateLimitExceededRetryAfter." This key indicates how many seconds until the next valid API call can take place.

```go
err := descopeClient.Auth.MagicLink().SignUpOrIn(context.Background(), descope.MethodEmail, "desmond@descope.com", "http://myapp.com/verify-magic-link", nil)
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
