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
import "github.com/descope/go-sdk/descope"

// Initialized after setting the DESCOPE_PROJECT_ID env var
descopeClient := descope.NewDescopeClient()

// ** Or directly **
descopeClient := descope.NewDescopeClientWithConfig(&descope.Config{ProjectID: projectID})
```

## Usage

Here are some examples how to manage and authenticate users:

### OTP Authentication

Send a user a one-time password (OTP) using your preferred delivery method (_email / SMS_). An email address or phone number must be provided accordingly.

The user can either `sign up`, `sign in` or `sign up or in`

```go
import (
    "github.com/descope/go-sdk/descope"
    "github.com/descope/go-sdk/descope/auth"
)

// Every user must have an identifier. All other user information is optional
identifier := "desmond@descope.com"
user :=  &auth.User{
    Name: "Desmond Copeland",
    Phone: "212-555-1234",
    Email: identifier,
}
err := client.Auth.OTP().SignUp(auth.MethodEmail, identifier, user)
if err != nil {
    // handle error
}
```

The user will receive a code using the selected delivery method. Verify that code using:

```go
// The optional `w http.ResponseWriter` adds the session and refresh cookies to the response automatically.
// Otherwise they're available via authInfo
authInfo, err :=  descopeClient.OTP().Verify(auth.MethodEmail, identifier, code, w)
if err != nil {
    // handle error
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
err := descopeClient.SignUpOrIn(auth.MethodEmail, "desmond@descope.com", "http://myapp.com/verify-magic-link")
if err {
    // handle error
}
```

To verify a magic link, your redirect page must call the validation function on the token (`t`) parameter (`https://your-redirect-address.com/verify?t=<token>`):

```go
// The optional `w http.ResponseWriter` adds the session and refresh cookies to the response automatically.
// Otherwise they're available via authInfo
authInfo, err := client.Auth.MagicLink().Verify(token, w)
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
res, err := client.Auth.EnchantedLink().SignIn(identifier, "http://myapp.com/verify-enchanted-link", nil, nil)
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
    authInfo, err := client.Auth.EnchantedLink().GetSession(res.PendingRef, w)
    if err == nil {
        // The user successfully authenticated using the correct link
        // The optional `w http.ResponseWriter` adds the session and refresh cookies to the response automatically.
        // Otherwise they're available via authInfo
        break
    }
    if err == errors.EnchantedLinkUnauthorized && i > 1 {
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
if err := descopeClient.EnchantedLink().Verify(token); err != nil {
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
url, err := descopeClient.OAuth().Start("google", "https://my-app.com/handle-oauth", nil, nil, w)
if err != nil {
    // handle error
}
```

The user will authenticate with the authentication provider, and will be redirected back to the redirect URL, with an appended `code` HTTP URL parameter. Exchange it to validate the user:

```go
// The optional `w http.ResponseWriter` adds the session and refresh cookies to the response automatically.
// Otherwise they're available via authInfo
authInfo, err := descopeClient.OAuth().ExchangeToken(code, w)
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
url, err := descopeClient.SAML().Start("my-tenant-ID", "https://my-app.com/handle-saml", nil, nil, w)
if err != nil {
    // handle error
}
```

The user will authenticate with the authentication provider configured for that tenant, and will be redirected back to the redirect URL, with an appended `code` HTTP URL parameter. Exchange it to validate the user:

```go
// The optional `w http.ResponseWriter` adds the session and refresh cookies to the response automatically.
// Otherwise they're available via authInfo
authInfo, err := descopeClient.OAuth().ExchangeToken(code, w)
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
// Every user must have an identifier. All other user information is optional
identifier := "desmond@descope.com"
user :=  &auth.User{
    Name: "Desmond Copeland",
    Phone: "212-555-1234",
    Email: identifier,
}
totpResponse, err := client.Auth.TOTP().SignUp(auth.MethodEmail, identifier, user)
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
authInfo, err := descopeClient.TOTP().sign_in_code(identifier, code, nil, nil, w)
if err != nil {
    // handle error
}
```

The session and refresh JWTs should be returned to the caller, and passed with every request in the session. Read more on [session validation](#session-validation)

### Session Validation

Every secure request performed between your client and server needs to be validated. The client sends
the session and refresh tokens with every request, and they are validated using:

When using cookies you can call:

```go
if authorized, sessionToken, err := descopeClient.Auth.ValidateSession(r, w); !authorized {
    // unauthorized error
}
```

Alternatively, tokens can be validated directly:

```go
if authorized, sessionToken, err := descopeClient.Auth.ValidateSessionTokens(sessionToken, refreshToken); !authorized {
    // unauthorized error
}
```

These function will validate the session and also refresh it in the event it has expired.
It returns the given session token if it's still valid, or a new one if it was refreshed.
Make sure to return the session token from the response to the client if tokens are validated directly.

The `refreshToken` is optional here to validate a session, but is required to refresh the session in the event it has expired.

Usually, the tokens can be passed in and out via HTTP headers or via a cookie.
The implementation can defer according to your implementation. See our [examples](#code-examples) for a few examples.

If Roles & Permissions are used, validate them immediately after validating the session. See the [next section](#roles--permission-validation)
for more information.

#### Session Validation Using Middleware

Alternatively, you can validate the session using any supported builtin Go middleware (for example Chi or Mux)
instead of using the ValidateSessions function. This middleware will automatically detect the cookies from the
request and save the current user ID in the context for further usage. On failure, it will respond with `401 Unauthorized`.

```go
r.Use(auth.AuthenticationMiddleware(descopeClient.Auth, nil, nil))
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

## Management API

It is very common for some form of management or automation to be required. These can be performed
using the management API. Please note that these actions are more sensitive as they are administrative
in nature. Please use responsibly.

### Setup

To use the management API you'll need a `Management Key` along with your `Project ID`.
Create one in the [Descope Console](https://app.descope.com/settings/company/managementkeys).

```go
import "github.com/descope/go-sdk/descope"

// Initialized after setting the DESCOPE_PROJECT_ID and the DESCOPE_MANAGEMENT_KEY env vars
descopeClient := descope.NewDescopeClient()

// ** Or directly **
descopeClient := descope.NewDescopeClientWithConfig(&descope.Config{
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
// A user must have an identifier, other fields are optional.
// Roles should be set directly if no tenants exist, otherwise set
// on a per-tenant basis.
err := descopeClient.Management.User().Create("desmond@descope.com", "desmond@descope.com", "", "Desmond Copeland", nil, []*mgmt.AssociatedTenant{
    {TenantID: "tenant-ID1", RoleNames: []string{"role-name1"}},
    {TenantID: "tenant-ID2"},
})

// Update will override all fields as is. Use carefully.
err := descopeClient.Management.User().Update("desmond@descope.com", "desmond@descope.com", "", "Desmond Copeland", nil, []*mgmt.AssociatedTenant{
    {TenantID: "tenant-ID1", RoleNames: []string{"role-name1", "role-name2"}},
    {TenantID: "tenant-ID2"},
})

// User deletion cannot be undone. Use carefully.
err := descopeClient.Management.User().Delete("desmond@descope.com")

// Load specific user
userRes, err := descopeClient.Management.User().Load("desmond@descope.com")

// If needed, users can be loaded using their ID as well
userRes, err := descopeClient.Management.User().LoadByUserID("<user-id>")

// Search all users, optionally according to tenant and/or role filter
usersResp, err := descopeClient.Management.User().SearchAll([]string{"my-tenant-id"}, nil, 0)
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
res, err := descopeClient.Management.AccessKey().Create("access-key-1", 0, nil, []*mgmt.AssociatedTenant{
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
// You can configure SSO settings manually by setting the required fields directly
tenantID := "tenant-id" // Which tenant this configuration is for
idpURL := "https://idp.com"
entityID := "my-idp-entity-id"
idpCert := "<your-cert-here>"
redirectURL := "https://my-app.com/handle-saml" // Global redirect URL for SSO/SAML
err := descopeClient.Management.SSO().ConfigureSettings(tenantID, idpURL, entityID, idpCert, redirectURL)

// Alternatively, configure using an SSO metadata URL
err := descopeClient.Management.SSO().ConfigureMetadata(tenantID, "https://idp.com/my-idp-metadata")

// Map IDP groups to Descope roles, or map user attributes.
// This function overrides any previous mapping (even when empty). Use carefully.
roleMapping := []*mgmt.RoleMapping{
    {Groups: []string{"IDP_ADMIN"}, Role: "Tenant Admin"},
}
attributeMapping := &mgmt.AttributeMapping {
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

// Load all groups for the given user's identifiers (used for sign-in)
res, err := descopeClient.Management.Group().LoadAllGroupsForMembers("tenant-id", nil, []string{"identifier-1", "identifier-2"})
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
            ValidateSessionResponse:        &auth.Token{JWT: validateSessionResponse},
            ValidateSessionError:           errors.NoPublicKeyError,
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
ok, info, err := api.Auth.ValidateSession(nil, nil)
assert.False(t, ok)
assert.NotEmpty(t, info)
assert.EqualValues(t, validateSessionResponse, info.JWT)
assert.ErrorIs(t, err, errors.NoPublicKeyError)

res, err := api.Management.JWT().UpdateJWTWithCustomClaims("some jwt", nil)
require.NoError(t, err)
assert.True(t, updateJWTWithCustomClaimsCalled)
assert.EqualValues(t, updateJWTWithCustomClaimsResponse, res)
```

## Learn More

To learn more please see the [Descope Documentation and API reference page](https://docs.descope.com/).

## Contact Us

If you need help you can email [Descope Support](mailto:support@descope.com)

## License

The Descope SDK for Go is licensed for use under the terms and conditions of the [MIT license Agreement](https://github.com/descope/go-sdk/blob/main/LICENSE).
