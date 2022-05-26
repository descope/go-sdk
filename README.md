[![CI](https://github.com/descope/go-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/descope/go-sdk/actions/workflows/ci.yml)

# Golang SDK

Go library used to integrate with Descope

## API

https://github.com/descope/go-sdk/blob/main/descope/api.go#L12

## How To Use

Use the authentication API to provide an easy sign up or sign in options for Golang.

### Prerequisites

1. Import the package by running `go get -u github.com/descope/go-sdk`
1. In order to use any of the authentication API you must specify the project ID given by Descope either by:
   - Set the `DESCOPE_PROJECT_ID` environment variable.
   - Set the ProjectID in the Conf{} on initialize.
1. When using the session validation API you may specify the public key given by Descope either by:
   - Set the `DESCOPE_PUBLIC_KEY` environment variable.
   - Set the PublicKey in the Conf{} on initialize.
   - Or keep empty to fetch matching public keys from descope services.

### Code Usage

Use the following code snippets for an quick and easy usage or check out our examples in the examples package for a more in depth how to use.

```
package mygreatapp

import (
    github.com/descope/go-sdk/descope
    github.com/descope/go-sdk/descope/auth
)

// Init Descope client when starting your app, provide your project ID (from your Descope account).
// Store the client so you can easily access it later in the router level.
client, err = descope.NewDescopeClient(descope.Config{ProjectID: "myprojectid"})
...

// In your sign-in route
if err := client.Auth.SignInOTP(auth.MethodEmail, "mytestmail@test.com"); err != nil {
    // handle error
}
...

// In your verify code route or after a sucessful sign-in route
if _, err := client.Auth.VerifyCode(auth.MethodEmail, "mytestmail@test.com", code, w); err != nil {
    // handle error
}
...

// In your logout route
if _, err := client.Auth.Logout(r, w); err != nil {
    // handle error
}
...

// Put this in your routes middleware for any request which requires authentication, Or use the builtin middleware.
if authorized, err := client.Auth.ValidateSession(r, w); !authorized {
    // unauthorized error
}
// Use the builtin middleware to authenticate selected routes invoke myCustomFailureCallback on authentication failure.
r.Use(auth.AuthenticationMiddleware(client.Auth, myCustomFailureCallback)
```

## Run The Example

1. Clone repository locally `git clone github.com/descope/go-sdk`
2. Download prerequisites and build `make build`
3. Navigate to examples folder `cd examples`
4. export your project id:

```
export DESCOPE_PROJECT_ID=<insert here>
```

5. Run one of our example applications:
    - Gin web app: `make run-gin-example`
    - HTTP web app: `make run-example`
6. Application runs on `http://localhost:8085`

### Run the Example: VS Code
Alternatively you can run the example using a predefined launch configurations by following the below simple steps
1. Follow steps 1-4 above
1. Open `.vscode/launch.json` and replace `<insert here>` to your project id
1. Run/Debug using VS Code

## Unit Testing and Mocking
After integrating Descope SDK, you might want to unit test your app, for that we added mocks, so you can easily do the following:
```
api := descope.API{
	Auth: auth.MockDescopeAuth{
		ValidateSessionResponseNotOK:   true,
		ValidateSessionResponseCookies: []*http.Cookie{{}},
		ValidateSessionResponseError:   errors.BadRequest,
	},
}

ok, cookies, err := api.Auth.ValidateSession(nil, nil)

assert.False(t, ok)
assert.NotEmpty(t, cookies)
assert.ErrorIs(t, err, errors.BadRequest)
``` 
In this example we mocked the Auth APIs and changed the response of the ValidateSession
