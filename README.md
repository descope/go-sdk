[![CI](https://github.com/descope/go-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/descope/go-sdk/actions/workflows/ci.yml)

# Golang SDK

Go library used to integrate with Descope.
Use Descope client to get a quick and simple authentication options for your Golang applications.

## Installation

`go get -u github.com/descope/go-sdk`

## Prerequisites

1. In order to use any of the authentication API you must specify the project ID given by Descope. There are two options:
   - Set the `DESCOPE_PROJECT_ID` environment variable
   - Set the ProjectID in the `descope.Config` upon Descope Client initialization
1. When using the session validation you might need to specify your project public key. There are three options:
   - Keep empty to auto fetch matching public keys from Descope
   - Set the `DESCOPE_PUBLIC_KEY` environment variable
   - Set the PublicKey in `descope.Config{PublicKey: "<your_project_public_key>"}` upon Descope Client initialization

## Quick Start

Use the following code snippets for an quick and easy usage or check out our examples in the examples package for a more in depth how to use.

```golang
package mygreatapp

import (
    github.com/descope/go-sdk/descope
    github.com/descope/go-sdk/descope/auth
)
...

// Init Descope client when starting your app, provide your project ID (from your Descope account) or use the environment variable.
// Store the client so you can easily access it later in the router level.
descopeClient, err := descope.NewDescopeClient(descope.Config{})
...

// In your sign-up route for OTP use:
if err := descopeClient.Auth.SignUpOTP(auth.MethodEmail, "mytestmail@test.com", &auth.User{Name: "newusername"}); err != nil {
    // handle error
}
...

// In your login route for OTP use:
if err := descopeClient.Auth.SignInOTP(auth.MethodEmail, "mytestmail@test.com"); err != nil {
    // handle error
}
...

// In your verify OTP code route use:
if _, err := descopeClient.Auth.VerifyCode(auth.MethodEmail, "mytestmail@test.com", code, w); err != nil {
    // handle error
}

```

## Running the Example

1. Clone repository locally `git clone github.com/descope/go-sdk`
### Run Manually
1. Download prerequisites and build `make build`
1. setup all prerequisites
1. Run one of our example applications:
    - Gin web app: `make run-gin-example`
    - Gorilla Mux web app: `make run-example`

### Debug in Visual Studio Code

1. Open `.vscode/launch.json` and replace `<insert here>` with your project id
1. Run and Debug using Visual Studio Code "Run Example: Gorilla Mux Web App" or "Run Example: Gin Web App"

The examples runs on TLS at `https://localhost:8085`.

## Unit Testing and Data Mocks
After integrating with Descope SDK, you might want to add unit tests to your app, for that we added mocks, so you can easily do the following:
```golang
descopeClient := descope.DescopeClient{
	Auth: auth.MockDescopeAuthentication{
		ValidateSessionResponseNotOK:   true,
		ValidateSessionResponseToken:   "newtoken",
		ValidateSessionResponseError:   errors.BadRequest,
	},
}

ok, userToken, err := descopeClient.Auth.ValidateSession("my token", "another token")
assert.False(t, ok)
assert.NotEmpty(t, userToken)
assert.ErrorIs(t, err, errors.BadRequest)
``` 
In this example we mocked the Descope Authentication to change the response of the ValidateSession

## License
Descope go-sdk is [MIT licensed](./LICENSE).

-----

```golang
// Put the following in your routes middleware for any request that requires authentication, or use the builtin middleware. (see below example)
if authorized, userToken, err := descopeClient.Auth.ValidateSession(r, w); !authorized {
    // unauthorized error
}
...

// In your logout route
if err := descopeClient.Auth.Logout(r, w); err != nil {
    // handle error
}

// Use the builtin middleware to protect your application routes, invokes failure callback on authentication failure.

// Example with Chi / Mux routers:
r.Use(auth.AuthenticationMiddleware(descopeClient.Auth, nil))

// Example with httprouter and alice:
r := httprouter.New()
authMiddleware := alice.New(auth.AuthenticationMiddleware(descopeClient.Auth, nil))
r.GET("/hello", handlerToHandle(authMiddleware.ThenFunc(helloHandler)))

// Example of customer failure callback:
r.Use(auth.AuthenticationMiddleware(descopeClient.Auth, func(w http.ResponseWriter, r *http.Request, err error) {
    w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte("Unauthorized"))
}))

// For full Gin example, see "examples/ginwebapp/main.go"
// For full Mux example, see "examples/webapp/main.go"
```
