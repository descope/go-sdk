[![CI](https://github.com/descope/go-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/descope/go-sdk/actions/workflows/ci.yml)

# Golang SDK

Go library used to integrate with Descope.

## How To Use

Use Descope client to get a quick and simple authentication options for your Golang applications.

### Prerequisites

1. Import Descope package by running `go get -u github.com/descope/go-sdk`
1. In order to use any of the authentication API you must specify the project ID given by Descope. There are two options:
   - Set the `DESCOPE_PROJECT_ID` environment variable
   - Set the ProjectID in `descope.Config{ProjectID: "<your_project_id>"}` upon Descope Client initialization
1. When using the session validation you might need to specify your project public key. There are three options:
   - Keep empty to auto fetch matching public keys from Descope
   - Set the `DESCOPE_PUBLIC_KEY` environment variable
   - Set the PublicKey in `descope.Config{PublicKey: "<your_project_public_key>"}` upon Descope Client initialization

### Code Usage

Use the following code snippets for an quick and easy usage or check out our examples in the examples package for a more in depth how to use.

```golang
package mygreatapp

import (
    github.com/descope/go-sdk/descope
    github.com/descope/go-sdk/descope/auth
)

// Init Descope client when starting your app, provide your project ID (from your Descope account).
// Store the client so you can easily access it later in the router level.
descopeClient, err := descope.NewDescopeClient(descope.Config{ProjectID: "myprojectid"})
...

// In your sign-up route for OTP
if err := descopeClient.Auth.SignUpOTP(auth.MethodEmail, "mytestmail@test.com", &auth.User{Name: "newusername"}); err != nil {
    // handle error
}
...

// In your sign-in route for OTP
if err := descopeClient.Auth.SignInOTP(auth.MethodEmail, "mytestmail@test.com"); err != nil {
    // handle error
}
...

// In your verify OTP code route
if _, err := descopeClient.Auth.VerifyCode(auth.MethodEmail, "mytestmail@test.com", code, w); err != nil {
    // handle error
}
...

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

## Run web apps examples locally

1. Clone repository locally `git clone github.com/descope/go-sdk`
1. Download prerequisites and build `make build`
1. Navigate to examples folder `cd examples`
1. export your project id:
    ```bash
    export DESCOPE_PROJECT_ID=<insert here>
    ```
1. Run one of our example applications:
    - Gin web app: `make run-gin-example`
    - Gorilla Mux web app: `make run-example`
1. Application runs on `http://localhost:8085`

### Run examples in Visual Studio Code
Alternatively you can run the example using a predefined launch configurations with the following simple steps:
1. Follow steps 1-4 above
1. Open `.vscode/launch.json` and replace `<insert here>` to your project id
1. Run & Debug using Visual Studio Code

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

ok, userToken, err := descopeClient.Auth.ValidateSession(nil, nil)

assert.False(t, ok)
assert.NotEmpty(t, userToken)
assert.ErrorIs(t, err, errors.BadRequest)
``` 
In this example we mocked the Descope Authentication to change the response of the ValidateSession

### License

Descope go-sdk is [MIT licensed](./LICENSE).
