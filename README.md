[![CI](https://github.com/descope/go-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/descope/go-sdk/actions/workflows/ci.yml)

# Golang SDK

## Overview
Go library used to integrate with Descope.
Use Descope client to get a quick and simple authentication options for your Golang applications.

The following code samples implement best practices and automatically fetch the project public keys to be used when validating the session. For advnaced configurations [see here](placeholder)

a. (jeff) insert diagram and explanation

## Installation
In your project use the following command to fetch the go-sdk as the project dependency:

`go get -u github.com/descope/go-sdk`

## Express Start

### Prerequisites
 In the [Descope console](link) create or get your project id and then set the `DESCOPE_PROJECT_ID` environment variable run the following command
 ```
 export DESCOPE_PROJECT_ID=mysecret
 ```

### Import the Package
After installation import the package

```golang
import (
    github.com/descope/go-sdk/descope
    github.com/descope/go-sdk/descope/auth
)
```

### Initialize Descope Client

Init Descope client when starting your app, using the default configurations and project id set from the environment variable.
Store the client instance so you can easily access it later in your routes.

```golang
descopeClient, err := descope.NewDescopeClient()
```

### Sign Up (OTP)

In your sign-up route for OTP such as `myapp.com/signup` use this to generate a sign up request and send verification code trough the
appropriate delivry method. In the example below we send an email to "mytestmail@test.com" while also adding user optional data such as a custom username.

```golang
if err := descopeClient.Auth.SignUpOTP(auth.MethodEmail, "mytestmail@test.com", &auth.User{Username: "newusername"}); err != nil {
    // handle error
}
```

### Sign In (OTP)
In your login route for OTP such as `myapp.com/login` use this to generate a login request and send verification code to the existing user associated with the identifier.
In the example below we send the verification code using an email delivery method to the email identifier "mytestmail@test.com".
```golang
identifier := "mytestmail@test.com"
if err := descopeClient.Auth.SignInOTP(auth.MethodEmail, identifier); err != nil {
    // handle error
}
```

### Verify Code (OTP)
// In your verify OTP code route use:
In your verify route for OTP such as `myapp.com/verify` use this to authenticate and verify the identifier using the verification code provided by sign up or sign in.
In the example a successful verify code will automatically write the tokens and cookies to the response writer (w) that will be used by the client to validate the session.
```golang
if _, err := descopeClient.Auth.VerifyCode(auth.MethodEmail, "mytestmail@test.com", code, w); err != nil {
    // handle error
}
```

### Validate Session
In order to validate the sessions provided by the authentication methods, you may use the ValidateSession or any provided middleware to validate the session whenever needed.
In the example the Request arguemnt (r) is used to parse and validate the tokens and cookies from the client and returns true if the user is authorized or false if not.
Farthermore, the session may automatically extend if valid but expired which will automatically write the tokens and cookies to the response writer (w).

```golang
if authorized, userToken, err := descopeClient.Auth.ValidateSession(r, w); !authorized {
    // unauthorized error
}
```

## Running the Example
### Prerequisites 
1. Clone repository locally `git clone github.com/descope/go-sdk
1. Set the `DESCOPE_PUBLIC_KEY` environment variable by running the following command
 ```
 export DESCOPE_PROJECT_ID=mysecret
 ```

### Run It
1. Download prerequisites and build `make build`
1. Run one of our example applications:
    - Gin web app: `make run-gin-example`
    - Gorilla Mux web app: `make run-example`

### Run in Visual Studio Code
1. Run and Debug using Visual Studio Code "Run Example: Gorilla Mux Web App" or "Run Example: Gin Web App"

The examples run on TLS at `https://localhost:8085`.

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
Descope go-sdk is [MIT licensed](https://github.com/descope/go-sdk/blob/main/LICENSE).

-----

When using the session validation you might need to specify your project public key. There are three options:
   - Keep empty to auto fetch matching public keys from Descope
   - Set the `DESCOPE_PUBLIC_KEY` environment variable
   - Set the PublicKey in `descope.Config{PublicKey: "<your_project_public_key>"}` upon Descope Client initialization

```golang

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
