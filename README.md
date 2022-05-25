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

### Usage

Use the following code snippets or the example in the example package for a more depth how to use.

```
package myapp

import (
    github.com/descope/go-sdk/descope
    github.com/descope/go-sdk/descope/auth
)

client, err = descope.NewDescopeClient(descope.Config{ProjectID: "myprojectid"})
...

if err := client.Auth.SignInOTP(auth.MethodEmail, "mytestmail@test.com"); err != nil {
    // handle error
}
...

if tokens, err := client.Auth.VerifyCodeEmail("mytestmail@test.com", code); err != nil {
    // handle error
}
for i := range tokens {
    http.SetCookie(w, tokens[i])
}
...

if authorized, err := client.Auth.ValidateSession(auth.RequestJWTProvider(r)); !authorized {
    // unauthorized error
}
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