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

Use the following code snippets or the example in the example package for how to use.

```
package myapp

import github.com/descope/go-sdk/descope

client, err = descope.NewDescopeAPI(descope.Config{ProjectID: "myprojectid"})
...

if err := client.Auth.SignInOTP(auth.MethodEmail, "mytestmail@test.com"); err != nil {
    // handle error
}
...

if tokens, err := client.Auth.VerifyCodeEmail("mytestmail@test.com", code); err != nil {
    // handle error
}
...

if authorized, err := client.Auth.ValidateSession(token); !authorized {
    // unauthorized error
}
```

## Run The Example

1. Clone repo locally `git clone github.com/descope/go-sdk`
1. Download prerequisites and compile `make build`
1. Set a self signed local private and public key using:

```
openssl genrsa -out server.key 2048
openssl req -new -x509 -sha256 -key server.key -out server.crt -days 3650
```

4. export your project id and public key for the project:

```
export DESCOPE_PROJECT_ID=<insert here> && export DESCOPE_PUBLIC_KEY=<insert here>
```

5. Run the example application `make run-example`
6. Application runs on `http://localhost:8085`
