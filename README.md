[![CI](https://github.com/descope/go-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/descope/go-sdk/actions/workflows/ci.yml)

# ExpresSDK for Go
Use the Descope ExpresSDK for Go to quickly and easily add user authentication to your application or website. If you need more background on how the ExpresSDKs work, [click here](/sdk/index.mdx). 

The SDK will require a valid `DESCOPE_PROJECT_ID`, which confirms that you are a registered Descope customer. We'll show you below exactly where to find your Project ID and how to set it.

## ExpressStart with OTP Authentication

This section will show you how to implement user authentication using a one-time password (OTP). A typical four step flow for OTP authentictaion is shown below.

```mermaid
flowchart LR
  signup[1. customer sign-up]-- customer gets OTP -->verify[3. customer verification]
  signin[2. customer sign-in]-- customer gets OTP -->verify
  verify-- access private API -->validate[4. session validation]
```

### Prerequisites

Replace any instance of  `<ProjectID>` in the code below with your company's Project ID, which can be found in the [Descope console](link).

* Run the following commands in your project

     These commands will add the Descope Go ExpresSDK as a project dependency and set the `DESCOPE_PROJECT_ID`.

     ```bash
    go get -u github.com/descope/go-sdk
    export DESCOPE_PROJECT_ID=<ProjectID>
     ```

* Import and initialize the ExpresSDK for Go client in your source code

    ```golang
    import (
        github.com/descope/go-sdk/descope
    )

    descopeClient, err := descope.NewDescopeClient()
    ```

### 1. Customer Sign-up

In your sign-up route for OTP (for example, `myapp.com/signup`) generate a sign-up request and send the OTP verification code via the selected delivery method. In the example below an email is sent to "mytestmail@test.com". In additon, optional user data (for exmaple, a custom username in the code sample below) can be gathered during the sign-up process.

```golang
if err := descopeClient.Auth.SignUpOTP(auth.MethodEmail, "mytestmail@test.com", &auth.User{Username: "newusername"}); err != nil {
    // handle error
}
```

### 2. Customer Sign-in
In your sign-in route for OTP (for exmaple, `myapp.com/login`) generate a sign-in request send the OTP verification code via the selected delivery method. In the example below an email is sent to "mytestmail@test.com".

```golang
identifier := "mytestmail@test.com"
if err := descopeClient.Auth.SignInOTP(auth.MethodEmail, identifier); err != nil {
    // handle error
}
```

### 3. Customer Verification

In your verify customer route for OTP (for example, `myapp.com/verify`) verify the OTP from either a customer sign-up or sign-in. The VerifyCode function call will write the necessary tokens and cookies to the response writer (`w`), which will be used by the Go client to validate each session interaction.

```golang
if _, err := descopeClient.Auth.VerifyCode(auth.MethodEmail, "mytestmail@test.com", code, w); err != nil {
    // handle error
}
```

### 4. Session Validation

Session validation checks to see that the visitor to your website or application is who they say they are, by comparing the value in the validation variables against the session data that is already stored.

In the code below the Request argument (r) parses and validates the tokens and cookies from the client. ValidateSession returns true if the user is authorized, and false if the user is not authorized. In addition, the session will automatically be extended if the user is valid but the sesssion has expired by writing the updated tokens and cookies to the response writer (w).

```golang
if authorized, userToken, err := descopeClient.Auth.ValidateSession(r, w); !authorized {
    // unauthorized error
}
```

##### Session Validation Using Middleware
Alternativly, you can validate the session using any supported builtin Go middleware (for example Chi or Mux) instead of using the ValidateSessions function.

```golang
r.Use(auth.AuthenticationMiddleware(descopeClient.Auth, nil))
```

## ExpressStart with MagicLink Authentication

This section will help you implement user authentication using Magiclinks. A typical four step flow for OTP authentictaion is shown below.

```mermaid
flowchart LR
  signup[1. customer sign-up]-- customer gets MagicLink -->verify[3. MagicLink verification]
  signin[2. customer sign-in]-- customer gets MagicLink -->verify
  verify-- access private API -->validate[4. session validation]
```

### Prerequisites

Replace any instance of  `<ProjectID>` in the code below with your company's Project ID, which can be found in the [Descope console](link).

* Run the following commands in your project

     These commands will add the Descope Go ExpresSDK as a project dependency and set the `DESCOPE_PROJECT_ID`.

     ```bash
    go get -u github.com/descope/go-sdk
    export DESCOPE_PROJECT_ID=<ProjectID>
     ```

* Import and initialize the ExpresSDK for Go client in your source code

    ```golang
    import (
        github.com/descope/go-sdk/descope
    )

    descopeClient, err := descope.NewDescopeClient()
    ```

### 1. Customer Sign-up

In your sign-up route using magic link (for example, `myapp.com/signup`) generate a sign-up request and send the magic link via the selected delivery method. In the example below an email is sent to "mytestmail@test.com" containing the magic link and the link will automatically return back to the provided URL ("https://mydomain.com/verify"). In additon, optional user data (for exmaple, a custom username in the code sample below) can be gathered during the sign-up process.

```golang
if err := descopeClient.Auth.SignUpMagicLink(auth.MethodEmail, "mytestmail@test.com", "https://mydomain.com/verify", &auth.User{Username: "newusername"}); err != nil {
    // handle error
}
```

### 2. Customer Sign-in
In your sign-in route using magic link (for exmaple, `myapp.com/login`) generate a sign-in request send the magic link via the selected delivery method. In the example below an email is sent to "mytestmail@test.com" containing the magic link and the link will automatically return back to the provided URL ("https://mydomain.com/verify"). 

```golang
identifier := "mytestmail@test.com"
if err := descopeClient.Auth.SignInMagicLink(auth.MethodEmail, identifier, "https://mydomain.com/verify"); err != nil {
    // handle error
}
```

### 3. Customer Verification

In your verify customer route for magic link (for example, `mydomain.com/verify`) verify the token from either a customer sign-up or sign-in. The VerifyMagicLink function call will write the necessary tokens and cookies to the response writer (`w`), which will be used by the Go client to validate each session interaction.

```golang
if _, err := descopeClient.Auth.VerifyMagicLink(auth.MethodEmail, "mytestmail@test.com", token, w); err != nil {
    // handle error
}
```

### 4. Session Validation

Session validation checks to see that the visitor to your website or application is who they say they are, by comparing the value in the validation variables against the session data that is already stored.

In the code below the Request argument (r) parses and validates the tokens and cookies from the client. ValidateSession returns true if the user is authorized, and false if the user is not authorized. In addition, the session will automatically be extended if the user is valid but the sesssion has expired by writing the updated tokens and cookies to the response writer (w).

```golang
if authorized, userToken, err := descopeClient.Auth.ValidateSession(r, w); !authorized {
    // unauthorized error
}
```

##### Session Validation Using Middleware
Alternativly, you can validate the session using any supported builtin Go middleware (for example Chi or Mux) instead of using the ValidateSessions function.

```golang
r.Use(auth.AuthenticationMiddleware(descopeClient.Auth, nil))
```

## ExpressStart with Oauth

:::warning placeholder
placeholder for instanst-start OAuth example
:::

## ExpresStart for WebAuthn

:::warning placeholder
placeholder for instanst-start WebAuthn example
:::


## Run the Go Examples

Instantly run the end-to-end ExpresSDK for Go examples, as shown below. The source code for these examples are in the folder [GitHib go-sdk/examples folder](https://github.com/descope/go-sdk/blob/main/examples).

### Prerequisites

Run the following commands in your project. Replace any instance of  `<ProjectID>` in the code below with your company's Project ID, which can be found in the [Descope console](link).

This commands will add the Descope Go ExpresSDK as a project dependency, clone the Go repository locally, and set the `DESCOPE_PROJECT_ID`.

```code Go
go get -u github.com/descope/go-sdk
git clone github.com/descope/go-sdk
export DESCOPE_PROJECT_ID=<ProjectID>
```

### Run an example

1. Run this command in your project to build the examples.

    ```code
    make build
    ```

2. Run a specific example

    ```code Gin web app
    make run-gin-example
    ```
   
    ```code Gorilla Mux web app
    make run-example
    ```

### Using Visual Studio Code

To run Run and Debug using Visual Studio Code "Run Example: Gorilla Mux Web App" or "Run Example: Gin Web App"

The examples run on TLS at the following URL: [https://localhost:8085](https://localhost:8085).


## Unit Testing and Data Mocks
Simplify your unit testing by using the predefined mocks and mock objects provided with the ExpresSDK.

```code go
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

The Descope ExpresSDK for Go is licensed for use under the terms and conditions of the [MIT license Agreement](https://github.com/descope/go-sdk/blob/main/LICENSE).