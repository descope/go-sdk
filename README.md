[![CI](https://github.com/descope/go-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/descope/go-sdk/actions/workflows/ci.yml)

# Golang SDK

Go library used to integrate with Descope

## API

https://github.com/descope/go-sdk/blob/implementation/pkg/auth/types.go#L62

## Quick Start

1. Clone repo locally `git clone github.com/descope/go-sdk`
1. Download prerequisites and compile `make build`
1. Set a self signed local private and public key using:

```
openssl genrsa -out server.key 2048
openssl req -new -x509 -sha256 -key server.key -out server.crt -days 3650
```

4. export your project id and public key for the project:

```
export PROJECT_ID=<insert here> && export PUBLIC_KEY=<insert here>
```

5. Run the example application `go run example/main.go`
6. Application runs on `http://localhost:8085`
