package auth

import (
	"fmt"

	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/errors"
	"github.com/descope/go-sdk/descope/utils"
)

func (auth *authenticationService) SignUpWebAuthnStart(user *User) (*WebAuthnTransactionResponse, error) {
	res, err := auth.client.DoPostRequest(api.Routes.WebAuthnSignupStart(), authenticationWebAuthnSignUpRequestBody{User: user}, &api.HTTPRequest{BaseURL: "http://localhost:8181"}, "")
	if err != nil {
		return nil, err
	}

	webAuthnResponse := &WebAuthnTransactionResponse{}
	err = utils.Unmarshal([]byte(res.BodyStr), webAuthnResponse)
	return webAuthnResponse, err
}

func (auth *authenticationService) SignUpWebAuthnFinish(request *WebAuthnFinishRequest) (*AuthenticationInfo, error) {
	res, err := auth.client.DoPostRequest(api.Routes.WebAuthnSignupFinish(), request, &api.HTTPRequest{BaseURL: "http://localhost:8181"}, "")
	if err != nil {
		return nil, err
	}
	fmt.Println(res.BodyStr)
	return NewAuthenticationInfo(nil), nil
}

func (auth *authenticationService) SignInWebAuthnStart(identifier string) (*WebAuthnTransactionResponse, error) {
	if identifier == "" {
		return nil, errors.NewInvalidArgumentError("identifier")
	}

	res, err := auth.client.DoPostRequest(api.Routes.WebAuthnSigninStart(), authenticationRequestBody{ExternalID: identifier}, &api.HTTPRequest{BaseURL: "http://localhost:8181"}, "")
	if err != nil {
		return nil, err
	}

	webAuthnResponse := &WebAuthnTransactionResponse{}
	err = utils.Unmarshal([]byte(res.BodyStr), webAuthnResponse)
	return webAuthnResponse, err

}

func (auth *authenticationService) SignInWebAuthnFinish(request *WebAuthnFinishRequest) (*AuthenticationInfo, error) {
	res, err := auth.client.DoPostRequest(api.Routes.WebAuthnSigninFinish(), request, &api.HTTPRequest{BaseURL: "http://localhost:8181"}, "")
	if err != nil {
		return nil, err
	}
	fmt.Println(res.BodyStr)
	return NewAuthenticationInfo(nil), nil
}
