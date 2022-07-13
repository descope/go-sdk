package auth

import (
	"net/http"

	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/errors"
	"github.com/descope/go-sdk/descope/utils"
)

func (auth *authenticationService) SignUpWebAuthnStart(identifier string, user *User) (*WebAuthnTransactionResponse, error) {
	if user == nil {
		user = &User{}
	}
	uRes := &UserResponse{User: *user}
	uRes.ExternalID = identifier
	res, err := auth.client.DoPostRequest(api.Routes.WebAuthnSignupStart(), authenticationWebAuthnSignUpRequestBody{User: uRes}, nil, "")
	if err != nil {
		return nil, err
	}

	webAuthnResponse := &WebAuthnTransactionResponse{}
	err = utils.Unmarshal([]byte(res.BodyStr), webAuthnResponse)
	return webAuthnResponse, err
}

func (auth *authenticationService) SignUpWebAuthnFinish(request *WebAuthnFinishRequest, w http.ResponseWriter) (*AuthenticationInfo, error) {
	return auth.SignUpWebAuthnFinishWithOptions(request, WithResponseOption(w))
}

func (auth *authenticationService) SignUpWebAuthnFinishWithOptions(request *WebAuthnFinishRequest, options ...Option) (*AuthenticationInfo, error) {
	res, err := auth.client.DoPostRequest(api.Routes.WebAuthnSignupFinish(), request, nil, "")
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(res, options...)
}

func (auth *authenticationService) SignInWebAuthnStart(identifier string) (*WebAuthnTransactionResponse, error) {
	if identifier == "" {
		return nil, errors.NewInvalidArgumentError("identifier")
	}

	res, err := auth.client.DoPostRequest(api.Routes.WebAuthnSigninStart(), authenticationRequestBody{ExternalID: identifier}, nil, "")
	if err != nil {
		return nil, err
	}

	webAuthnResponse := &WebAuthnTransactionResponse{}
	err = utils.Unmarshal([]byte(res.BodyStr), webAuthnResponse)
	return webAuthnResponse, err

}

func (auth *authenticationService) SignInWebAuthnFinish(request *WebAuthnFinishRequest, w http.ResponseWriter) (*AuthenticationInfo, error) {
	return auth.SignInWebAuthnFinishWithOptions(request, WithResponseOption(w))
}

func (auth *authenticationService) SignInWebAuthnFinishWithOptions(request *WebAuthnFinishRequest, options ...Option) (*AuthenticationInfo, error) {
	res, err := auth.client.DoPostRequest(api.Routes.WebAuthnSigninFinish(), request, nil, "")
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(res, options...)
}
