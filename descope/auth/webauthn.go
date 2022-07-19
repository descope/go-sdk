package auth

import (
	"net/http"

	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/errors"
	"github.com/descope/go-sdk/descope/utils"
)

type webAuthnService struct {
	authenticationsBase
}

func (auth *webAuthnService) SignUpStart(identifier string, user *User) (*WebAuthnTransactionResponse, error) {
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

func (auth *webAuthnService) SignUpFinish(request *WebAuthnFinishRequest, w http.ResponseWriter) (*AuthenticationInfo, error) {
	return auth.SignUpFinishWithOptions(request, WithResponseOption(w))
}

func (auth *webAuthnService) SignUpFinishWithOptions(request *WebAuthnFinishRequest, options ...Option) (*AuthenticationInfo, error) {
	res, err := auth.client.DoPostRequest(api.Routes.WebAuthnSignupFinish(), request, nil, "")
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(res, options...)
}

func (auth *webAuthnService) SignInStart(identifier string) (*WebAuthnTransactionResponse, error) {
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

func (auth *webAuthnService) SignInFinish(request *WebAuthnFinishRequest, w http.ResponseWriter) (*AuthenticationInfo, error) {
	return auth.SignInFinishWithOptions(request, WithResponseOption(w))
}

func (auth *webAuthnService) SignInFinishWithOptions(request *WebAuthnFinishRequest, options ...Option) (*AuthenticationInfo, error) {
	res, err := auth.client.DoPostRequest(api.Routes.WebAuthnSigninFinish(), request, nil, "")
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(res, options...)
}
