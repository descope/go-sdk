package auth

import (
	"net/http"

	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/errors"
	"github.com/descope/go-sdk/descope/utils"
)

type webAuthn struct {
	authenticationsBase
}

func (auth *webAuthn) SignUpStart(identifier string, user *User) (*WebAuthnTransactionResponse, error) {
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

func (auth *webAuthn) SignUpFinish(request *WebAuthnFinishRequest, w http.ResponseWriter) (*AuthenticationInfo, error) {
	return auth.SignUpFinishWithOptions(request, WithResponseOption(w))
}

func (auth *webAuthn) SignUpFinishWithOptions(request *WebAuthnFinishRequest, options ...Option) (*AuthenticationInfo, error) {
	res, err := auth.client.DoPostRequest(api.Routes.WebAuthnSignupFinish(), request, nil, "")
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(res, options...)
}

func (auth *webAuthn) SignInStart(identifier string) (*WebAuthnTransactionResponse, error) {
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

func (auth *webAuthn) SignInFinish(request *WebAuthnFinishRequest, w http.ResponseWriter) (*AuthenticationInfo, error) {
	return auth.SignInFinishWithOptions(request, WithResponseOption(w))
}

func (auth *webAuthn) SignInFinishWithOptions(request *WebAuthnFinishRequest, options ...Option) (*AuthenticationInfo, error) {
	res, err := auth.client.DoPostRequest(api.Routes.WebAuthnSigninFinish(), request, nil, "")
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(res, options...)
}

func (auth *webAuthn) AddDeviceStart(identifier string, r *http.Request) (*WebAuthnTransactionResponse, error) {
	if identifier == "" {
		return nil, errors.NewInvalidArgumentError("identifier")
	}

	pswd, err := getValidRefreshToken(r)
	if err != nil {
		return nil, err
	}

	res, err := auth.client.DoPostRequest(api.Routes.WebAuthnAddDeviceStart(), authenticationRequestBody{ExternalID: identifier}, nil, pswd)
	if err != nil {
		return nil, err
	}

	webAuthnResponse := &WebAuthnTransactionResponse{}
	err = utils.Unmarshal([]byte(res.BodyStr), webAuthnResponse)
	return webAuthnResponse, err
}

func (auth *webAuthn) AddDeviceFinish(request *WebAuthnFinishRequest) error {
	_, err := auth.client.DoPostRequest(api.Routes.WebAuthnAddDeviceFinish(), request, nil, "")
	return err
}
