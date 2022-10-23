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

func (auth *webAuthn) SignUpStart(identifier string, user *User, origin string) (*WebAuthnTransactionResponse, error) {
	if user == nil {
		user = &User{}
	}
	uRes := &WebauthnUserRequest{ExternalID: identifier}
	if user != nil {
		uRes.Name = user.Name
	}
	res, err := auth.client.DoPostRequest(api.Routes.WebAuthnSignupStart(), authenticationWebAuthnSignUpRequestBody{User: uRes, Origin: origin}, nil, "")
	if err != nil {
		return nil, err
	}

	webAuthnResponse := &WebAuthnTransactionResponse{}
	err = utils.Unmarshal([]byte(res.BodyStr), webAuthnResponse)
	return webAuthnResponse, err
}

func (auth *webAuthn) SignUpFinish(request *WebAuthnFinishRequest, r *http.Request, loginOptions *LoginOptions, w http.ResponseWriter) (*AuthenticationInfo, error) {
	var pswd string
	var err error
	if loginOptions.IsStepup() {
		pswd, err = getValidRefreshToken(r)
		if err != nil {
			return nil, err
		}
	}
	request.LoginOptions = loginOptions
	res, err := auth.client.DoPostRequest(api.Routes.WebAuthnSignupFinish(), request, nil, pswd)
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(res, w)
}

func (auth *webAuthn) SignInStart(identifier string, origin string) (*WebAuthnTransactionResponse, error) {
	if identifier == "" {
		return nil, errors.NewInvalidArgumentError("identifier")
	}

	res, err := auth.client.DoPostRequest(api.Routes.WebAuthnSigninStart(), authenticationWebAuthnSignInRequestBody{ExternalID: identifier, Origin: origin}, nil, "")
	if err != nil {
		return nil, err
	}

	webAuthnResponse := &WebAuthnTransactionResponse{}
	err = utils.Unmarshal([]byte(res.BodyStr), webAuthnResponse)
	return webAuthnResponse, err

}

func (auth *webAuthn) SignInFinish(request *WebAuthnFinishRequest, r *http.Request, loginOptions *LoginOptions, w http.ResponseWriter) (*AuthenticationInfo, error) {
	var pswd string
	var err error
	if loginOptions.IsStepup() {
		pswd, err = getValidRefreshToken(r)
		if err != nil {
			return nil, err
		}
	}
	request.LoginOptions = loginOptions
	res, err := auth.client.DoPostRequest(api.Routes.WebAuthnSigninFinish(), request, nil, pswd)
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(res, w)
}

func (auth *webAuthn) UpdateUserDeviceStart(identifier string, origin string, r *http.Request) (*WebAuthnTransactionResponse, error) {
	if identifier == "" {
		return nil, errors.NewInvalidArgumentError("identifier")
	}

	pswd, err := getValidRefreshToken(r)
	if err != nil {
		return nil, err
	}

	res, err := auth.client.DoPostRequest(api.Routes.WebAuthnUpdateUserDeviceStart(), authenticationWebAuthnAddDeviceRequestBody{ExternalID: identifier, Origin: origin}, nil, pswd)
	if err != nil {
		return nil, err
	}

	webAuthnResponse := &WebAuthnTransactionResponse{}
	err = utils.Unmarshal([]byte(res.BodyStr), webAuthnResponse)
	return webAuthnResponse, err
}

func (auth *webAuthn) UpdateUserDeviceFinish(request *WebAuthnFinishRequest) error {
	_, err := auth.client.DoPostRequest(api.Routes.WebAuthnUpdateUserDeviceFinish(), request, nil, "")
	return err
}
