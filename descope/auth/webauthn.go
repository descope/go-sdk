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

func (auth *webAuthn) SignUpStart(loginID string, user *User, origin string) (*WebAuthnTransactionResponse, error) {
	if user == nil {
		user = &User{}
	}
	uRes := &WebauthnUserRequest{LoginID: loginID}
	if user != nil {
		uRes.Name = user.Name
	}
	res, err := auth.client.DoPostRequest(api.Routes.WebAuthnSignUpStart(), authenticationWebAuthnSignUpRequestBody{User: uRes, Origin: origin}, nil, "")
	if err != nil {
		return nil, err
	}

	webAuthnResponse := &WebAuthnTransactionResponse{}
	err = utils.Unmarshal([]byte(res.BodyStr), webAuthnResponse)
	return webAuthnResponse, err
}

func (auth *webAuthn) SignUpFinish(request *WebAuthnFinishRequest, w http.ResponseWriter) (*AuthenticationInfo, error) {
	res, err := auth.client.DoPostRequest(api.Routes.WebAuthnSignUpFinish(), request, nil, "")
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(res, w)
}

func (auth *webAuthn) SignInStart(loginID string, origin string, r *http.Request, loginOptions *LoginOptions) (*WebAuthnTransactionResponse, error) {
	if loginID == "" {
		return nil, errors.NewInvalidArgumentError("loginID")
	}
	var pswd string
	var err error
	if loginOptions.IsJWTRequired() {
		pswd, err = getValidRefreshToken(r)
		if err != nil {
			return nil, errors.InvalidStepupJwtError
		}
	}

	res, err := auth.client.DoPostRequest(api.Routes.WebAuthnSignInStart(), authenticationWebAuthnSignInRequestBody{LoginID: loginID, Origin: origin, LoginOptions: loginOptions}, nil, pswd)
	if err != nil {
		return nil, err
	}

	webAuthnResponse := &WebAuthnTransactionResponse{}
	err = utils.Unmarshal([]byte(res.BodyStr), webAuthnResponse)
	return webAuthnResponse, err

}

func (auth *webAuthn) SignInFinish(request *WebAuthnFinishRequest, w http.ResponseWriter) (*AuthenticationInfo, error) {
	res, err := auth.client.DoPostRequest(api.Routes.WebAuthnSignInFinish(), request, nil, "")
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(res, w)
}

func (auth *webAuthn) SignUpOrInStart(loginID string, origin string) (*WebAuthnTransactionResponse, error) {
	if loginID == "" {
		return nil, errors.NewInvalidArgumentError("loginID")
	}

	res, err := auth.client.DoPostRequest(api.Routes.WebAuthnSignUpOrInStart(), authenticationWebAuthnSignInRequestBody{LoginID: loginID, Origin: origin}, nil, "")
	if err != nil {
		return nil, err
	}

	webAuthnResponse := &WebAuthnTransactionResponse{}
	err = utils.Unmarshal([]byte(res.BodyStr), webAuthnResponse)
	return webAuthnResponse, err
}

func (auth *webAuthn) UpdateUserDeviceStart(loginID string, origin string, r *http.Request) (*WebAuthnTransactionResponse, error) {
	if loginID == "" {
		return nil, errors.NewInvalidArgumentError("loginID")
	}

	pswd, err := getValidRefreshToken(r)
	if err != nil {
		return nil, err
	}

	res, err := auth.client.DoPostRequest(api.Routes.WebAuthnUpdateUserDeviceStart(), authenticationWebAuthnAddDeviceRequestBody{LoginID: loginID, Origin: origin}, nil, pswd)
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
