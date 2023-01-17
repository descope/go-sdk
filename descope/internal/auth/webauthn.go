package auth

import (
	"net/http"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/errors"
	"github.com/descope/go-sdk/descope/internal/utils"
)

type webAuthn struct {
	authenticationsBase
}

func (auth *webAuthn) SignUpStart(loginID string, user *descope.User, origin string) (*descope.WebAuthnTransactionResponse, error) {
	if user == nil {
		user = &descope.User{}
	}
	uRes := &descope.WebauthnUserRequest{LoginID: loginID}
	if user != nil {
		uRes.Name = user.Name
	}
	res, err := auth.client.DoPostRequest(api.Routes.WebAuthnSignUpStart(), authenticationWebAuthnSignUpRequestBody{User: uRes, Origin: origin}, nil, "")
	if err != nil {
		return nil, err
	}

	webAuthnResponse := &descope.WebAuthnTransactionResponse{}
	err = utils.Unmarshal([]byte(res.BodyStr), webAuthnResponse)
	return webAuthnResponse, err
}

func (auth *webAuthn) SignUpFinish(request *descope.WebAuthnFinishRequest, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	res, err := auth.client.DoPostRequest(api.Routes.WebAuthnSignUpFinish(), request, nil, "")
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(res, w)
}

func (auth *webAuthn) SignInStart(loginID string, origin string, r *http.Request, loginOptions *descope.LoginOptions) (*descope.WebAuthnTransactionResponse, error) {
	if loginID == "" {
		return nil, errors.NewInvalidArgumentError("loginID")
	}
	var pswd string
	var err error
	if loginOptions.IsJWTRequired() {
		pswd, err = getValidRefreshToken(r)
		if err != nil {
			return nil, errors.ErrInvalidStepUpJWT
		}
	}

	res, err := auth.client.DoPostRequest(api.Routes.WebAuthnSignInStart(), authenticationWebAuthnSignInRequestBody{LoginID: loginID, Origin: origin, LoginOptions: loginOptions}, nil, pswd)
	if err != nil {
		return nil, err
	}

	webAuthnResponse := &descope.WebAuthnTransactionResponse{}
	err = utils.Unmarshal([]byte(res.BodyStr), webAuthnResponse)
	return webAuthnResponse, err

}

func (auth *webAuthn) SignInFinish(request *descope.WebAuthnFinishRequest, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	res, err := auth.client.DoPostRequest(api.Routes.WebAuthnSignInFinish(), request, nil, "")
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(res, w)
}

func (auth *webAuthn) SignUpOrInStart(loginID string, origin string) (*descope.WebAuthnTransactionResponse, error) {
	if loginID == "" {
		return nil, errors.NewInvalidArgumentError("loginID")
	}

	res, err := auth.client.DoPostRequest(api.Routes.WebAuthnSignUpOrInStart(), authenticationWebAuthnSignInRequestBody{LoginID: loginID, Origin: origin}, nil, "")
	if err != nil {
		return nil, err
	}

	webAuthnResponse := &descope.WebAuthnTransactionResponse{}
	err = utils.Unmarshal([]byte(res.BodyStr), webAuthnResponse)
	return webAuthnResponse, err
}

func (auth *webAuthn) UpdateUserDeviceStart(loginID string, origin string, r *http.Request) (*descope.WebAuthnTransactionResponse, error) {
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

	webAuthnResponse := &descope.WebAuthnTransactionResponse{}
	err = utils.Unmarshal([]byte(res.BodyStr), webAuthnResponse)
	return webAuthnResponse, err
}

func (auth *webAuthn) UpdateUserDeviceFinish(request *descope.WebAuthnFinishRequest) error {
	_, err := auth.client.DoPostRequest(api.Routes.WebAuthnUpdateUserDeviceFinish(), request, nil, "")
	return err
}
