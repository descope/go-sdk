package auth

import (
	"context"
	"net/http"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
)

type webAuthn struct {
	authenticationsBase
}

func (auth *webAuthn) SignUpStart(ctx context.Context, loginID string, user *descope.User, origin string) (*descope.WebAuthnTransactionResponse, error) {
	if user == nil {
		user = &descope.User{}
	}
	res, err := auth.client.DoPostRequest(ctx, api.Routes.WebAuthnSignUpStart(), authenticationWebAuthnSignUpRequestBody{LoginID: loginID, User: user, Origin: origin}, nil, "")
	if err != nil {
		return nil, err
	}

	webAuthnResponse := &descope.WebAuthnTransactionResponse{}
	err = utils.Unmarshal([]byte(res.BodyStr), webAuthnResponse)
	return webAuthnResponse, err
}

func (auth *webAuthn) SignUpFinish(ctx context.Context, request *descope.WebAuthnFinishRequest, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	res, err := auth.client.DoPostRequest(ctx, api.Routes.WebAuthnSignUpFinish(), request, nil, "")
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(res, w)
}

func (auth *webAuthn) SignInStart(ctx context.Context, loginID string, origin string, r *http.Request, loginOptions *descope.LoginOptions) (*descope.WebAuthnTransactionResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	var pswd string
	var err error
	if loginOptions.IsJWTRequired() {
		pswd, err = getValidRefreshToken(r)
		if err != nil {
			return nil, descope.ErrInvalidStepUpJWT
		}
	}

	res, err := auth.client.DoPostRequest(ctx, api.Routes.WebAuthnSignInStart(), authenticationWebAuthnSignInRequestBody{LoginID: loginID, Origin: origin, LoginOptions: loginOptions}, nil, pswd)
	if err != nil {
		return nil, err
	}

	webAuthnResponse := &descope.WebAuthnTransactionResponse{}
	err = utils.Unmarshal([]byte(res.BodyStr), webAuthnResponse)
	return webAuthnResponse, err

}

func (auth *webAuthn) SignInFinish(ctx context.Context, request *descope.WebAuthnFinishRequest, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	res, err := auth.client.DoPostRequest(ctx, api.Routes.WebAuthnSignInFinish(), request, nil, "")
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(res, w)
}

func (auth *webAuthn) SignUpOrInStart(ctx context.Context, loginID string, origin string) (*descope.WebAuthnTransactionResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}

	res, err := auth.client.DoPostRequest(ctx, api.Routes.WebAuthnSignUpOrInStart(), authenticationWebAuthnSignInRequestBody{LoginID: loginID, Origin: origin}, nil, "")
	if err != nil {
		return nil, err
	}

	webAuthnResponse := &descope.WebAuthnTransactionResponse{}
	err = utils.Unmarshal([]byte(res.BodyStr), webAuthnResponse)
	return webAuthnResponse, err
}

func (auth *webAuthn) UpdateUserDeviceStart(ctx context.Context, loginID string, origin string, r *http.Request) (*descope.WebAuthnTransactionResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}

	pswd, err := getValidRefreshToken(r)
	if err != nil {
		return nil, err
	}

	res, err := auth.client.DoPostRequest(ctx, api.Routes.WebAuthnUpdateUserDeviceStart(), authenticationWebAuthnAddDeviceRequestBody{LoginID: loginID, Origin: origin}, nil, pswd)
	if err != nil {
		return nil, err
	}

	webAuthnResponse := &descope.WebAuthnTransactionResponse{}
	err = utils.Unmarshal([]byte(res.BodyStr), webAuthnResponse)
	return webAuthnResponse, err
}

func (auth *webAuthn) UpdateUserDeviceFinish(ctx context.Context, request *descope.WebAuthnFinishRequest) error {
	_, err := auth.client.DoPostRequest(ctx, api.Routes.WebAuthnUpdateUserDeviceFinish(), request, nil, "")
	return err
}
