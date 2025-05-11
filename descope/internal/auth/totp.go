package auth

import (
	"context"
	"net/http"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/internal/utils"
)

type totp struct {
	authenticationsBase
}

func (auth *totp) SignUp(ctx context.Context, loginID string, user *descope.User) (*descope.TOTPResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}

	httpResponse, err := auth.client.DoPostRequest(ctx, composeSignUpTOTPURL(), newSignUPTOTPRequestBody(loginID, user), nil, "")
	if err != nil {
		return nil, err
	}
	totpResponse := &descope.TOTPResponse{}
	err = utils.Unmarshal([]byte(httpResponse.BodyStr), totpResponse)
	if err != nil {
		return nil, err
	}
	return totpResponse, nil
}

func (auth *totp) UpdateUser(ctx context.Context, loginID string, r *http.Request) (*descope.TOTPResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	pswd, err := auth.getValidRefreshToken(r)
	if err != nil {
		return nil, err
	}
	httpResponse, err := auth.client.DoPostRequest(ctx, composeUpdateTOTPURL(), newSignUPTOTPRequestBody(loginID, nil), nil, pswd)
	if err != nil {
		return nil, err
	}
	totpResponse := &descope.TOTPResponse{}
	err = utils.Unmarshal([]byte(httpResponse.BodyStr), totpResponse)
	if err != nil {
		return nil, err
	}
	return totpResponse, nil
}

func (auth *totp) SignInCode(ctx context.Context, loginID string, code string, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	var pswd string
	var err error
	if loginOptions.IsJWTRequired() {
		pswd, err = auth.getValidRefreshToken(r)
		if err != nil {
			return nil, err
		}
	}

	httpResponse, err := auth.client.DoPostRequest(ctx, composeVerifyTOTPCodeURL(), newAuthenticationVerifyTOTPRequestBody(loginID, code, loginOptions), nil, pswd)
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(httpResponse, w)
}
