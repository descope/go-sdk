package auth

import (
	"net/http"

	"github.com/descope/go-sdk/descope/errors"
	"github.com/descope/go-sdk/descope/utils"
)

type totp struct {
	authenticationsBase
}

func (auth *totp) SignUp(identifier string, user *User) (*TOTPResponse, error) {
	if identifier == "" {
		return nil, errors.NewInvalidArgumentError("identifier")
	}

	httpResponse, err := auth.client.DoPostRequest(composeSignUpTOTPURL(), newSignUPTOTPRequestBody(identifier, user), nil, "")
	if err != nil {
		return nil, err
	}
	totpResponse := &TOTPResponse{}
	err = utils.Unmarshal([]byte(httpResponse.BodyStr), totpResponse)
	if err != nil {
		return nil, err
	}
	return totpResponse, nil
}

func (auth *totp) UpdateUser(identifier string, r *http.Request) (*TOTPResponse, error) {
	if identifier == "" {
		return nil, errors.NewInvalidArgumentError("identifier")
	}
	pswd, err := getValidRefreshToken(r)
	if err != nil {
		return nil, err
	}
	httpResponse, err := auth.client.DoPostRequest(composeUpdateTOTPURL(), newSignUPTOTPRequestBody(identifier, nil), nil, pswd)
	if err != nil {
		return nil, err
	}
	totpResponse := &TOTPResponse{}
	err = utils.Unmarshal([]byte(httpResponse.BodyStr), totpResponse)
	if err != nil {
		return nil, err
	}
	return totpResponse, nil
}

func (auth *totp) SignInCode(identifier string, code string, r *http.Request, loginOptions *LoginOptions, w http.ResponseWriter) (*AuthenticationInfo, error) {
	if identifier == "" {
		return nil, errors.NewInvalidArgumentError("identifier")
	}
	var pswd string
	var err error
	if loginOptions.IsJWTRequired() {
		pswd, err = getValidRefreshToken(r)
		if err != nil {
			return nil, err
		}
	}

	httpResponse, err := auth.client.DoPostRequest(composeVerifyTOTPCodeURL(), newAuthenticationVerifyTOTPRequestBody(identifier, code, loginOptions), nil, pswd)
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(httpResponse, w)
}
