package auth

import (
	"net/http"

	"github.com/descope/go-sdk/descope/errors"
	"github.com/descope/go-sdk/descope/utils"
)

type totp struct {
	authenticationsBase
}

func (auth *totp) SignUp(loginID string, user *User) (*TOTPResponse, error) {
	if loginID == "" {
		return nil, errors.NewInvalidArgumentError("loginID")
	}

	httpResponse, err := auth.client.DoPostRequest(composeSignUpTOTPURL(), newSignUPTOTPRequestBody(loginID, user), nil, "")
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

func (auth *totp) UpdateUser(loginID string, r *http.Request) (*TOTPResponse, error) {
	if loginID == "" {
		return nil, errors.NewInvalidArgumentError("loginID")
	}
	pswd, err := getValidRefreshToken(r)
	if err != nil {
		return nil, err
	}
	httpResponse, err := auth.client.DoPostRequest(composeUpdateTOTPURL(), newSignUPTOTPRequestBody(loginID, nil), nil, pswd)
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

func (auth *totp) SignInCode(loginID string, code string, r *http.Request, loginOptions *LoginOptions, w http.ResponseWriter) (*AuthenticationInfo, error) {
	if loginID == "" {
		return nil, errors.NewInvalidArgumentError("loginID")
	}
	var pswd string
	var err error
	if loginOptions.IsJWTRequired() {
		pswd, err = getValidRefreshToken(r)
		if err != nil {
			return nil, err
		}
	}

	httpResponse, err := auth.client.DoPostRequest(composeVerifyTOTPCodeURL(), newAuthenticationVerifyTOTPRequestBody(loginID, code, loginOptions), nil, pswd)
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(httpResponse, w)
}
