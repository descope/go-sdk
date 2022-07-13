package auth

import (
	"net/http"

	"github.com/descope/go-sdk/descope/errors"
	"github.com/descope/go-sdk/descope/utils"
)

func (auth *authenticationService) SignUpTOTP(identifier string, user *User) (*TOTPResponse, error) {
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

func (auth *authenticationService) UpdateUserTOTP(identifier string, r *http.Request) (*TOTPResponse, error) {
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

func (auth *authenticationService) SignInTOTPCode(identifier string, code string, w http.ResponseWriter) (*AuthenticationInfo, error) {
	return auth.SignInTOTPCodeWithOptions(identifier, code, WithResponseOption(w))
}

func (auth *authenticationService) SignInTOTPCodeWithOptions(identifier, code string, options ...Option) (*AuthenticationInfo, error) {
	if identifier == "" {
		return nil, errors.NewInvalidArgumentError("identifier")
	}

	httpResponse, err := auth.client.DoPostRequest(composeVerifyTOTPCodeURL(), newAuthenticationVerifyRequestBody(identifier, code), nil, "")
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(httpResponse, options...)
}
