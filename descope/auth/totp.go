package auth

import (
	"encoding/json"
	"net/http"

	"github.com/descope/go-sdk/descope/errors"
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
	err = json.Unmarshal([]byte(httpResponse.BodyStr), totpResponse)
	if err != nil {
		return nil, err
	}
	return totpResponse, nil
}

func (auth *authenticationService) VerifyTOTPCode(identifier string, code string, w http.ResponseWriter) (*AuthenticationInfo, error) {
	return auth.VerifyTOTPCodeWithOptions(identifier, code, WithResponseOption(w))
}
func (auth *authenticationService) VerifyTOTPCodeWithOptions(identifier, code string, options ...Option) (*AuthenticationInfo, error) {
	if identifier == "" {
		return nil, errors.NewInvalidArgumentError("identifier")
	}

	httpResponse, err := auth.client.DoPostRequest(composeVerifyTOTPCodeURL(), newAuthenticationVerifyRequestBody(identifier, code), nil, "")
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(httpResponse, options...)
}
