package auth

import (
	"net/http"

	"github.com/descope/go-sdk/descope/errors"
)

func (auth *authenticationService) SignInOTP(method DeliveryMethod, identifier string) error {
	if identifier == "" {
		return errors.NewInvalidArgumentError("identifier")
	}

	_, err := auth.client.DoPostRequest(composeSignInURL(method), newSignInRequestBody(identifier), nil, "")
	return err
}

func (auth *authenticationService) SignUpOTP(method DeliveryMethod, identifier string, user *User) error {
	if err := auth.verifyDeliveryMethod(method, identifier); err != nil {
		return err
	}

	_, err := auth.client.DoPostRequest(composeSignUpURL(method), newAuthenticationSignUpRequestBody(method, identifier, user), nil, "")
	return err
}

func (auth *authenticationService) VerifyCode(method DeliveryMethod, identifier string, code string, w http.ResponseWriter) (*AuthenticationInfo, error) {
	return auth.VerifyCodeWithOptions(method, identifier, code, WithResponseOption(w))
}

func (auth *authenticationService) VerifyCodeWithOptions(method DeliveryMethod, identifier string, code string, options ...Option) (*AuthenticationInfo, error) {
	if identifier == "" {
		return nil, errors.NewInvalidArgumentError("identifier")
	}
	if method == "" {
		if phoneRegex.MatchString(identifier) {
			method = MethodSMS
		}

		if emailRegex.MatchString(identifier) {
			method = MethodEmail
		}

		if method == "" {
			return nil, errors.NewInvalidArgumentError("method")
		}
	}

	httpResponse, err := auth.client.DoPostRequest(composeVerifyCodeURL(method), newAuthenticationVerifyRequestBody(identifier, code), nil, "")
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(httpResponse, options...)
}
