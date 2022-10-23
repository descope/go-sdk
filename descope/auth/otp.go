package auth

import (
	"net/http"

	"github.com/descope/go-sdk/descope/errors"
)

type otp struct {
	authenticationsBase
}

func (auth *otp) SignIn(method DeliveryMethod, identifier string) error {
	if identifier == "" {
		return errors.NewInvalidArgumentError("identifier")
	}

	_, err := auth.client.DoPostRequest(composeSignInURL(method), newSignInRequestBody(identifier), nil, "")
	return err
}

func (auth *otp) SignUp(method DeliveryMethod, identifier string, user *User) error {
	if user == nil {
		user = &User{}
	}
	if err := auth.verifyDeliveryMethod(method, identifier, user); err != nil {
		return err
	}

	_, err := auth.client.DoPostRequest(composeSignUpURL(method), newAuthenticationSignUpRequestBody(method, identifier, user), nil, "")
	return err
}

func (auth *otp) SignUpOrIn(method DeliveryMethod, identifier string) error {
	if identifier == "" {
		return errors.NewInvalidArgumentError("identifier")
	}

	_, err := auth.client.DoPostRequest(composeSignUpOrInURL(method), newSignInRequestBody(identifier), nil, "")
	return err
}

func (auth *otp) VerifyCode(method DeliveryMethod, identifier string, code string, w http.ResponseWriter) (*AuthenticationInfo, error) {
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
	return auth.generateAuthenticationInfo(httpResponse, w)
}

func (auth *otp) UpdateUserEmail(identifier, email string, r *http.Request) error {
	if identifier == "" {
		return errors.NewInvalidArgumentError("identifier")
	}
	if email == "" {
		return errors.NewInvalidArgumentError("email")
	}
	if !emailRegex.MatchString(email) {
		return errors.NewInvalidArgumentError("email")
	}
	pswd, err := getValidRefreshToken(r)
	if err != nil {
		return err
	}
	_, err = auth.client.DoPostRequest(composeUpdateUserEmailOTP(), newOTPUpdateEmailRequestBody(identifier, email), nil, pswd)
	return err
}

func (auth *otp) UpdateUserPhone(method DeliveryMethod, identifier, phone string, r *http.Request) error {
	if identifier == "" {
		return errors.NewInvalidArgumentError("identifier")
	}
	if phone == "" {
		return errors.NewInvalidArgumentError("phone")
	}
	if !phoneRegex.MatchString(phone) {
		return errors.NewInvalidArgumentError("phone")
	}
	if method != MethodSMS && method != MethodWhatsApp {
		return errors.NewInvalidArgumentError("method")
	}
	pswd, err := getValidRefreshToken(r)
	if err != nil {
		return err
	}
	_, err = auth.client.DoPostRequest(composeUpdateUserPhone(method), newOTPUpdatePhoneRequestBody(identifier, phone), nil, pswd)
	return err
}
