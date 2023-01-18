package auth

import (
	"net/http"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/internal/utils"
)

type otp struct {
	authenticationsBase
}

func (auth *otp) SignIn(method descope.DeliveryMethod, loginID string, r *http.Request, loginOptions *descope.LoginOptions) error {
	var pswd string
	var err error
	if loginID == "" {
		return utils.NewInvalidArgumentError("loginID")
	}
	if loginOptions.IsJWTRequired() {
		pswd, err = getValidRefreshToken(r)
		if err != nil {
			return descope.ErrInvalidStepUpJWT
		}
	}

	_, err = auth.client.DoPostRequest(composeSignInURL(method), newSignInRequestBody(loginID, loginOptions), nil, pswd)
	return err
}

func (auth *otp) SignUp(method descope.DeliveryMethod, loginID string, user *descope.User) error {
	if user == nil {
		user = &descope.User{}
	}
	if err := auth.verifyDeliveryMethod(method, loginID, user); err != nil {
		return err
	}

	_, err := auth.client.DoPostRequest(composeSignUpURL(method), newAuthenticationSignUpRequestBody(method, loginID, user), nil, "")
	return err
}

func (auth *otp) SignUpOrIn(method descope.DeliveryMethod, loginID string) error {
	if loginID == "" {
		return utils.NewInvalidArgumentError("loginID")
	}

	_, err := auth.client.DoPostRequest(composeSignUpOrInURL(method), newSignInRequestBody(loginID, nil), nil, "")
	return err
}

func (auth *otp) VerifyCode(method descope.DeliveryMethod, loginID string, code string, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	if method == "" {
		if phoneRegex.MatchString(loginID) {
			method = descope.MethodSMS
		}

		if emailRegex.MatchString(loginID) {
			method = descope.MethodEmail
		}

		if method == "" {
			return nil, utils.NewInvalidArgumentError("method")
		}
	}
	httpResponse, err := auth.client.DoPostRequest(composeVerifyCodeURL(method), newAuthenticationVerifyRequestBody(loginID, code), nil, "")
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(httpResponse, w)
}

func (auth *otp) UpdateUserEmail(loginID, email string, r *http.Request) error {
	if loginID == "" {
		return utils.NewInvalidArgumentError("loginID")
	}
	if email == "" {
		return utils.NewInvalidArgumentError("email")
	}
	if !emailRegex.MatchString(email) {
		return utils.NewInvalidArgumentError("email")
	}
	pswd, err := getValidRefreshToken(r)
	if err != nil {
		return err
	}
	_, err = auth.client.DoPostRequest(composeUpdateUserEmailOTP(), newOTPUpdateEmailRequestBody(loginID, email), nil, pswd)
	return err
}

func (auth *otp) UpdateUserPhone(method descope.DeliveryMethod, loginID, phone string, r *http.Request) error {
	if loginID == "" {
		return utils.NewInvalidArgumentError("loginID")
	}
	if phone == "" {
		return utils.NewInvalidArgumentError("phone")
	}
	if !phoneRegex.MatchString(phone) {
		return utils.NewInvalidArgumentError("phone")
	}
	if method != descope.MethodSMS && method != descope.MethodWhatsApp {
		return utils.NewInvalidArgumentError("method")
	}
	pswd, err := getValidRefreshToken(r)
	if err != nil {
		return err
	}
	_, err = auth.client.DoPostRequest(composeUpdateUserPhoneOTP(method), newOTPUpdatePhoneRequestBody(loginID, phone), nil, pswd)
	return err
}
