package auth

import (
	"net/http"

	"github.com/descope/go-sdk/descope/errors"
)

type magicLink struct {
	authenticationsBase
}

func (auth *magicLink) SignIn(method DeliveryMethod, loginID, URI string, r *http.Request, loginOptions *LoginOptions) error {
	var pswd string
	var err error
	if loginID == "" {
		return errors.NewInvalidArgumentError("loginID")
	}
	if loginOptions.IsJWTRequired() {
		pswd, err = getValidRefreshToken(r)
		if err != nil {
			return errors.InvalidStepupJwtError
		}
	}

	_, err = auth.client.DoPostRequest(composeMagicLinkSignInURL(method), newMagicLinkAuthenticationRequestBody(loginID, URI, false, loginOptions), nil, pswd)
	return err
}

func (auth *magicLink) SignUp(method DeliveryMethod, loginID, URI string, user *User) error {
	if user == nil {
		user = &User{}
	}
	if err := auth.verifyDeliveryMethod(method, loginID, user); err != nil {
		return err
	}

	_, err := auth.client.DoPostRequest(composeMagicLinkSignUpURL(method), newMagicLinkAuthenticationSignUpRequestBody(method, loginID, URI, user, false), nil, "")
	return err
}

func (auth *magicLink) SignUpOrIn(method DeliveryMethod, loginID, URI string) error {
	if loginID == "" {
		return errors.NewInvalidArgumentError("loginID")
	}
	_, err := auth.client.DoPostRequest(composeMagicLinkSignUpOrInURL(method), newMagicLinkAuthenticationRequestBody(loginID, URI, false, nil), nil, "")
	return err
}

func (auth *magicLink) Verify(token string, w http.ResponseWriter) (*AuthenticationInfo, error) {
	var err error

	httpResponse, err := auth.client.DoPostRequest(composeVerifyMagicLinkURL(), newMagicLinkAuthenticationVerifyRequestBody(token), nil, "")
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(httpResponse, w)
}

func (auth *magicLink) UpdateUserEmail(loginID, email, URI string, r *http.Request) error {
	if loginID == "" {
		return errors.NewInvalidArgumentError("loginID")
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
	_, err = auth.client.DoPostRequest(composeUpdateUserEmailMagicLink(), newMagicLinkUpdateEmailRequestBody(loginID, email, URI, false), nil, pswd)
	return err
}

func (auth *magicLink) UpdateUserPhone(method DeliveryMethod, loginID, phone, URI string, r *http.Request) error {
	if loginID == "" {
		return errors.NewInvalidArgumentError("loginID")
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
	_, err = auth.client.DoPostRequest(composeUpdateUserPhoneMagiclink(method), newMagicLinkUpdatePhoneRequestBody(loginID, phone, URI, false), nil, pswd)
	return err
}
