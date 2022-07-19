package auth

import (
	"net/http"

	"github.com/descope/go-sdk/descope/errors"
)

type magicLink struct {
	authenticationsBase
}

func (auth *magicLink) SignIn(method DeliveryMethod, identifier, URI string) error {
	if identifier == "" {
		return errors.NewInvalidArgumentError("identifier")
	}
	_, err := auth.client.DoPostRequest(composeMagicLinkSignInURL(method), newMagicLinkAuthenticationRequestBody(identifier, URI, false), nil, "")
	return err
}

func (auth *magicLink) SignUp(method DeliveryMethod, identifier, URI string, user *User) error {
	if user == nil {
		user = &User{}
	}
	if err := auth.verifyDeliveryMethod(method, identifier, user); err != nil {
		return err
	}

	_, err := auth.client.DoPostRequest(composeMagicLinkSignUpURL(method), newMagicLinkAuthenticationSignUpRequestBody(method, identifier, URI, user, false), nil, "")
	return err
}

func (auth *magicLink) SignUpOrIn(method DeliveryMethod, identifier, URI string) error {
	if identifier == "" {
		return errors.NewInvalidArgumentError("identifier")
	}
	_, err := auth.client.DoPostRequest(composeMagicLinkSignUpOrInURL(method), newMagicLinkAuthenticationRequestBody(identifier, URI, false), nil, "")
	return err
}

func (auth *magicLink) SignInCrossDevice(method DeliveryMethod, identifier, URI string) (*MagicLinkResponse, error) {
	if identifier == "" {
		return nil, errors.NewInvalidArgumentError("identifier")
	}
	httpResponse, err := auth.client.DoPostRequest(composeMagicLinkSignInURL(method), newMagicLinkAuthenticationRequestBody(identifier, URI, true), nil, "")
	if err != nil {
		return nil, err
	}
	return getPendingRefFromResponse(httpResponse)
}

func (auth *magicLink) SignUpCrossDevice(method DeliveryMethod, identifier, URI string, user *User) (*MagicLinkResponse, error) {
	if user == nil {
		user = &User{}
	}
	if err := auth.verifyDeliveryMethod(method, identifier, user); err != nil {
		return nil, err
	}

	httpResponse, err := auth.client.DoPostRequest(composeMagicLinkSignUpURL(method), newMagicLinkAuthenticationSignUpRequestBody(method, identifier, URI, user, true), nil, "")
	if err != nil {
		return nil, err
	}
	return getPendingRefFromResponse(httpResponse)
}

func (auth *magicLink) SignUpOrInCrossDevice(method DeliveryMethod, identifier, URI string) (*MagicLinkResponse, error) {
	if identifier == "" {
		return nil, errors.NewInvalidArgumentError("identifier")
	}
	httpResponse, err := auth.client.DoPostRequest(composeMagicLinkSignUpOrInURL(method), newMagicLinkAuthenticationRequestBody(identifier, URI, true), nil, "")
	if err != nil {
		return nil, err
	}
	return getPendingRefFromResponse(httpResponse)
}

func (auth *magicLink) GetSession(pendingRef string, w http.ResponseWriter) (*AuthenticationInfo, error) {
	return auth.GetSessionWithOptions(pendingRef, WithResponseOption(w))
}

func (auth *magicLink) GetSessionWithOptions(pendingRef string, options ...Option) (*AuthenticationInfo, error) {
	httpResponse, err := auth.client.DoPostRequest(composeGetSession(), newAuthenticationGetMagicLinkSessionBody(pendingRef), nil, "")
	if err != nil {
		if err == errors.UnauthorizedError {
			return nil, errors.MagicLinkUnauthorized
		}
		return nil, err
	}
	return auth.generateAuthenticationInfo(httpResponse, options...)
}

func (auth *magicLink) Verify(token string, w http.ResponseWriter) (*AuthenticationInfo, error) {
	return auth.VerifyWithOptions(token, WithResponseOption(w))
}

func (auth *magicLink) VerifyWithOptions(token string, options ...Option) (*AuthenticationInfo, error) {
	httpResponse, err := auth.client.DoPostRequest(composeVerifyMagicLinkURL(), newMagicLinkAuthenticationVerifyRequestBody(token), nil, "")
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(httpResponse, options...)
}

func (auth *magicLink) UpdateUserEmail(identifier, email, URI string, r *http.Request) error {
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
	_, err = auth.client.DoPostRequest(composeUpdateUserEmailMagicLink(), newMagicLinkUpdateEmailRequestBody(identifier, email, URI, false), nil, pswd)
	return err
}

func (auth *magicLink) UpdateUserEmailCrossDevice(identifier, email, URI string, r *http.Request) (*MagicLinkResponse, error) {
	if identifier == "" {
		return nil, errors.NewInvalidArgumentError("identifier")
	}
	if email == "" {
		return nil, errors.NewInvalidArgumentError("email")
	}
	if !emailRegex.MatchString(email) {
		return nil, errors.NewInvalidArgumentError("email")
	}
	pswd, err := getValidRefreshToken(r)
	if err != nil {
		return nil, err
	}
	httpResponse, err := auth.client.DoPostRequest(composeUpdateUserEmailMagicLink(), newMagicLinkUpdateEmailRequestBody(identifier, email, URI, true), nil, pswd)
	if err != nil {
		return nil, err
	}
	return getPendingRefFromResponse(httpResponse)
}

func (auth *magicLink) UpdateUserPhone(method DeliveryMethod, identifier, phone, URI string, r *http.Request) error {
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
	_, err = auth.client.DoPostRequest(composeUpdateUserPhone(method), newMagicLinkUpdatePhoneRequestBody(identifier, phone, URI, false), nil, pswd)
	return err
}

func (auth *magicLink) UpdateUserPhoneCrossDevice(method DeliveryMethod, identifier, phone, URI string, r *http.Request) (*MagicLinkResponse, error) {
	if identifier == "" {
		return nil, errors.NewInvalidArgumentError("identifier")
	}
	if phone == "" {
		return nil, errors.NewInvalidArgumentError("phone")
	}
	if !phoneRegex.MatchString(phone) {
		return nil, errors.NewInvalidArgumentError("phone")
	}
	if method != MethodSMS && method != MethodWhatsApp {
		return nil, errors.NewInvalidArgumentError("method")
	}
	pswd, err := getValidRefreshToken(r)
	if err != nil {
		return nil, err
	}
	httpResponse, err := auth.client.DoPostRequest(composeUpdateUserPhone(method), newMagicLinkUpdatePhoneRequestBody(identifier, phone, URI, true), nil, pswd)
	if err != nil {
		return nil, err
	}
	return getPendingRefFromResponse(httpResponse)
}
