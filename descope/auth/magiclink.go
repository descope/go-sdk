package auth

import (
	"net/http"

	"github.com/descope/go-sdk/descope/errors"
)

func (auth *authenticationService) SignInMagicLink(method DeliveryMethod, identifier, URI string) error {
	if identifier == "" {
		return errors.NewInvalidArgumentError("identifier")
	}
	_, err := auth.client.DoPostRequest(composeMagicLinkSignInURL(method), newMagicLinkAuthenticationRequestBody(identifier, URI, false), nil, "")
	return err
}

func (auth *authenticationService) SignUpMagicLink(method DeliveryMethod, identifier, URI string, user *User) error {
	if err := auth.verifyDeliveryMethod(method, identifier); err != nil {
		return err
	}

	_, err := auth.client.DoPostRequest(composeMagicLinkSignUpURL(method), newMagicLinkAuthenticationSignUpRequestBody(method, identifier, URI, user, false), nil, "")
	return err
}

func (auth *authenticationService) SignUpOrInMagicLink(method DeliveryMethod, identifier, URI string) error {
	if identifier == "" {
		return errors.NewInvalidArgumentError("identifier")
	}
	_, err := auth.client.DoPostRequest(composeMagicLinkSignUpOrInURL(method), newMagicLinkAuthenticationRequestBody(identifier, URI, false), nil, "")
	return err
}

func (auth *authenticationService) SignInMagicLinkCrossDevice(method DeliveryMethod, identifier, URI string) (*MagicLinkResponse, error) {
	if identifier == "" {
		return nil, errors.NewInvalidArgumentError("identifier")
	}
	httpResponse, err := auth.client.DoPostRequest(composeMagicLinkSignInURL(method), newMagicLinkAuthenticationRequestBody(identifier, URI, true), nil, "")
	if err != nil {
		return nil, err
	}
	return getPendingRefFromResponse(httpResponse)
}

func (auth *authenticationService) SignUpMagicLinkCrossDevice(method DeliveryMethod, identifier, URI string, user *User) (*MagicLinkResponse, error) {
	if err := auth.verifyDeliveryMethod(method, identifier); err != nil {
		return nil, err
	}

	httpResponse, err := auth.client.DoPostRequest(composeMagicLinkSignUpURL(method), newMagicLinkAuthenticationSignUpRequestBody(method, identifier, URI, user, true), nil, "")
	if err != nil {
		return nil, err
	}
	return getPendingRefFromResponse(httpResponse)
}

func (auth *authenticationService) SignUpOrInMagicLinkCrossDevice(method DeliveryMethod, identifier, URI string) (*MagicLinkResponse, error) {
	if identifier == "" {
		return nil, errors.NewInvalidArgumentError("identifier")
	}
	httpResponse, err := auth.client.DoPostRequest(composeMagicLinkSignUpOrInURL(method), newMagicLinkAuthenticationRequestBody(identifier, URI, true), nil, "")
	if err != nil {
		return nil, err
	}
	return getPendingRefFromResponse(httpResponse)
}

func (auth *authenticationService) GetMagicLinkSession(pendingRef string, w http.ResponseWriter) (*AuthenticationInfo, error) {
	return auth.GetMagicLinkSessionWithOptions(pendingRef, WithResponseOption(w))
}

func (auth *authenticationService) GetMagicLinkSessionWithOptions(pendingRef string, options ...Option) (*AuthenticationInfo, error) {
	httpResponse, err := auth.client.DoPostRequest(composeGetMagicLinkSession(), newAuthenticationGetMagicLinkSessionBody(pendingRef), nil, "")
	if err != nil {
		if err == errors.UnauthorizedError {
			return nil, errors.MagicLinkUnauthorized
		}
		return nil, err
	}
	return auth.generateAuthenticationInfo(httpResponse, options...)
}

func (auth *authenticationService) VerifyMagicLink(token string, w http.ResponseWriter) (*AuthenticationInfo, error) {
	return auth.VerifyMagicLinkWithOptions(token, WithResponseOption(w))
}

func (auth *authenticationService) VerifyMagicLinkWithOptions(token string, options ...Option) (*AuthenticationInfo, error) {
	httpResponse, err := auth.client.DoPostRequest(composeVerifyMagicLinkURL(), newMagicLinkAuthenticationVerifyRequestBody(token), nil, "")
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(httpResponse, options...)
}

func (auth *authenticationService) UpdateUserEmailMagicLink(identifier, email, URI string, r *http.Request) error {
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

func (auth *authenticationService) UpdateUserEmailMagicLinkCrossDevice(identifier, email, URI string, r *http.Request) (*MagicLinkResponse, error) {
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

func (auth *authenticationService) UpdateUserPhoneMagicLink(method DeliveryMethod, identifier, phone, URI string, r *http.Request) error {
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
	_, err = auth.client.DoPostRequest(composeUpdateUserPhoneMagicLink(method), newMagicLinkUpdatePhoneRequestBody(identifier, phone, URI, false), nil, pswd)
	return err
}

func (auth *authenticationService) UpdateUserPhoneMagicLinkCrossDevice(method DeliveryMethod, identifier, phone, URI string, r *http.Request) (*MagicLinkResponse, error) {
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
	httpResponse, err := auth.client.DoPostRequest(composeUpdateUserPhoneMagicLink(method), newMagicLinkUpdatePhoneRequestBody(identifier, phone, URI, true), nil, pswd)
	if err != nil {
		return nil, err
	}
	return getPendingRefFromResponse(httpResponse)
}
