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
	return auth.authenticationInfoFromResponse(httpResponse, options...)
}

func (auth *authenticationService) VerifyMagicLink(token string, w http.ResponseWriter) (*AuthenticationInfo, error) {
	return auth.VerifyMagicLinkWithOptions(token, WithResponseOption(w))
}

func (auth *authenticationService) VerifyMagicLinkWithOptions(token string, options ...Option) (*AuthenticationInfo, error) {
	httpResponse, err := auth.client.DoPostRequest(composeVerifyMagicLinkURL(), newMagicLinkAuthenticationVerifyRequestBody(token), nil, "")
	if err != nil {
		return nil, err
	}
	return auth.authenticationInfoFromResponse(httpResponse, options...)
}
