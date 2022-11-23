package auth

import (
	"net/http"

	"github.com/descope/go-sdk/descope/errors"
)

type enchantedLink struct {
	authenticationsBase
}

func (auth *enchantedLink) SignIn(identifier, URI string, r *http.Request, loginOptions *LoginOptions) (*EnchantedLinkResponse, error) {
	var pswd string
	var err error
	if identifier == "" {
		return nil, errors.NewInvalidArgumentError("identifier")
	}
	if loginOptions.IsJWTRequired() {
		pswd, err = getValidRefreshToken(r)
		if err != nil {
			return nil, errors.InvalidStepupJwtError
		}
	}
	httpResponse, err := auth.client.DoPostRequest(composeEnchantedLinkSignInURL(), newMagicLinkAuthenticationRequestBody(identifier, URI, true, loginOptions), nil, pswd)
	if err != nil {
		return nil, err
	}
	return getPendingRefFromResponse(httpResponse)
}

func (auth *enchantedLink) SignUp(identifier, URI string, user *User) (*EnchantedLinkResponse, error) {
	if identifier == "" {
		return nil, errors.NewInvalidArgumentError("identifier")
	}
	if user == nil {
		user = &User{}
	}
	if len(user.Email) == 0 {
		user.Email = identifier
	}

	httpResponse, err := auth.client.DoPostRequest(composeEnchantedLinkSignUpURL(), newMagicLinkAuthenticationSignUpRequestBody(MethodEmail, identifier, URI, user, true), nil, "")
	if err != nil {
		return nil, err
	}
	return getPendingRefFromResponse(httpResponse)
}

func (auth *enchantedLink) SignUpOrIn(identifier, URI string) (*EnchantedLinkResponse, error) {
	if identifier == "" {
		return nil, errors.NewInvalidArgumentError("identifier")
	}
	httpResponse, err := auth.client.DoPostRequest(composeEnchantedLinkSignUpOrInURL(), newMagicLinkAuthenticationRequestBody(identifier, URI, true, nil), nil, "")
	if err != nil {
		return nil, err
	}
	return getPendingRefFromResponse(httpResponse)
}

func (auth *enchantedLink) GetSession(pendingRef string, w http.ResponseWriter) (*AuthenticationInfo, error) {
	var err error
	httpResponse, err := auth.client.DoPostRequest(composeGetSession(), newAuthenticationGetMagicLinkSessionBody(pendingRef), nil, "")
	if err != nil {
		if err == errors.UnauthorizedError {
			return nil, errors.MagicLinkUnauthorized
		}
		return nil, err
	}
	return auth.generateAuthenticationInfo(httpResponse, w)
}

func (auth *enchantedLink) Verify(token string) error {
	_, err := auth.client.DoPostRequest(composeVerifyEnchantedLinkURL(), newMagicLinkAuthenticationVerifyRequestBody(token), nil, "")
	if err != nil {
		return err
	}
	return nil
}

func (auth *enchantedLink) UpdateUserEmail(identifier, email, URI string, r *http.Request) (*EnchantedLinkResponse, error) {
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
	httpResponse, err := auth.client.DoPostRequest(composeUpdateUserEmailEnchantedLink(), newMagicLinkUpdateEmailRequestBody(identifier, email, URI, true), nil, pswd)
	if err != nil {
		return nil, err
	}
	return getPendingRefFromResponse(httpResponse)
}
