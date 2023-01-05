package auth

import (
	"net/http"

	"github.com/descope/go-sdk/descope/errors"
)

type enchantedLink struct {
	authenticationsBase
}

func (auth *enchantedLink) SignIn(loginID, URI string, r *http.Request, loginOptions *LoginOptions) (*EnchantedLinkResponse, error) {
	var pswd string
	var err error
	if loginID == "" {
		return nil, errors.NewInvalidArgumentError("loginID")
	}
	if loginOptions.IsJWTRequired() {
		pswd, err = getValidRefreshToken(r)
		if err != nil {
			return nil, errors.InvalidStepupJwtError
		}
	}
	httpResponse, err := auth.client.DoPostRequest(composeEnchantedLinkSignInURL(), newMagicLinkAuthenticationRequestBody(loginID, URI, true, loginOptions), nil, pswd)
	if err != nil {
		return nil, err
	}
	return getPendingRefFromResponse(httpResponse)
}

func (auth *enchantedLink) SignUp(loginID, URI string, user *User) (*EnchantedLinkResponse, error) {
	if loginID == "" {
		return nil, errors.NewInvalidArgumentError("loginID")
	}
	if user == nil {
		user = &User{}
	}
	if len(user.Email) == 0 {
		user.Email = loginID
	}

	httpResponse, err := auth.client.DoPostRequest(composeEnchantedLinkSignUpURL(), newMagicLinkAuthenticationSignUpRequestBody(MethodEmail, loginID, URI, user, true), nil, "")
	if err != nil {
		return nil, err
	}
	return getPendingRefFromResponse(httpResponse)
}

func (auth *enchantedLink) SignUpOrIn(loginID, URI string) (*EnchantedLinkResponse, error) {
	if loginID == "" {
		return nil, errors.NewInvalidArgumentError("loginID")
	}
	httpResponse, err := auth.client.DoPostRequest(composeEnchantedLinkSignUpOrInURL(), newMagicLinkAuthenticationRequestBody(loginID, URI, true, nil), nil, "")
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
			return nil, errors.EnchantedLinkUnauthorized
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

func (auth *enchantedLink) UpdateUserEmail(loginID, email, URI string, r *http.Request) (*EnchantedLinkResponse, error) {
	if loginID == "" {
		return nil, errors.NewInvalidArgumentError("loginID")
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
	httpResponse, err := auth.client.DoPostRequest(composeUpdateUserEmailEnchantedLink(), newMagicLinkUpdateEmailRequestBody(loginID, email, URI, true), nil, pswd)
	if err != nil {
		return nil, err
	}
	return getPendingRefFromResponse(httpResponse)
}
