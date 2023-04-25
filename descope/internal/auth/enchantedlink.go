package auth

import (
	"net/http"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/internal/utils"
)

type enchantedLink struct {
	authenticationsBase
}

func (auth *enchantedLink) SignIn(loginID, URI string, r *http.Request, loginOptions *descope.LoginOptions) (*descope.EnchantedLinkResponse, error) {
	var pswd string
	var err error
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	if loginOptions.IsJWTRequired() {
		pswd, err = getValidRefreshToken(r)
		if err != nil {
			return nil, descope.ErrInvalidStepUpJWT
		}
	}
	httpResponse, err := auth.client.DoPostRequest(composeEnchantedLinkSignInURL(), newMagicLinkAuthenticationRequestBody(loginID, URI, true, loginOptions), nil, pswd)
	if err != nil {
		return nil, err
	}
	return getPendingRefFromResponse(httpResponse)
}

func (auth *enchantedLink) SignUp(loginID, URI string, user *descope.User) (*descope.EnchantedLinkResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	if user == nil {
		user = &descope.User{}
	}
	if len(user.Email) == 0 {
		user.Email = loginID
	}

	httpResponse, err := auth.client.DoPostRequest(composeEnchantedLinkSignUpURL(), newMagicLinkAuthenticationSignUpRequestBody(descope.MethodEmail, loginID, URI, user, true), nil, "")
	if err != nil {
		return nil, err
	}
	return getPendingRefFromResponse(httpResponse)
}

func (auth *enchantedLink) SignUpOrIn(loginID, URI string) (*descope.EnchantedLinkResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	httpResponse, err := auth.client.DoPostRequest(composeEnchantedLinkSignUpOrInURL(), newMagicLinkAuthenticationRequestBody(loginID, URI, true, nil), nil, "")
	if err != nil {
		return nil, err
	}
	return getPendingRefFromResponse(httpResponse)
}

func (auth *enchantedLink) GetSession(pendingRef string, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	var err error
	httpResponse, err := auth.client.DoPostRequest(composeGetSession(), newAuthenticationGetMagicLinkSessionBody(pendingRef), nil, "")
	if err != nil {
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

func (auth *enchantedLink) UpdateUserEmail(loginID, email, URI string, updateOptions *descope.UpdateOptions, r *http.Request) (*descope.EnchantedLinkResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	if email == "" {
		return nil, utils.NewInvalidArgumentError("email")
	}
	if !emailRegex.MatchString(email) {
		return nil, utils.NewInvalidArgumentError("email")
	}
	pswd, err := getValidRefreshToken(r)
	if err != nil {
		return nil, err
	}
	if updateOptions == nil {
		updateOptions = &descope.UpdateOptions{}
	}
	httpResponse, err := auth.client.DoPostRequest(composeUpdateUserEmailEnchantedLink(), newMagicLinkUpdateEmailRequestBody(loginID, email, URI, true, updateOptions), nil, pswd)
	if err != nil {
		return nil, err
	}
	return getPendingRefFromResponse(httpResponse)
}
