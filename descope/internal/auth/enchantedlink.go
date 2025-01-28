package auth

import (
	"context"
	"net/http"

	"github.com/descope/go-sdk/v2/descope"
	"github.com/descope/go-sdk/v2/descope/internal/utils"
)

type enchantedLink struct {
	authenticationsBase
}

func (auth *enchantedLink) SignIn(ctx context.Context, loginID, URI string, r *http.Request, loginOptions *descope.LoginOptions) (*descope.EnchantedLinkResponse, error) {
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
	httpResponse, err := auth.client.DoPostRequest(ctx, composeEnchantedLinkSignInURL(), newMagicLinkAuthenticationRequestBody(loginID, URI, true, loginOptions), nil, pswd)
	if err != nil {
		return nil, err
	}
	return getPendingRefFromResponse(httpResponse)
}

func (auth *enchantedLink) SignUp(ctx context.Context, loginID, URI string, user *descope.User, signUpOptions *descope.SignUpOptions) (*descope.EnchantedLinkResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	if user == nil {
		user = &descope.User{}
	}
	if len(user.Email) == 0 {
		user.Email = loginID
	}

	httpResponse, err := auth.client.DoPostRequest(ctx, composeEnchantedLinkSignUpURL(), newMagicLinkAuthenticationSignUpRequestBody(descope.MethodEmail, loginID, URI, user, true, signUpOptions), nil, "")
	if err != nil {
		return nil, err
	}
	return getPendingRefFromResponse(httpResponse)
}

func (auth *enchantedLink) SignUpOrIn(ctx context.Context, loginID, URI string, signUpOptions *descope.SignUpOptions) (*descope.EnchantedLinkResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	if signUpOptions == nil {
		signUpOptions = &descope.SignUpOptions{}
	}
	httpResponse, err := auth.client.DoPostRequest(ctx, composeEnchantedLinkSignUpOrInURL(), newMagicLinkAuthenticationRequestBody(loginID, URI, true, &descope.LoginOptions{
		CustomClaims:    signUpOptions.CustomClaims,
		TemplateOptions: signUpOptions.TemplateOptions,
		TemplateID:      signUpOptions.TemplateID,
	}), nil, "")
	if err != nil {
		return nil, err
	}
	return getPendingRefFromResponse(httpResponse)
}

func (auth *enchantedLink) GetSession(ctx context.Context, pendingRef string, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	var err error
	httpResponse, err := auth.client.DoPostRequest(ctx, composeGetSession(), newAuthenticationGetSessionBody(pendingRef), nil, "")
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(httpResponse, w)
}

func (auth *enchantedLink) Verify(ctx context.Context, token string) error {
	_, err := auth.client.DoPostRequest(ctx, composeVerifyEnchantedLinkURL(), newMagicLinkAuthenticationVerifyRequestBody(token), nil, "")
	if err != nil {
		return err
	}
	return nil
}

func (auth *enchantedLink) UpdateUserEmail(ctx context.Context, loginID, email, URI string, updateOptions *descope.UpdateOptions, r *http.Request) (*descope.EnchantedLinkResponse, error) {
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
	httpResponse, err := auth.client.DoPostRequest(ctx, composeUpdateUserEmailEnchantedLink(), newMagicLinkUpdateEmailRequestBody(loginID, email, URI, true, updateOptions), nil, pswd)
	if err != nil {
		return nil, err
	}
	return getPendingRefFromResponse(httpResponse)
}
