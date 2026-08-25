package auth

import (
	"context"
	"net/http"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/internal/utils"
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
		pswd, err = auth.getValidRefreshToken(r)
		if err != nil {
			return nil, descope.ErrInvalidStepUpJWT
		}
	}
	httpResponse, err := auth.client.DoPostRequest(ctx, composeEnchantedLinkSignInURL(descope.MethodEmail), newMagicLinkAuthenticationRequestBody(loginID, URI, true, loginOptions), nil, pswd)
	if err != nil {
		return nil, err
	}
	return getPendingRefFromResponse(httpResponse)
}

// SignInWithPhone - Use to login a user based on an enchanted link that will be sent by SMS.
// the jwt would be returned on the getSession function at the end of the flow rather that on the verify.
// returns an error upon failure.
func (auth *enchantedLink) SignInWithPhone(ctx context.Context, phone, URI string, r *http.Request, loginOptions *descope.LoginOptions) (*descope.EnchantedLinkResponse, error) {
	var pswd string
	var err error
	if phone == "" {
		return nil, utils.NewInvalidArgumentError("phone")
	}
	if loginOptions.IsJWTRequired() {
		pswd, err = auth.getValidRefreshToken(r)
		if err != nil {
			return nil, descope.ErrInvalidStepUpJWT
		}
	}
	httpResponse, err := auth.client.DoPostRequest(ctx, composeEnchantedLinkSignInURL(descope.MethodSMS), newMagicLinkAuthenticationRequestBody(phone, URI, true, loginOptions), nil, pswd)
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

	httpResponse, err := auth.client.DoPostRequest(ctx, composeEnchantedLinkSignUpURL(descope.MethodEmail), newMagicLinkAuthenticationSignUpRequestBody(descope.MethodEmail, loginID, URI, user, true, signUpOptions), nil, "")
	if err != nil {
		return nil, err
	}
	return getPendingRefFromResponse(httpResponse)
}

// SignUpWithPhone - Use to create a new user based on the given phone number, verified via an enchanted link sent by SMS.
// optional to add user metadata for farther user details such as name and more.
// returns an error upon failure.
func (auth *enchantedLink) SignUpWithPhone(ctx context.Context, phone, URI string, user *descope.User, signUpOptions *descope.SignUpOptions) (*descope.EnchantedLinkResponse, error) {
	if phone == "" {
		return nil, utils.NewInvalidArgumentError("phone")
	}
	if user == nil {
		user = &descope.User{}
	}
	if len(user.Phone) == 0 {
		user.Phone = phone
	}

	httpResponse, err := auth.client.DoPostRequest(ctx, composeEnchantedLinkSignUpURL(descope.MethodSMS), newMagicLinkAuthenticationSignUpRequestBody(descope.MethodSMS, phone, URI, user, true, signUpOptions), nil, "")
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
	httpResponse, err := auth.client.DoPostRequest(ctx, composeEnchantedLinkSignUpOrInURL(descope.MethodEmail), newMagicLinkAuthenticationRequestBody(loginID, URI, true, &descope.LoginOptions{
		CustomClaims:    signUpOptions.CustomClaims,
		TemplateOptions: signUpOptions.TemplateOptions,
		TemplateID:      signUpOptions.TemplateID,
		TenantID:        signUpOptions.TenantID,
	}), nil, "")
	if err != nil {
		return nil, err
	}
	return getPendingRefFromResponse(httpResponse)
}

// SignUpOrInWithPhone - Use to login in using phone, if user does not exist, a new user will be created
// with the given phone number.
// optional to add user metadata for farther user details such as name and more.
// returns an error upon failure.
func (auth *enchantedLink) SignUpOrInWithPhone(ctx context.Context, phone string, URI string, signUpOptions *descope.SignUpOptions) (*descope.EnchantedLinkResponse, error) {
	if phone == "" {
		return nil, utils.NewInvalidArgumentError("phone")
	}
	if signUpOptions == nil {
		signUpOptions = &descope.SignUpOptions{}
	}
	httpResponse, err := auth.client.DoPostRequest(ctx, composeEnchantedLinkSignUpOrInURL(descope.MethodSMS), newMagicLinkAuthenticationRequestBody(phone, URI, true, &descope.LoginOptions{
		CustomClaims:    signUpOptions.CustomClaims,
		TemplateOptions: signUpOptions.TemplateOptions,
		TemplateID:      signUpOptions.TemplateID,
		TenantID:        signUpOptions.TenantID,
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
	pswd, err := auth.getValidRefreshToken(r)
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
