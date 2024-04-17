package auth

import (
	"context"
	"net/http"

	"github.com/descope/go-sdk/descope"
)

type notp struct {
	authenticationsBase
}

func (auth *notp) SignIn(ctx context.Context, loginID string, r *http.Request, loginOptions *descope.LoginOptions) (*descope.NOTPResponse, error) {
	var pswd string
	var err error
	if loginOptions.IsJWTRequired() {
		pswd, err = getValidRefreshToken(r)
		if err != nil {
			return nil, descope.ErrInvalidStepUpJWT
		}
	}
	httpResponse, err := auth.client.DoPostRequest(ctx, composeNOTPSignInURL(), newNOTPAuthenticationRequestBody(loginID, loginOptions), nil, pswd)
	if err != nil {
		return nil, err
	}
	return getNOTPResponse(httpResponse)
}

func (auth *notp) SignUp(ctx context.Context, loginID string, user *descope.User, signUpOptions *descope.SignUpOptions) (*descope.NOTPResponse, error) {
	if user == nil {
		user = &descope.User{}
	}
	if len(user.Phone) == 0 {
		user.Phone = loginID
	}

	httpResponse, err := auth.client.DoPostRequest(ctx, composeNOTPSignUpURL(), newNOTPAuthenticationSignUpRequestBody(loginID, user, signUpOptions), nil, "")
	if err != nil {
		return nil, err
	}
	return getNOTPResponse(httpResponse)
}

func (auth *notp) SignUpOrIn(ctx context.Context, loginID string, signUpOptions *descope.SignUpOptions) (*descope.NOTPResponse, error) {
	if signUpOptions == nil {
		signUpOptions = &descope.SignUpOptions{}
	}
	httpResponse, err := auth.client.DoPostRequest(ctx, composeNOTPSignUpOrInURL(), newNOTPAuthenticationRequestBody(loginID, &descope.LoginOptions{
		CustomClaims:    signUpOptions.CustomClaims,
		TemplateOptions: signUpOptions.TemplateOptions,
	}), nil, "")
	if err != nil {
		return nil, err
	}
	return getNOTPResponse(httpResponse)
}

func (auth *notp) GetSession(ctx context.Context, pendingRef string, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	var err error
	httpResponse, err := auth.client.DoPostRequest(ctx, composeNOTPGetSession(), newAuthenticationGetSessionBody(pendingRef), nil, "")
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(httpResponse, w)
}
