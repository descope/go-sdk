package auth

import (
	"context"
	"net/http"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/logger"
)

type password struct {
	authenticationsBase
}

func (auth *password) SignUp(ctx context.Context, loginID string, user *descope.User, cleartext string, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	if user == nil {
		user = &descope.User{}
	}
	res, err := auth.client.DoPostRequest(ctx, api.Routes.SignUpPassword(), authenticationPasswordSignUpRequestBody{LoginID: loginID, User: user, Password: cleartext}, nil, "")
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(res, w)
}

func (auth *password) SignIn(ctx context.Context, loginID string, cleartext string, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	res, err := auth.client.DoPostRequest(ctx, api.Routes.SignInPassword(), authenticationPasswordSignInRequestBody{LoginID: loginID, Password: cleartext}, nil, "")
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(res, w)
}

func (auth *password) SendPasswordReset(ctx context.Context, loginID, redirectURL string, templateOptions map[string]interface{}) error {
	if loginID == "" {
		return utils.NewInvalidArgumentError("loginID")
	}

	_, err := auth.client.DoPostRequest(ctx, api.Routes.SendResetPassword(), authenticationPasswordResetRequestBody{LoginID: loginID, RedirectURL: redirectURL, TemplateOptions: templateOptions}, nil, "")
	if err != nil {
		return err
	}
	return nil
}

func (auth *password) UpdateUserPassword(ctx context.Context, loginID, newPassword string, r *http.Request) error {
	if loginID == "" {
		return utils.NewInvalidArgumentError("loginID")
	}
	pswd, err := getValidRefreshToken(r)
	if err != nil {
		return err
	}

	_, err = auth.client.DoPostRequest(ctx, api.Routes.UpdateUserPassword(), authenticationPasswordUpdateRequestBody{LoginID: loginID, NewPassword: newPassword}, nil, pswd)
	if err != nil {
		return err
	}
	return nil
}

func (auth *password) ReplaceUserPassword(ctx context.Context, loginID, oldPassword, newPassword string, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}

	res, err := auth.client.DoPostRequest(ctx, api.Routes.ReplaceUserPassword(), authenticationPasswordReplaceRequestBody{LoginID: loginID, OldPassword: oldPassword, NewPassword: newPassword}, nil, "")
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(res, w)
}

func (auth *password) GetPasswordPolicy(ctx context.Context) (*descope.PasswordPolicy, error) {
	p, err := auth.client.DoGetRequest(ctx, api.Routes.PasswordPolicy(), nil, "")
	if err != nil {
		return nil, err
	}
	return auth.extractPasswordPolicyResponse(p.BodyStr)
}

func (auth *authenticationsBase) extractPasswordPolicyResponse(bodyStr string) (*descope.PasswordPolicy, error) {
	if bodyStr == "" {
		// notest
		return nil, descope.ErrUnexpectedResponse.WithMessage("Empty policy returned")
	}
	res := descope.PasswordPolicy{}
	err := utils.Unmarshal([]byte(bodyStr), &res)
	if err != nil {
		logger.LogError("Unable to parse password policy response", err)
		return nil, err
	}
	return &res, nil
}
