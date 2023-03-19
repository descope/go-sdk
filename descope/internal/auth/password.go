package auth

import (
	"net/http"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/logger"
)

type password struct {
	authenticationsBase
}

func (auth *password) SignUp(loginID string, user *descope.User, cleartext string, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	if user == nil {
		user = &descope.User{}
	}
	res, err := auth.client.DoPostRequest(api.Routes.SignUpPassword(), authenticationPasswordSignUpRequestBody{LoginID: loginID, User: user, Password: cleartext}, nil, "")
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(res, w)
}

func (auth *password) SignIn(loginID string, cleartext string, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	res, err := auth.client.DoPostRequest(api.Routes.SignInPassword(), authenticationPasswordSignInRequestBody{LoginID: loginID, Password: cleartext}, nil, "")
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(res, w)
}

func (auth *password) SendPasswordReset(loginID, redirectURL string) error {
	if loginID == "" {
		return utils.NewInvalidArgumentError("loginID")
	}

	_, err := auth.client.DoPostRequest(api.Routes.SendResetPassword(), authenticationPasswordResetRequestBody{LoginID: loginID, RedirectURL: redirectURL}, nil, "")
	if err != nil {
		return err
	}
	return nil
}

func (auth *password) UpdateUserPassword(loginID, newPassword string, r *http.Request) error {
	if loginID == "" {
		return utils.NewInvalidArgumentError("loginID")
	}
	pswd, err := getValidRefreshToken(r)
	if err != nil {
		return err
	}

	_, err = auth.client.DoPostRequest(api.Routes.UpdateUserPassword(), authenticationPasswordUpdateRequestBody{LoginID: loginID, NewPassword: newPassword}, nil, pswd)
	if err != nil {
		return err
	}
	return nil
}

func (auth *password) ReplaceUserPassword(loginID, oldPassword, newPassword string) error {
	if loginID == "" {
		return utils.NewInvalidArgumentError("loginID")
	}

	_, err := auth.client.DoPostRequest(api.Routes.ReplaceUserPassword(), authenticationPasswordReplaceRequestBody{LoginID: loginID, OldPassword: oldPassword, NewPassword: newPassword}, nil, "")
	if err != nil {
		return err
	}
	return nil
}

func (auth *password) GetPasswordPolicy() (*descope.PasswordPolicy, error) {
	p, err := auth.client.DoGetRequest(api.Routes.PasswordPolicy(), nil, "")
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
