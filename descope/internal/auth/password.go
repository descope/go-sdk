package auth

import (
	"net/http"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
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
