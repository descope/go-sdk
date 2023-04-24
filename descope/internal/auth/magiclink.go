package auth

import (
	"net/http"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
)

type magicLink struct {
	authenticationsBase
}

func (auth *magicLink) SignIn(method descope.DeliveryMethod, loginID, URI string, r *http.Request, loginOptions *descope.LoginOptions) (string, error) {
	var pswd string
	var err error
	if loginID == "" {
		return "", utils.NewInvalidArgumentError("loginID")
	}
	if loginOptions.IsJWTRequired() {
		pswd, err = getValidRefreshToken(r)
		if err != nil {
			return "", descope.ErrInvalidStepUpJWT
		}
	}
	masked := getMaskedValue(method)
	options := &api.HTTPRequest{ResBodyObj: masked}
	_, err = auth.client.DoPostRequest(composeMagicLinkSignInURL(method), newMagicLinkAuthenticationRequestBody(loginID, URI, false, loginOptions), options, pswd)
	return masked.GetMasked(), err
}

func (auth *magicLink) SignUp(method descope.DeliveryMethod, loginID, URI string, user *descope.User) (string, error) {
	if user == nil {
		user = &descope.User{}
	}
	if err := auth.verifyDeliveryMethod(method, loginID, user); err != nil {
		return "", err
	}
	masked := getMaskedValue(method)
	options := &api.HTTPRequest{ResBodyObj: masked}
	_, err := auth.client.DoPostRequest(composeMagicLinkSignUpURL(method), newMagicLinkAuthenticationSignUpRequestBody(method, loginID, URI, user, false), options, "")
	return masked.GetMasked(), err
}

func (auth *magicLink) SignUpOrIn(method descope.DeliveryMethod, loginID, URI string) (string, error) {
	if loginID == "" {
		return "", utils.NewInvalidArgumentError("loginID")
	}
	masked := getMaskedValue(method)
	options := &api.HTTPRequest{ResBodyObj: masked}
	_, err := auth.client.DoPostRequest(composeMagicLinkSignUpOrInURL(method), newMagicLinkAuthenticationRequestBody(loginID, URI, false, nil), options, "")
	return masked.GetMasked(), err
}

func (auth *magicLink) Verify(token string, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	var err error

	httpResponse, err := auth.client.DoPostRequest(composeVerifyMagicLinkURL(), newMagicLinkAuthenticationVerifyRequestBody(token), nil, "")
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(httpResponse, w)
}

func (auth *magicLink) UpdateUserEmail(loginID, email, URI string, updateOptions *descope.UpdateOptions, r *http.Request) (string, error) {
	if loginID == "" {
		return "", utils.NewInvalidArgumentError("loginID")
	}
	if email == "" {
		return "", utils.NewInvalidArgumentError("email")
	}
	if !emailRegex.MatchString(email) {
		return "", utils.NewInvalidArgumentError("email")
	}
	pswd, err := getValidRefreshToken(r)
	if err != nil {
		return "", err
	}
	if updateOptions == nil {
		updateOptions = &descope.UpdateOptions{}
	}
	masked := getMaskedValue(descope.MethodEmail)
	options := &api.HTTPRequest{ResBodyObj: masked}
	_, err = auth.client.DoPostRequest(composeUpdateUserEmailMagicLink(), newMagicLinkUpdateEmailRequestBody(loginID, email, URI, false, updateOptions), options, pswd)
	return masked.GetMasked(), err
}

func (auth *magicLink) UpdateUserPhone(method descope.DeliveryMethod, loginID, phone, URI string, updateOptions *descope.UpdateOptions, r *http.Request) (string, error) {
	if loginID == "" {
		return "", utils.NewInvalidArgumentError("loginID")
	}
	if phone == "" {
		return "", utils.NewInvalidArgumentError("phone")
	}
	if !phoneRegex.MatchString(phone) {
		return "", utils.NewInvalidArgumentError("phone")
	}
	if method != descope.MethodSMS && method != descope.MethodWhatsApp {
		return "", utils.NewInvalidArgumentError("method")
	}
	pswd, err := getValidRefreshToken(r)
	if err != nil {
		return "", err
	}
	if updateOptions == nil {
		updateOptions = &descope.UpdateOptions{}
	}
	masked := getMaskedValue(descope.MethodSMS)
	options := &api.HTTPRequest{ResBodyObj: masked}
	_, err = auth.client.DoPostRequest(composeUpdateUserPhoneMagiclink(method), newMagicLinkUpdatePhoneRequestBody(loginID, phone, URI, false, updateOptions), options, pswd)
	return masked.GetMasked(), err
}
