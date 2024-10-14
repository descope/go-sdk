package auth

import (
	"context"
	"net/http"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
)

type otp struct {
	authenticationsBase
}

func (auth *otp) SignIn(ctx context.Context, method descope.DeliveryMethod, loginID string, r *http.Request, loginOptions *descope.LoginOptions) (string, error) {
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
	_, err = auth.client.DoPostRequest(ctx, composeSignInURL(method), newSignInRequestBody(loginID, loginOptions), options, pswd)
	return masked.GetMasked(), err
}

func (auth *otp) SignUp(ctx context.Context, method descope.DeliveryMethod, loginID string, user *descope.User, signUpOptions *descope.SignUpOptions) (string, error) {
	if user == nil {
		user = &descope.User{}
	}
	if err := auth.verifyDeliveryMethod(method, loginID, user); err != nil {
		return "", err
	}
	masked := getMaskedValue(method)
	options := &api.HTTPRequest{ResBodyObj: masked}
	_, err := auth.client.DoPostRequest(ctx, composeSignUpURL(method), newAuthenticationSignUpRequestBody(method, loginID, user, signUpOptions), options, "")
	return masked.GetMasked(), err
}

func (auth *otp) SignUpOrIn(ctx context.Context, method descope.DeliveryMethod, loginID string, signUpOptions *descope.SignUpOptions) (string, error) {
	if loginID == "" {
		return "", utils.NewInvalidArgumentError("loginID")
	}

	if signUpOptions == nil {
		signUpOptions = &descope.SignUpOptions{}
	}

	masked := getMaskedValue(method)
	options := &api.HTTPRequest{ResBodyObj: masked}
	_, err := auth.client.DoPostRequest(ctx, composeSignUpOrInURL(method), newSignInRequestBody(loginID, &descope.LoginOptions{
		CustomClaims:    signUpOptions.CustomClaims,
		TemplateOptions: signUpOptions.TemplateOptions,
		TemplateID:      signUpOptions.TemplateID,
	}), options, "")
	return masked.GetMasked(), err
}

func (auth *otp) VerifyCode(ctx context.Context, method descope.DeliveryMethod, loginID string, code string, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	if method == "" {
		if phoneRegex.MatchString(loginID) {
			method = descope.MethodSMS
		}

		if emailRegex.MatchString(loginID) {
			method = descope.MethodEmail
		}

		if method == "" {
			return nil, utils.NewInvalidArgumentError("method")
		}
	}
	httpResponse, err := auth.client.DoPostRequest(ctx, composeVerifyCodeURL(method), newAuthenticationVerifyRequestBody(loginID, code), nil, "")
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(httpResponse, w)
}

func (auth *otp) UpdateUserEmail(ctx context.Context, loginID, email string, updateOptions *descope.UpdateOptions, r *http.Request) (string, error) {
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
	_, err = auth.client.DoPostRequest(ctx, composeUpdateUserEmailOTP(), newOTPUpdateEmailRequestBody(loginID, email, updateOptions), options, pswd)
	return masked.GetMasked(), err
}

func (auth *otp) UpdateUserPhone(ctx context.Context, method descope.DeliveryMethod, loginID, phone string, updateOptions *descope.UpdateOptions, r *http.Request) (string, error) {
	if loginID == "" {
		return "", utils.NewInvalidArgumentError("loginID")
	}
	if phone == "" {
		return "", utils.NewInvalidArgumentError("phone")
	}
	if !phoneRegex.MatchString(phone) {
		return "", utils.NewInvalidArgumentError("phone")
	}
	if method != descope.MethodSMS && method != descope.MethodVoice && method != descope.MethodWhatsApp {
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
	_, err = auth.client.DoPostRequest(ctx, composeUpdateUserPhoneOTP(method), newOTPUpdatePhoneRequestBody(loginID, phone, updateOptions), options, pswd)
	return masked.GetMasked(), err
}
