package mgmt

import (
	"context"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/auth"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/logger"
	"github.com/descope/go-sdk/descope/sdk"
)

type jwt struct {
	managementBase
	provider *auth.Provider
}

var _ sdk.JWT = &jwt{}

type jwtRes struct {
	JWT string `json:"jwt,omitempty"`
}

func (j *jwt) UpdateJWTWithCustomClaims(ctx context.Context, jwt string, customClaims map[string]any, refreshDuration int32) (string, error) {
	if jwt == "" {
		return "", utils.NewInvalidArgumentError("jwt")
	}
	// customClaims can be nil, it will mean that this JWT will be validated, and updated authz data will be set
	req := map[string]any{
		"jwt":             jwt,
		"customClaims":    customClaims,
		"refreshDuration": refreshDuration,
	}
	res, err := j.client.DoPostRequest(ctx, api.Routes.ManagementUpdateJWT(), req, nil, j.conf.ManagementKey)
	if err != nil {
		return "", err
	}
	jRes := &jwtRes{}
	err = utils.Unmarshal([]byte(res.BodyStr), jRes)
	if err != nil {
		return "", err //notest
	}
	return jRes.JWT, nil
}

func (j *jwt) Impersonate(ctx context.Context, impersonatorID string, loginID string, validateConcent bool, customClaims map[string]any, tenantID string) (string, error) {
	if loginID == "" {
		return "", utils.NewInvalidArgumentError("loginID")
	}
	if impersonatorID == "" {
		return "", utils.NewInvalidArgumentError("impersonatorID")
	}
	req := map[string]any{
		"loginId":         loginID,
		"impersonatorId":  impersonatorID,
		"validateConsent": validateConcent,
		"customClaims":    customClaims,
		"selectedTenant":  tenantID,
	}
	res, err := j.client.DoPostRequest(ctx, api.Routes.ManagementImpersonate(), req, nil, j.conf.ManagementKey)
	if err != nil {
		return "", err
	}
	jRes := &jwtRes{}
	err = utils.Unmarshal([]byte(res.BodyStr), jRes)
	if err != nil {
		return "", err //notest
	}
	return jRes.JWT, nil
}

func (j *jwt) parseJWT(jwtResponse *descope.JWTResponse) (*descope.AuthenticationInfo, error) {
	dsr, err := auth.ValidateJWT(jwtResponse.RefreshJwt, j.provider)
	if err != nil {
		return nil, err
	}
	ds, err := auth.ValidateJWT(jwtResponse.SessionJwt, j.provider)
	if err != nil {
		return nil, err
	}
	ds.RefreshExpiration = dsr.Expiration
	return descope.NewAuthenticationInfo(jwtResponse, ds, dsr), nil
}

type authenticationRequestBody struct {
	LoginID             string                 `json:"loginId,omitempty"`
	Stepup              bool                   `json:"stepup,omitempty"`
	MFA                 bool                   `json:"mfa,omitempty"`
	RevokeOtherSessions bool                   `json:"revokeOtherSessions,omitempty"`
	CustomClaims        map[string]interface{} `json:"customClaims,omitempty"`
	JWT                 string                 `json:"jwt,omitempty"`
}

type authenticationSignUpRequestBody struct {
	LoginID       string                 `json:"loginId,omitempty"`
	User          *descope.User          `json:"user,omitempty"`
	EmailVerified bool                   `json:"emailVerified,omitempty"`
	PhoneVerified bool                   `json:"phoneVerified,omitempty"`
	SsoAppID      string                 `json:"ssoAppId,omitempty"`
	CustomClaims  map[string]interface{} `json:"customClaims,omitempty"`
}

func (j *jwt) SignIn(ctx context.Context, loginID string, loginOptions *descope.MgmLoginOptions) (*descope.AuthenticationInfo, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	if loginOptions == nil {
		loginOptions = &descope.MgmLoginOptions{}
	}
	if loginOptions.IsJWTRequired() && len(loginOptions.JWT) == 0 {
		return nil, descope.ErrInvalidStepUpJWT
	}

	arb := &authenticationRequestBody{
		LoginID:             loginID,
		Stepup:              loginOptions.Stepup,
		MFA:                 loginOptions.MFA,
		RevokeOtherSessions: loginOptions.RevokeOtherSessions,
		CustomClaims:        loginOptions.CustomClaims,
		JWT:                 loginOptions.JWT,
	}
	httpResponse, err := j.client.DoPostRequest(ctx, api.Routes.ManagementSignIn(), arb, nil, j.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	jRes := &descope.JWTResponse{}
	err = utils.Unmarshal([]byte(httpResponse.BodyStr), jRes)
	if err != nil {
		logger.LogError("Unable to parse jwt response", err)
		return nil, err
	}
	return j.parseJWT(jRes)
}

func (j *jwt) SignUp(ctx context.Context, loginID string, user *descope.MgmtUserRequest, signUpOptions *descope.MgmSignUpOptions) (*descope.AuthenticationInfo, error) {
	return j.signUp(ctx, api.Routes.ManagementSignUp(), loginID, user, signUpOptions)
}

func (j *jwt) signUp(ctx context.Context, endpoint string, loginID string, user *descope.MgmtUserRequest, signUpOptions *descope.MgmSignUpOptions) (*descope.AuthenticationInfo, error) {
	if user == nil {
		user = &descope.MgmtUserRequest{}
	}
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	if signUpOptions == nil {
		signUpOptions = &descope.MgmSignUpOptions{}
	}

	arb := &authenticationSignUpRequestBody{
		LoginID:       loginID,
		User:          &user.User,
		EmailVerified: user.EmailVerified,
		PhoneVerified: user.PhoneVerified,
		SsoAppID:      user.SsoAppID,
		CustomClaims:  signUpOptions.CustomClaims,
	}
	httpResponse, err := j.client.DoPostRequest(ctx, endpoint, arb, nil, j.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	jRes := &descope.JWTResponse{}
	err = utils.Unmarshal([]byte(httpResponse.BodyStr), jRes)
	if err != nil {
		logger.LogError("Unable to parse jwt response", err)
		return nil, err
	}
	return j.parseJWT(jRes)
}

func (j *jwt) SignUpOrIn(ctx context.Context, loginID string, user *descope.MgmtUserRequest, signUpOptions *descope.MgmSignUpOptions) (*descope.AuthenticationInfo, error) {
	return j.signUp(ctx, api.Routes.ManagementSignUpOrIn(), loginID, user, signUpOptions)
}
