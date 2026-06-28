package auth

import (
	"context"
	"net/http"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
)

type webAuthn struct {
	authenticationsBase
}

func (auth *webAuthn) SignUpStart(ctx context.Context, loginID string, user *descope.User, origin string, signUpOptions *descope.SignUpOptions) (*descope.WebAuthnTransactionResponse, error) {
	if user == nil {
		user = &descope.User{}
	}
	var loginOpts *descope.LoginOptions
	if signUpOptions != nil {
		loginOpts = &descope.LoginOptions{
			TenantID:        signUpOptions.TenantID,
			CustomClaims:    signUpOptions.CustomClaims,
			TemplateOptions: signUpOptions.TemplateOptions,
			TemplateID:      signUpOptions.TemplateID,
		}
	}
	res, err := auth.client.DoPostRequest(ctx, api.Routes.WebAuthnSignUpStart(), authenticationWebAuthnSignUpRequestBody{LoginID: loginID, User: user, Origin: origin, LoginOptions: loginOpts}, nil, "")
	if err != nil {
		return nil, err
	}

	webAuthnResponse := &descope.WebAuthnTransactionResponse{}
	err = utils.Unmarshal([]byte(res.BodyStr), webAuthnResponse)
	return webAuthnResponse, err
}

func (auth *webAuthn) SignUpFinish(ctx context.Context, request *descope.WebAuthnFinishRequest, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	res, err := auth.client.DoPostRequest(ctx, api.Routes.WebAuthnSignUpFinish(), request, nil, "")
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(res, w)
}

func (auth *webAuthn) SignInStart(ctx context.Context, loginID string, origin string, r *http.Request, loginOptions *descope.LoginOptions) (*descope.WebAuthnTransactionResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}
	var pswd string
	var err error
	if loginOptions.IsJWTRequired() {
		pswd, err = auth.getValidRefreshToken(r)
		if err != nil {
			return nil, descope.ErrInvalidStepUpJWT
		}
	}

	res, err := auth.client.DoPostRequest(ctx, api.Routes.WebAuthnSignInStart(), authenticationWebAuthnSignInRequestBody{LoginID: loginID, Origin: origin, LoginOptions: loginOptions}, nil, pswd)
	if err != nil {
		return nil, err
	}

	webAuthnResponse := &descope.WebAuthnTransactionResponse{}
	err = utils.Unmarshal([]byte(res.BodyStr), webAuthnResponse)
	return webAuthnResponse, err

}

func (auth *webAuthn) SignInFinish(ctx context.Context, request *descope.WebAuthnFinishRequest, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	res, err := auth.client.DoPostRequest(ctx, api.Routes.WebAuthnSignInFinish(), request, nil, "")
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(res, w)
}

func (auth *webAuthn) SignUpOrInStart(ctx context.Context, loginID string, origin string, loginOptions *descope.LoginOptions) (*descope.WebAuthnTransactionResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}

	res, err := auth.client.DoPostRequest(ctx, api.Routes.WebAuthnSignUpOrInStart(), authenticationWebAuthnSignInRequestBody{LoginID: loginID, Origin: origin, LoginOptions: loginOptions}, nil, "")
	if err != nil {
		return nil, err
	}

	webAuthnResponse := &descope.WebAuthnTransactionResponse{}
	err = utils.Unmarshal([]byte(res.BodyStr), webAuthnResponse)
	return webAuthnResponse, err
}

// UpdateUserDeviceStart starts a passkey enrollment for an existing, logged-in user.
// Pass mfa=true to have UpdateUserDeviceFinish return a single session whose amr merges the user's
// previously-passed factors with the newly-enrolled passkey, instead of having to run a separate
// sign-in ceremony afterwards.
func (auth *webAuthn) UpdateUserDeviceStart(ctx context.Context, loginID string, origin string, r *http.Request, mfa ...bool) (*descope.WebAuthnTransactionResponse, error) {
	if loginID == "" {
		return nil, utils.NewInvalidArgumentError("loginID")
	}

	pswd, err := auth.getValidRefreshToken(r)
	if err != nil {
		return nil, err
	}

	var mfaVal bool
	if len(mfa) > 0 {
		mfaVal = mfa[0]
	}
	res, err := auth.client.DoPostRequest(ctx, api.Routes.WebAuthnUpdateUserDeviceStart(), authenticationWebAuthnAddDeviceRequestBody{LoginID: loginID, Origin: origin, MFA: mfaVal}, nil, pswd)
	if err != nil {
		return nil, err
	}

	webAuthnResponse := &descope.WebAuthnTransactionResponse{}
	err = utils.Unmarshal([]byte(res.BodyStr), webAuthnResponse)
	return webAuthnResponse, err
}

// UpdateUserDeviceFinish completes a passkey enrollment. When the matching UpdateUserDeviceStart
// opted into MFA/Stepup, the returned AuthenticationInfo carries a session whose amr merges the
// previously-passed factors with the new passkey; otherwise it returns (nil, nil) - the credential
// is enrolled but no new session is minted (the default flow).
func (auth *webAuthn) UpdateUserDeviceFinish(ctx context.Context, request *descope.WebAuthnFinishRequest, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	res, err := auth.client.DoPostRequest(ctx, api.Routes.WebAuthnUpdateUserDeviceFinish(), request, nil, "")
	if err != nil {
		return nil, err
	}
	// the merged-amr session, if any, is nested under "jwt" so the default (no-mfa) response stays empty.
	// guard the empty-body case (the credential was enrolled, no session minted) before unmarshalling.
	if res.BodyStr == "" {
		return nil, nil
	}
	var wrapper struct {
		JWT *descope.JWTResponse `json:"jwt,omitempty"`
	}
	if err := utils.Unmarshal([]byte(res.BodyStr), &wrapper); err != nil {
		return nil, err
	}
	if wrapper.JWT == nil || wrapper.JWT.SessionJwt == "" {
		return nil, nil
	}
	flat, err := utils.Marshal(wrapper.JWT)
	if err != nil {
		return nil, err
	}
	res.BodyStr = string(flat)
	return auth.generateAuthenticationInfo(res, w)
}
