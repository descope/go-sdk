package auth

import (
	"net/http"
)

type MockDescopeAuthenticationOTP struct {
	AssertSignInOTP                 func(method DeliveryMethod, identifier string)
	AssertSignUpOTP                 func(method DeliveryMethod, identifier string, user *User)
	AssertSignUpOrInOTP             func(method DeliveryMethod, identifier string)
	AssertVerifyCode                func(method DeliveryMethod, identifier string, code string)
	SignInOTPResponseError          error
	SignUpOTPResponseError          error
	SignUpOrInOTPResponseError      error
	VerifyCodeResponseInfo          *AuthenticationInfo
	AssertUpdateUserEmailOTP        func(identifier string, email string, request *http.Request)
	UpdateUserEmailOTPResponseError error
	AssertUpdateUserPhoneOTP        func(method DeliveryMethod, identifier string, email string, request *http.Request)
	UpdateUserPhoneOTPResponseError error
	VerifyCodeResponseError         error
}

type MockDescopeAuthenticationExchanger struct {
	AssertExchangeToken        func(code string, options ...Option)
	ExchangeTokenResponseInfo  *AuthenticationInfo
	ExchangeTokenResponseError error
}

type MockDescopeAuthenticationSAML struct {
	MockDescopeAuthenticationExchanger
	AssertSAMLStart            func(tenant string, landingURL string, options ...Option)
	AssertSAMLStartResponseURL string
	SAMLStartResponseError     error
}

type MockDescopeAuthenticationOAuth struct {
	MockDescopeAuthenticationExchanger
	AssertOAuthStart        func(provider OAuthProvider, landingURL string)
	AssertOAuthResponseURL  string
	OAuthStartResponseError error
}

type MockDescopeAuthenticationMagicLink struct {
	AssertSignInMagicLink                       func(method DeliveryMethod, identifier, URI string)
	AssertSignUpMagicLink                       func(method DeliveryMethod, identifier, URI string, user *User)
	AssertSignUpOrInMagicLink                   func(method DeliveryMethod, identifier, URI string)
	SignUpMagicLinkResponseError                error
	SignInMagicLinkResponseError                error
	SignUpOrInMagicLinkResponseError            error
	AssertSignInMagicLinkCrossDevice            func(method DeliveryMethod, identifier, URI string)
	AssertSignUpMagicLinkCrossDevice            func(method DeliveryMethod, identifier, URI string, user *User)
	AssertSignUpOrInMagicLinkCrossDevice        func(method DeliveryMethod, identifier, URI string)
	AssertGetMagicLinkSession                   func(pendingRef string)
	SignUpMagicLinkCrossDeviceResponseError     error
	SignInMagicLinkCrossDeviceResponseError     error
	SignUpOrInMagicLinkCrossDeviceResponseError error
	AssertVerifyMagicLink                       func(token string)
	VerifyCodeResponseError                     error
	VerifyCodeResponseInfo                      *AuthenticationInfo
	MagicLinkPendingLinkCrossDeviceResponse     *MagicLinkResponse
	AssertUpdateUserEmailMagicLink              func(identifier, email, URI string, request *http.Request)
	UpdateUserEmailMagicLinkResponseError       error
	AssertUpdateUserEmailMagicLinkCrossDevice   func(identifier, email, URI string, request *http.Request)
	UpdateUserEmailMagicLinkCrossDeviceError    error
	UpdateUserEmailMagicLinkCrossDeviceResponse *MagicLinkResponse
	AssertUpdateUserPhoneMagicLink              func(method DeliveryMethod, identifier, email, URI string, request *http.Request)
	UpdateUserPhoneMagicLinkResponseError       error
	AssertUpdateUserPhoneMagicLinkCrossDevice   func(method DeliveryMethod, identifier, email, URI string, request *http.Request)
	UpdateUserPhoneMagicLinkCrossDeviceError    error
	UpdateUserPhoneMagicLinkCrossDeviceResponse *MagicLinkResponse
	GetMagicLinkSessionResponseInfo             *AuthenticationInfo
	GetMagicLinkSessionResponseError            error
}

type MockDescopeAuthenticationTOTP struct {
	AssertSignInTOTP            func(method DeliveryMethod, identifier string)
	SignInTOTPResponseError     error
	AssertSignUpTOTP            func(identifier string, user *User)
	SignUpTOTPResponse          *TOTPResponse
	SignUpTOTPResponseError     error
	AssertUpdateTOTP            func(identifier string)
	UpdateTOTPResponse          *TOTPResponse
	UpdateTOTPResponseError     error
	AssertVerifyTOTPCode        func(identifier string, code string)
	VerifyTOTPCodeResponseInfo  *AuthenticationInfo
	VerifyTOTPCodeResponseError error
}

type MockDescopeAuthenticationWebAuthn struct {
	SignUpWebAuthnStartResponseError                 error
	SignUpWebAuthnStartResponseTransaction           *WebAuthnTransactionResponse
	SignUpWebAuthnFinishResponseError                error
	SignUpWebAuthnFinishResponseInfo                 *AuthenticationInfo
	SignInWebAuthnStartResponseError                 error
	SignInWebAuthnStartResponseTransaction           *WebAuthnTransactionResponse
	SignInWebAuthnFinishResponseError                error
	SignInWebAuthnFinishResponseInfo                 *AuthenticationInfo
	UpdateUserDeviceWebAuthnStartResponseError       error
	UpdateUserDeviceWebAuthnStartResponseTransaction *WebAuthnTransactionResponse
	UpdateUserDeviceWebAuthnFinishResponseError      error
}

type MockDescopeAuthentication struct {
	MockDescopeAuthenticationOTP
	MockDescopeAuthenticationMagicLink
	MockDescopeAuthenticationSAML
	MockDescopeAuthenticationOAuth
	MockDescopeAuthenticationTOTP
	MockDescopeAuthenticationWebAuthn

	AssertLogout func(r *http.Request)

	ValidateSessionResponseNotOK bool
	ValidateSessionResponseInfo  *Token
	ValidateSessionResponseError error

	RefreshSessionResponseNotOK bool
	RefreshSessionResponseInfo  *Token
	RefreshSessionResponseError error

	LogoutResponseError error

	ExchangeAccessKeyResponseNotOK bool
	ExchangeAccessKeyResponseInfo  *Token
	ExchangeAccessKeyResponseError error
}

func NewMockDescopeAuthentication() MockDescopeAuthentication {
	return MockDescopeAuthentication{}
}

func (m MockDescopeAuthentication) OTP() OTP {
	return m.MockDescopeAuthenticationOTP
}

func (m MockDescopeAuthentication) MagicLink() MagicLink {
	return m.MockDescopeAuthenticationMagicLink
}

func (m MockDescopeAuthentication) WebAuthn() WebAuthn {
	return m.MockDescopeAuthenticationWebAuthn
}

func (m MockDescopeAuthentication) TOTP() TOTP {
	return m.MockDescopeAuthenticationTOTP
}

func (m MockDescopeAuthentication) SAML() SAML {
	return m.MockDescopeAuthenticationSAML
}

func (m MockDescopeAuthentication) OAuth() OAuth {
	return m.MockDescopeAuthenticationOAuth
}

func (m MockDescopeAuthenticationOTP) SignIn(method DeliveryMethod, identifier string) error {
	if m.AssertSignInOTP != nil {
		m.AssertSignInOTP(method, identifier)
	}
	return m.SignInOTPResponseError
}

func (m MockDescopeAuthenticationOTP) SignUp(method DeliveryMethod, identifier string, user *User) error {
	if m.AssertSignUpOTP != nil {
		m.AssertSignUpOTP(method, identifier, user)
	}
	return m.SignUpOTPResponseError
}

func (m MockDescopeAuthenticationOTP) SignUpOrIn(method DeliveryMethod, identifier string) error {
	if m.AssertSignUpOrInOTP != nil {
		m.AssertSignUpOrInOTP(method, identifier)
	}
	return m.SignUpOrInOTPResponseError
}

func (m MockDescopeAuthenticationTOTP) SignUp(identifier string, user *User) (*TOTPResponse, error) {
	if m.AssertSignUpTOTP != nil {
		m.AssertSignUpTOTP(identifier, user)
	}
	return m.SignUpTOTPResponse, m.SignUpTOTPResponseError
}

func (m MockDescopeAuthenticationTOTP) UpdateUser(identifier string, _ *http.Request) (*TOTPResponse, error) {
	if m.AssertUpdateTOTP != nil {
		m.AssertUpdateTOTP(identifier)
	}
	return m.UpdateTOTPResponse, m.UpdateTOTPResponseError
}

func (m MockDescopeAuthenticationTOTP) SignInCode(identifier string, code string, _ http.ResponseWriter) (*AuthenticationInfo, error) {
	return m.SignInCodeWithOptions(identifier, code, nil)
}

func (m MockDescopeAuthenticationTOTP) SignInCodeWithOptions(identifier string, code string, _ ...Option) (*AuthenticationInfo, error) {
	if m.AssertVerifyTOTPCode != nil {
		m.AssertVerifyTOTPCode(identifier, code)
	}
	return m.VerifyTOTPCodeResponseInfo, m.VerifyTOTPCodeResponseError
}

func (m MockDescopeAuthenticationOTP) UpdateUserEmail(identifier, email string, request *http.Request) error {
	if m.AssertUpdateUserEmailOTP != nil {
		m.AssertUpdateUserEmailOTP(identifier, email, request)
	}
	return m.UpdateUserEmailOTPResponseError
}

func (m MockDescopeAuthenticationOTP) UpdateUserPhone(method DeliveryMethod, identifier, email string, request *http.Request) error {
	if m.AssertUpdateUserPhoneOTP != nil {
		m.AssertUpdateUserPhoneOTP(method, identifier, email, request)
	}
	return m.UpdateUserPhoneOTPResponseError
}

func (m MockDescopeAuthenticationOTP) VerifyCode(method DeliveryMethod, identifier string, code string, _ http.ResponseWriter) (*AuthenticationInfo, error) {
	if m.AssertVerifyCode != nil {
		m.AssertVerifyCode(method, identifier, code)
	}
	return m.VerifyCodeResponseInfo, m.VerifyCodeResponseError
}

func (m MockDescopeAuthenticationOTP) VerifyCodeWithOptions(method DeliveryMethod, identifier string, code string, _ ...Option) (*AuthenticationInfo, error) {
	if m.AssertVerifyCode != nil {
		m.AssertVerifyCode(method, identifier, code)
	}
	return m.VerifyCodeResponseInfo, m.VerifyCodeResponseError
}

func (m MockDescopeAuthenticationMagicLink) SignIn(method DeliveryMethod, identifier, URI string) error {
	if m.AssertSignInMagicLink != nil {
		m.AssertSignInMagicLink(method, identifier, URI)
	}
	return m.SignInMagicLinkResponseError
}

func (m MockDescopeAuthenticationMagicLink) SignUp(method DeliveryMethod, identifier, URI string, user *User) error {
	if m.AssertSignUpMagicLink != nil {
		m.AssertSignUpMagicLink(method, identifier, URI, user)
	}
	return m.SignUpMagicLinkResponseError
}

func (m MockDescopeAuthenticationMagicLink) SignUpOrIn(method DeliveryMethod, identifier string, URI string) error {
	if m.AssertSignUpOrInMagicLink != nil {
		m.AssertSignUpOrInMagicLink(method, identifier, URI)
	}
	return m.SignUpOrInMagicLinkResponseError
}

func (m MockDescopeAuthenticationMagicLink) SignInCrossDevice(method DeliveryMethod, identifier, URI string) (*MagicLinkResponse, error) {
	if m.AssertSignInMagicLinkCrossDevice != nil {
		m.AssertSignInMagicLinkCrossDevice(method, identifier, URI)
	}
	return m.MagicLinkPendingLinkCrossDeviceResponse, m.SignInMagicLinkCrossDeviceResponseError
}

func (m MockDescopeAuthenticationMagicLink) SignUpCrossDevice(method DeliveryMethod, identifier, URI string, user *User) (*MagicLinkResponse, error) {
	if m.AssertSignUpMagicLinkCrossDevice != nil {
		m.AssertSignUpMagicLinkCrossDevice(method, identifier, URI, user)
	}
	return m.MagicLinkPendingLinkCrossDeviceResponse, m.SignUpMagicLinkCrossDeviceResponseError
}

func (m MockDescopeAuthenticationMagicLink) SignUpOrInCrossDevice(method DeliveryMethod, identifier string, URI string) (*MagicLinkResponse, error) {
	if m.AssertSignUpOrInMagicLinkCrossDevice != nil {
		m.AssertSignUpOrInMagicLinkCrossDevice(method, identifier, URI)
	}
	return m.MagicLinkPendingLinkCrossDeviceResponse, m.SignUpOrInMagicLinkCrossDeviceResponseError
}

func (m MockDescopeAuthenticationMagicLink) UpdateUserEmail(identifier, email, URI string, request *http.Request) error {
	if m.AssertUpdateUserEmailMagicLink != nil {
		m.AssertUpdateUserEmailMagicLink(identifier, email, URI, request)
	}
	return m.UpdateUserEmailMagicLinkResponseError
}

func (m MockDescopeAuthenticationMagicLink) UpdateUserEmailCrossDevice(identifier, email, URI string, request *http.Request) (*MagicLinkResponse, error) {
	if m.AssertUpdateUserEmailMagicLinkCrossDevice != nil {
		m.AssertUpdateUserEmailMagicLinkCrossDevice(identifier, email, URI, request)
	}
	return m.UpdateUserEmailMagicLinkCrossDeviceResponse, m.UpdateUserEmailMagicLinkCrossDeviceError
}

func (m MockDescopeAuthenticationMagicLink) UpdateUserPhone(method DeliveryMethod, identifier, email, URI string, request *http.Request) error {
	if m.AssertUpdateUserPhoneMagicLink != nil {
		m.AssertUpdateUserPhoneMagicLink(method, identifier, email, URI, request)
	}
	return m.UpdateUserPhoneMagicLinkResponseError
}

func (m MockDescopeAuthenticationMagicLink) UpdateUserPhoneCrossDevice(method DeliveryMethod, identifier, email, URI string, request *http.Request) (*MagicLinkResponse, error) {
	if m.AssertUpdateUserPhoneMagicLinkCrossDevice != nil {
		m.AssertUpdateUserPhoneMagicLinkCrossDevice(method, identifier, email, URI, request)
	}
	return m.UpdateUserPhoneMagicLinkCrossDeviceResponse, m.UpdateUserPhoneMagicLinkCrossDeviceError
}

func (m MockDescopeAuthenticationMagicLink) GetSession(pendingRef string, _ http.ResponseWriter) (*AuthenticationInfo, error) {
	if m.AssertGetMagicLinkSession != nil {
		m.AssertGetMagicLinkSession(pendingRef)
	}
	return m.GetMagicLinkSessionResponseInfo, m.GetMagicLinkSessionResponseError
}

func (m MockDescopeAuthenticationMagicLink) GetSessionWithOptions(_ string, _ ...Option) (*AuthenticationInfo, error) {
	return m.GetMagicLinkSessionResponseInfo, m.GetMagicLinkSessionResponseError
}

func (m MockDescopeAuthenticationOAuth) Start(provider OAuthProvider, returnURL string, w http.ResponseWriter) (string, error) {
	return m.StartWithOptions(provider, returnURL, WithResponseOption(w))
}

func (m MockDescopeAuthenticationOAuth) StartWithOptions(provider OAuthProvider, returnURL string, _ ...Option) (string, error) {
	if m.AssertOAuthStart != nil {
		m.AssertOAuthStart(provider, returnURL)
	}
	return m.AssertOAuthResponseURL, m.OAuthStartResponseError
}

func (m MockDescopeAuthenticationExchanger) ExchangeToken(code string, w http.ResponseWriter) (*AuthenticationInfo, error) {
	return m.ExchangeTokenWithOptions(code, WithResponseOption(w))
}

func (m MockDescopeAuthenticationExchanger) ExchangeTokenWithOptions(code string, options ...Option) (*AuthenticationInfo, error) {
	if m.AssertExchangeToken != nil {
		m.AssertExchangeToken(code, options...)
	}
	return m.ExchangeTokenResponseInfo, m.ExchangeTokenResponseError
}

func (m MockDescopeAuthenticationSAML) Start(tenant string, returnURL string, w http.ResponseWriter) (string, error) {
	return m.StartWithOptions(tenant, returnURL, WithResponseOption(w))
}

func (m MockDescopeAuthenticationSAML) StartWithOptions(tenant string, returnURL string, option ...Option) (string, error) {
	if m.AssertSAMLStart != nil {
		m.AssertSAMLStart(tenant, returnURL, option...)
	}
	return m.AssertSAMLStartResponseURL, m.SAMLStartResponseError
}

func (m MockDescopeAuthenticationMagicLink) Verify(token string, _ http.ResponseWriter) (*AuthenticationInfo, error) {
	if m.AssertVerifyMagicLink != nil {
		m.AssertVerifyMagicLink(token)
	}
	return m.VerifyCodeResponseInfo, m.VerifyCodeResponseError
}

func (m MockDescopeAuthenticationMagicLink) VerifyWithOptions(token string, _ ...Option) (*AuthenticationInfo, error) {
	if m.AssertVerifyMagicLink != nil {
		m.AssertVerifyMagicLink(token)
	}
	return m.VerifyCodeResponseInfo, m.VerifyCodeResponseError
}

func (m MockDescopeAuthentication) ValidateSession(_ *http.Request, _ http.ResponseWriter) (bool, *Token, error) {
	return !m.ValidateSessionResponseNotOK, m.ValidateSessionResponseInfo, m.ValidateSessionResponseError
}

func (m MockDescopeAuthentication) ValidateSessionWithOptions(_ *http.Request, _ ...Option) (bool, *Token, error) {
	return !m.ValidateSessionResponseNotOK, m.ValidateSessionResponseInfo, m.ValidateSessionResponseError
}

func (m MockDescopeAuthentication) RefreshSession(_ *http.Request, _ http.ResponseWriter) (bool, *Token, error) {
	return !m.RefreshSessionResponseNotOK, m.RefreshSessionResponseInfo, m.RefreshSessionResponseError
}

func (m MockDescopeAuthentication) RefreshSessionWithOptions(_ *http.Request, _ ...Option) (bool, *Token, error) {
	return !m.RefreshSessionResponseNotOK, m.RefreshSessionResponseInfo, m.RefreshSessionResponseError
}

func (m MockDescopeAuthentication) Logout(r *http.Request, _ http.ResponseWriter) error {
	if m.AssertLogout != nil {
		m.AssertLogout(r)
	}
	return m.LogoutResponseError
}

func (m MockDescopeAuthentication) LogoutWithOptions(r *http.Request, _ ...Option) error {
	if m.AssertLogout != nil {
		m.AssertLogout(r)
	}
	return m.LogoutResponseError
}

func (m MockDescopeAuthenticationWebAuthn) SignUpStart(_ string, _ *User, _ string) (*WebAuthnTransactionResponse, error) {
	return m.SignUpWebAuthnStartResponseTransaction, m.SignUpWebAuthnStartResponseError
}

func (m MockDescopeAuthenticationWebAuthn) SignUpFinish(_ *WebAuthnFinishRequest, _ http.ResponseWriter) (*AuthenticationInfo, error) {
	return m.SignUpWebAuthnFinishResponseInfo, m.SignUpWebAuthnFinishResponseError
}

func (m MockDescopeAuthenticationWebAuthn) SignUpFinishWithOptions(_ *WebAuthnFinishRequest, _ ...Option) (*AuthenticationInfo, error) {
	return m.SignUpWebAuthnFinishResponseInfo, m.SignUpWebAuthnFinishResponseError
}

func (m MockDescopeAuthenticationWebAuthn) SignInStart(_ string, _ string) (*WebAuthnTransactionResponse, error) {
	return m.SignInWebAuthnStartResponseTransaction, m.SignInWebAuthnStartResponseError
}

func (m MockDescopeAuthenticationWebAuthn) SignInFinish(_ *WebAuthnFinishRequest, _ http.ResponseWriter) (*AuthenticationInfo, error) {
	return m.SignInWebAuthnFinishResponseInfo, m.SignInWebAuthnFinishResponseError
}

func (m MockDescopeAuthenticationWebAuthn) SignInFinishWithOptions(_ *WebAuthnFinishRequest, _ ...Option) (*AuthenticationInfo, error) {
	return m.SignInWebAuthnFinishResponseInfo, m.SignInWebAuthnFinishResponseError
}

func (m MockDescopeAuthenticationWebAuthn) UpdateUserDeviceStart(_ string, _ string, _ *http.Request) (*WebAuthnTransactionResponse, error) {
	return m.UpdateUserDeviceWebAuthnStartResponseTransaction, m.UpdateUserDeviceWebAuthnStartResponseError
}

func (m MockDescopeAuthenticationWebAuthn) UpdateUserDeviceFinish(_ *WebAuthnFinishRequest) error {
	return m.UpdateUserDeviceWebAuthnFinishResponseError
}

func (m MockDescopeAuthentication) ExchangeAccessKey(_ *http.Request) (bool, *Token, error) {
	return !m.ExchangeAccessKeyResponseNotOK, m.ExchangeAccessKeyResponseInfo, m.ExchangeAccessKeyResponseError
}
