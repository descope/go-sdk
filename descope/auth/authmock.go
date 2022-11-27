package auth

import (
	"net/http"
)

type MockDescopeAuthenticationOTP struct {
	AssertSignInOTP                 func(method DeliveryMethod, identifier string, r *http.Request, loginOptions *LoginOptions)
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
	AssertExchangeToken        func(code string, w http.ResponseWriter)
	ExchangeTokenResponseInfo  *AuthenticationInfo
	ExchangeTokenResponseError error
}

type MockDescopeAuthenticationSAML struct {
	MockDescopeAuthenticationExchanger
	AssertSAMLStart            func(tenant string, landingURL string, r *http.Request, loginOptions *LoginOptions, w http.ResponseWriter)
	AssertSAMLStartResponseURL string
	SAMLStartResponseError     error
}

type MockDescopeAuthenticationOAuth struct {
	MockDescopeAuthenticationExchanger
	AssertOAuthStart        func(provider OAuthProvider, landingURL string, r *http.Request, loginOptions *LoginOptions)
	AssertOAuthResponseURL  string
	OAuthStartResponseError error
}

type MockDescopeAuthenticationMagicLink struct {
	AssertSignInMagicLink                 func(method DeliveryMethod, identifier, URI string, r *http.Request, loginOptions *LoginOptions)
	AssertSignUpMagicLink                 func(method DeliveryMethod, identifier, URI string, user *User)
	AssertSignUpOrInMagicLink             func(method DeliveryMethod, identifier, URI string)
	SignUpMagicLinkResponseError          error
	SignInMagicLinkResponseError          error
	SignUpOrInMagicLinkResponseError      error
	AssertVerifyMagicLink                 func(token string)
	VerifyCodeResponseError               error
	VerifyCodeResponseInfo                *AuthenticationInfo
	AssertUpdateUserEmailMagicLink        func(identifier, email, URI string, request *http.Request)
	UpdateUserEmailMagicLinkResponseError error
	AssertUpdateUserPhoneMagicLink        func(method DeliveryMethod, identifier, email, URI string, request *http.Request)
	UpdateUserPhoneMagicLinkResponseError error
}

type MockDescopeAuthenticationEnchantedLink struct {
	AssertSignInEnchantedLink                 func(identifier, URI string, r *http.Request, loginOptions *LoginOptions)
	AssertSignUpEnchantedLink                 func(identifier, URI string, user *User)
	AssertSignUpOrInEnchantedLink             func(identifier, URI string)
	SignUpEnchantedLinkResponseError          error
	SignInEnchantedLinkResponseError          error
	SignUpOrInEnchantedLinkResponseError      error
	AssertGetEnchantedLinkSession             func(pendingRef string)
	AssertVerifyEnchantedLink                 func(token string)
	AssertVerifyEnchantedLinkResponseError    error
	VerifyCodeResponseError                   error
	EnchantedLinkPendingLinkResponse          *EnchantedLinkResponse
	AssertUpdateUserEmailEnchantedLink        func(identifier, email, URI string, request *http.Request)
	UpdateUserEmailEnchantedLinkResponseError error
	UpdateUserEmailEnchantedLinkResponse      *EnchantedLinkResponse
	GetEnchantedLinkSessionResponseInfo       *AuthenticationInfo
	GetEnchantedLinkSessionResponseError      error
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
	AssertVerifyTOTPCode        func(identifier string, code string, r *http.Request, loginOptions *LoginOptions)
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
	SignUpOrInWebAuthnStartResponseError             error
	SignUpOrInWebAuthnStartResponseTransaction       *WebAuthnTransactionResponse
	UpdateUserDeviceWebAuthnStartResponseError       error
	UpdateUserDeviceWebAuthnStartResponseTransaction *WebAuthnTransactionResponse
	UpdateUserDeviceWebAuthnFinishResponseError      error
}

type MockDescopeAuthentication struct {
	MockDescopeAuthenticationOTP
	MockDescopeAuthenticationMagicLink
	MockDescopeAuthenticationEnchantedLink
	MockDescopeAuthenticationSAML
	MockDescopeAuthenticationOAuth
	MockDescopeAuthenticationTOTP
	MockDescopeAuthenticationWebAuthn

	AssertLogout    func(r *http.Request)
	AssertLogoutAll func(r *http.Request)

	ValidateSessionResponseNotOK bool
	ValidateSessionResponseInfo  *Token
	ValidateSessionResponseError error

	RefreshSessionResponseNotOK bool
	RefreshSessionResponseInfo  *Token
	RefreshSessionResponseError error

	ValidatePermissionsResponse bool
	ValidateRolesResponse       bool

	LogoutResponseError    error
	LogoutAllResponseError error

	ExchangeAccessKeyResponseNotOK bool
	ExchangeAccessKeyResponseInfo  *Token
	ExchangeAccessKeyResponseError error

	MeResponseInfo  *UserResponse
	MeResponseError error
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

func (m MockDescopeAuthentication) EnchantedLink() EnchantedLink {
	return m.MockDescopeAuthenticationEnchantedLink
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

func (m MockDescopeAuthenticationOTP) SignIn(method DeliveryMethod, identifier string, r *http.Request, loginOptions *LoginOptions) error {
	if m.AssertSignInOTP != nil {
		m.AssertSignInOTP(method, identifier, r, loginOptions)
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

func (m MockDescopeAuthenticationTOTP) SignInCode(identifier string, code string, r *http.Request, loginOptions *LoginOptions, _ http.ResponseWriter) (*AuthenticationInfo, error) {
	if m.AssertVerifyTOTPCode != nil {
		m.AssertVerifyTOTPCode(identifier, code, r, loginOptions)
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

func (m MockDescopeAuthenticationMagicLink) SignIn(method DeliveryMethod, identifier, URI string, r *http.Request, loginOptions *LoginOptions) error {
	if m.AssertSignInMagicLink != nil {
		m.AssertSignInMagicLink(method, identifier, URI, r, loginOptions)
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

func (m MockDescopeAuthenticationMagicLink) UpdateUserEmail(identifier, email, URI string, request *http.Request) error {
	if m.AssertUpdateUserEmailMagicLink != nil {
		m.AssertUpdateUserEmailMagicLink(identifier, email, URI, request)
	}
	return m.UpdateUserEmailMagicLinkResponseError
}

func (m MockDescopeAuthenticationMagicLink) UpdateUserPhone(method DeliveryMethod, identifier, email, URI string, request *http.Request) error {
	if m.AssertUpdateUserPhoneMagicLink != nil {
		m.AssertUpdateUserPhoneMagicLink(method, identifier, email, URI, request)
	}
	return m.UpdateUserPhoneMagicLinkResponseError
}

func (m MockDescopeAuthenticationEnchantedLink) SignIn(identifier, URI string, r *http.Request, loginOptions *LoginOptions) (*EnchantedLinkResponse, error) {
	if m.AssertSignInEnchantedLink != nil {
		m.AssertSignInEnchantedLink(identifier, URI, r, loginOptions)
	}
	return m.EnchantedLinkPendingLinkResponse, m.SignInEnchantedLinkResponseError
}

func (m MockDescopeAuthenticationEnchantedLink) SignUp(identifier, URI string, user *User) (*EnchantedLinkResponse, error) {
	if m.AssertSignUpEnchantedLink != nil {
		m.AssertSignUpEnchantedLink(identifier, URI, user)
	}
	return m.EnchantedLinkPendingLinkResponse, m.SignUpEnchantedLinkResponseError
}

func (m MockDescopeAuthenticationEnchantedLink) SignUpOrIn(identifier string, URI string) (*EnchantedLinkResponse, error) {
	if m.AssertSignUpOrInEnchantedLink != nil {
		m.AssertSignUpOrInEnchantedLink(identifier, URI)
	}
	return m.EnchantedLinkPendingLinkResponse, m.SignUpOrInEnchantedLinkResponseError
}

func (m MockDescopeAuthenticationEnchantedLink) UpdateUserEmail(identifier, email, URI string, request *http.Request) (*EnchantedLinkResponse, error) {
	if m.AssertUpdateUserEmailEnchantedLink != nil {
		m.AssertUpdateUserEmailEnchantedLink(identifier, email, URI, request)
	}
	return m.UpdateUserEmailEnchantedLinkResponse, m.UpdateUserEmailEnchantedLinkResponseError
}

func (m MockDescopeAuthenticationEnchantedLink) GetSession(pendingRef string, _ http.ResponseWriter) (*AuthenticationInfo, error) {
	if m.AssertGetEnchantedLinkSession != nil {
		m.AssertGetEnchantedLinkSession(pendingRef)
	}
	return m.GetEnchantedLinkSessionResponseInfo, m.GetEnchantedLinkSessionResponseError
}

func (m MockDescopeAuthenticationEnchantedLink) Verify(token string) error {
	if m.AssertVerifyEnchantedLink != nil {
		m.AssertVerifyEnchantedLink(token)
	}
	return m.AssertVerifyEnchantedLinkResponseError
}

func (m MockDescopeAuthenticationOAuth) Start(provider OAuthProvider, returnURL string, r *http.Request, loginOptions *LoginOptions, _ http.ResponseWriter) (string, error) {
	if m.AssertOAuthStart != nil {
		m.AssertOAuthStart(provider, returnURL, r, loginOptions)
	}
	return m.AssertOAuthResponseURL, m.OAuthStartResponseError
}

func (m MockDescopeAuthenticationExchanger) ExchangeToken(code string, w http.ResponseWriter) (*AuthenticationInfo, error) {
	if m.AssertExchangeToken != nil {
		m.AssertExchangeToken(code, w)
	}
	return m.ExchangeTokenResponseInfo, m.ExchangeTokenResponseError
}

func (m MockDescopeAuthenticationSAML) Start(tenant string, returnURL string, r *http.Request, loginOptions *LoginOptions, w http.ResponseWriter) (string, error) {
	if m.AssertSAMLStart != nil {
		m.AssertSAMLStart(tenant, returnURL, r, loginOptions, w)
	}
	return m.AssertSAMLStartResponseURL, m.SAMLStartResponseError
}

func (m MockDescopeAuthenticationMagicLink) Verify(token string, _ http.ResponseWriter) (*AuthenticationInfo, error) {
	if m.AssertVerifyMagicLink != nil {
		m.AssertVerifyMagicLink(token)
	}
	return m.VerifyCodeResponseInfo, m.VerifyCodeResponseError
}

func (m MockDescopeAuthentication) ValidateSession(_ *http.Request, _ http.ResponseWriter) (bool, *Token, error) {
	return !m.ValidateSessionResponseNotOK, m.ValidateSessionResponseInfo, m.ValidateSessionResponseError
}

func (m MockDescopeAuthentication) ValidateSessionTokens(_ string, _ string) (bool, *Token, error) {
	return !m.ValidateSessionResponseNotOK, m.ValidateSessionResponseInfo, m.ValidateSessionResponseError
}

func (m MockDescopeAuthentication) RefreshSession(_ *http.Request, _ http.ResponseWriter) (bool, *Token, error) {
	return !m.RefreshSessionResponseNotOK, m.RefreshSessionResponseInfo, m.RefreshSessionResponseError
}

func (m MockDescopeAuthentication) ValidatePermissions(_ *Token, _ []string) bool {
	return m.ValidatePermissionsResponse
}

func (m MockDescopeAuthentication) ValidateTenantPermissions(_ *Token, _ string, _ []string) bool {
	return m.ValidatePermissionsResponse
}

func (m MockDescopeAuthentication) ValidateRoles(_ *Token, _ []string) bool {
	return m.ValidateRolesResponse
}

func (m MockDescopeAuthentication) ValidateTenantRoles(_ *Token, _ string, _ []string) bool {
	return m.ValidateRolesResponse
}

func (m MockDescopeAuthentication) Logout(r *http.Request, _ http.ResponseWriter) error {
	if m.AssertLogout != nil {
		m.AssertLogout(r)
	}
	return m.LogoutResponseError
}

func (m MockDescopeAuthentication) LogoutAll(r *http.Request, _ http.ResponseWriter) error {
	if m.AssertLogoutAll != nil {
		m.AssertLogoutAll(r)
	}
	return m.LogoutAllResponseError
}

func (m MockDescopeAuthenticationWebAuthn) SignUpStart(_ string, _ *User, _ string) (*WebAuthnTransactionResponse, error) {
	return m.SignUpWebAuthnStartResponseTransaction, m.SignUpWebAuthnStartResponseError
}

func (m MockDescopeAuthenticationWebAuthn) SignUpFinish(_ *WebAuthnFinishRequest, _ http.ResponseWriter) (*AuthenticationInfo, error) {
	return m.SignUpWebAuthnFinishResponseInfo, m.SignUpWebAuthnFinishResponseError
}

func (m MockDescopeAuthenticationWebAuthn) SignInStart(_ string, _ string, _ *http.Request, _ *LoginOptions) (*WebAuthnTransactionResponse, error) {
	return m.SignInWebAuthnStartResponseTransaction, m.SignInWebAuthnStartResponseError
}

func (m MockDescopeAuthenticationWebAuthn) SignInFinish(_ *WebAuthnFinishRequest, _ http.ResponseWriter) (*AuthenticationInfo, error) {
	return m.SignInWebAuthnFinishResponseInfo, m.SignInWebAuthnFinishResponseError
}

func (m MockDescopeAuthenticationWebAuthn) SignUpOrInStart(_ string, _ string) (*WebAuthnTransactionResponse, error) {
	return m.SignUpOrInWebAuthnStartResponseTransaction, m.SignUpOrInWebAuthnStartResponseError
}

func (m MockDescopeAuthenticationWebAuthn) UpdateUserDeviceStart(_ string, _ string, _ *http.Request) (*WebAuthnTransactionResponse, error) {
	return m.UpdateUserDeviceWebAuthnStartResponseTransaction, m.UpdateUserDeviceWebAuthnStartResponseError
}

func (m MockDescopeAuthenticationWebAuthn) UpdateUserDeviceFinish(_ *WebAuthnFinishRequest) error {
	return m.UpdateUserDeviceWebAuthnFinishResponseError
}

func (m MockDescopeAuthentication) ExchangeAccessKey(_ string) (bool, *Token, error) {
	return !m.ExchangeAccessKeyResponseNotOK, m.ExchangeAccessKeyResponseInfo, m.ExchangeAccessKeyResponseError
}

func (m MockDescopeAuthentication) Me(_ *http.Request) (*UserResponse, error) {
	return m.MeResponseInfo, m.MeResponseError
}
