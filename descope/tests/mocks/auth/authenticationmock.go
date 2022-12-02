package authmocks

import (
	"net/http"

	"github.com/descope/go-sdk/descope/auth"
)

type MockAuthentication struct {
	MockMagicLink
	MockEnchantedLink
	MockOTP
	MockTOTP
	MockOAuth
	MockSAML
	MockWebAuthn
	MockOthers
}

func (m MockAuthentication) MagicLink() auth.MagicLink {
	return m.MockMagicLink
}

func (m MockAuthentication) EnchantedLink() auth.EnchantedLink {
	return m.MockEnchantedLink
}

func (m MockAuthentication) OTP() auth.OTP {
	return m.MockOTP
}

func (m MockAuthentication) TOTP() auth.TOTP {
	return m.MockTOTP
}

func (m MockAuthentication) OAuth() auth.OAuth {
	return m.MockOAuth
}

func (m MockAuthentication) SAML() auth.SAML {
	return m.MockSAML
}

func (m MockAuthentication) WebAuthn() auth.WebAuthn {
	return m.MockWebAuthn
}

// Mock MagicLink

type MockMagicLink struct {
	SignInAssert func(method auth.DeliveryMethod, identifier, URI string, r *http.Request, loginOptions *auth.LoginOptions)
	SignInError  error

	SignUpAssert func(method auth.DeliveryMethod, identifier, URI string, user *auth.User)
	SignUpError  error

	SignUpOrInAssert func(method auth.DeliveryMethod, identifier string, URI string)
	SignUpOrInError  error

	VerifyAssert   func(token string, w http.ResponseWriter) (*auth.AuthenticationInfo, error)
	VerifyError    error
	VerifyResponse *auth.AuthenticationInfo

	UpdateUserEmailAssert func(identifier, email, URI string, request *http.Request)
	UpdateUserEmailError  error

	UpdateUserPhoneAssert func(method auth.DeliveryMethod, identifier, phone, URI string, request *http.Request)
	UpdateUserPhoneError  error
}

func (m MockMagicLink) SignIn(method auth.DeliveryMethod, identifier, URI string, r *http.Request, loginOptions *auth.LoginOptions) error {
	if m.SignInAssert != nil {
		m.SignInAssert(method, identifier, URI, r, loginOptions)
	}
	return m.SignInError
}

func (m MockMagicLink) SignUp(method auth.DeliveryMethod, identifier, URI string, user *auth.User) error {
	if m.SignUpAssert != nil {
		m.SignUpAssert(method, identifier, URI, user)
	}
	return m.SignUpError
}

func (m MockMagicLink) SignUpOrIn(method auth.DeliveryMethod, identifier string, URI string) error {
	if m.SignUpOrInAssert != nil {
		m.SignUpOrInAssert(method, identifier, URI)
	}
	return m.SignUpOrInError
}

func (m MockMagicLink) Verify(token string, w http.ResponseWriter) (*auth.AuthenticationInfo, error) {
	if m.VerifyAssert != nil {
		m.VerifyAssert(token, w)
	}
	return m.VerifyResponse, m.VerifyError
}

func (m MockMagicLink) UpdateUserEmail(identifier, email, URI string, request *http.Request) error {
	if m.UpdateUserEmailAssert != nil {
		m.UpdateUserEmailAssert(identifier, email, URI, request)
	}
	return m.UpdateUserEmailError
}

func (m MockMagicLink) UpdateUserPhone(method auth.DeliveryMethod, identifier, phone, URI string, request *http.Request) error {
	if m.UpdateUserPhoneAssert != nil {
		m.UpdateUserPhoneAssert(method, identifier, phone, URI, request)
	}
	return m.UpdateUserPhoneError
}

// Mock EnchantedLink

type MockEnchantedLink struct {
	SignInAssert   func(identifier, URI string, r *http.Request, loginOptions *auth.LoginOptions)
	SignInError    error
	SignInResponse *auth.EnchantedLinkResponse

	SignUpAssert   func(identifier, URI string, user *auth.User)
	SignUpError    error
	SignUpResponse *auth.EnchantedLinkResponse

	SignUpOrInAssert   func(identifier string, URI string)
	SignUpOrInError    error
	SignUpOrInResponse *auth.EnchantedLinkResponse

	GetSessionAssert   func(pendingRef string, w http.ResponseWriter)
	GetSessionResponse *auth.AuthenticationInfo
	GetSessionError    error

	VerifyAssert func(token string) (*auth.AuthenticationInfo, error)
	VerifyError  error

	UpdateUserEmailAssert   func(identifier, email, URI string, request *http.Request)
	UpdateUserEmailError    error
	UpdateUserEmailResponse *auth.EnchantedLinkResponse

	UpdateUserPhoneAssert func(method auth.DeliveryMethod, identifier, phone, URI string, request *http.Request)
	UpdateUserPhoneError  error
}

func (m MockEnchantedLink) SignIn(identifier, URI string, r *http.Request, loginOptions *auth.LoginOptions) (*auth.EnchantedLinkResponse, error) {
	if m.SignInAssert != nil {
		m.SignInAssert(identifier, URI, r, loginOptions)
	}
	return m.SignInResponse, m.SignInError
}

func (m MockEnchantedLink) SignUp(identifier, URI string, user *auth.User) (*auth.EnchantedLinkResponse, error) {
	if m.SignUpAssert != nil {
		m.SignUpAssert(identifier, URI, user)
	}
	return m.SignUpResponse, m.SignUpError
}

func (m MockEnchantedLink) SignUpOrIn(identifier string, URI string) (*auth.EnchantedLinkResponse, error) {
	if m.SignUpOrInAssert != nil {
		m.SignUpOrInAssert(identifier, URI)
	}
	return m.SignUpOrInResponse, m.SignUpOrInError
}

func (m MockEnchantedLink) GetSession(pendingRef string, w http.ResponseWriter) (*auth.AuthenticationInfo, error) {
	if m.GetSessionAssert != nil {
		m.GetSessionAssert(pendingRef, w)
	}
	return m.GetSessionResponse, m.GetSessionError
}

func (m MockEnchantedLink) Verify(token string) error {
	if m.VerifyAssert != nil {
		m.VerifyAssert(token)
	}
	return m.VerifyError
}

func (m MockEnchantedLink) UpdateUserEmail(identifier, email, URI string, request *http.Request) (*auth.EnchantedLinkResponse, error) {
	if m.UpdateUserEmailAssert != nil {
		m.UpdateUserEmailAssert(identifier, email, URI, request)
	}
	return m.UpdateUserEmailResponse, m.UpdateUserEmailError
}

// Mock OTP

type MockOTP struct {
	SignInAssert func(method auth.DeliveryMethod, identifier string, r *http.Request, loginOptions *auth.LoginOptions)
	SignInError  error

	SignUpAssert func(method auth.DeliveryMethod, identifier string, user *auth.User)
	SignUpError  error

	SignUpOrInAssert func(method auth.DeliveryMethod, identifier string)
	SignUpOrInError  error

	VerifyCodeAssert   func(method auth.DeliveryMethod, identifier string, code string, w http.ResponseWriter)
	VerifyCodeError    error
	VerifyCodeResponse *auth.AuthenticationInfo

	UpdateUserEmailAssert func(identifier, email string, request *http.Request)
	UpdateUserEmailError  error

	UpdateUserPhoneAssert func(method auth.DeliveryMethod, identifier, phone string, request *http.Request)
	UpdateUserPhoneError  error
}

func (m MockOTP) SignIn(method auth.DeliveryMethod, identifier string, r *http.Request, loginOptions *auth.LoginOptions) error {
	if m.SignInAssert != nil {
		m.SignInAssert(method, identifier, r, loginOptions)
	}
	return m.SignInError
}

func (m MockOTP) SignUp(method auth.DeliveryMethod, identifier string, user *auth.User) error {
	if m.SignUpAssert != nil {
		m.SignUpAssert(method, identifier, user)
	}
	return m.SignUpError
}

func (m MockOTP) SignUpOrIn(method auth.DeliveryMethod, identifier string) error {
	if m.SignUpOrInAssert != nil {
		m.SignUpOrInAssert(method, identifier)
	}
	return m.SignUpOrInError
}

func (m MockOTP) VerifyCode(method auth.DeliveryMethod, identifier string, code string, w http.ResponseWriter) (*auth.AuthenticationInfo, error) {
	if m.VerifyCodeAssert != nil {
		m.VerifyCodeAssert(method, identifier, code, w)
	}
	return m.VerifyCodeResponse, m.VerifyCodeError
}

func (m MockOTP) UpdateUserEmail(identifier, email string, request *http.Request) error {
	if m.UpdateUserEmailAssert != nil {
		m.UpdateUserEmailAssert(identifier, email, request)
	}
	return m.UpdateUserEmailError
}

func (m MockOTP) UpdateUserPhone(method auth.DeliveryMethod, identifier, phone string, request *http.Request) error {
	if m.UpdateUserPhoneAssert != nil {
		m.UpdateUserPhoneAssert(method, identifier, phone, request)
	}
	return m.UpdateUserPhoneError
}

// Mock TOTP

type MockTOTP struct {
	SignUpAssert   func(identifier string, user *auth.User)
	SignUpError    error
	SignUpResponse *auth.TOTPResponse

	SignInCodeAssert   func(identifier string, code string, r *http.Request, loginOptions *auth.LoginOptions, w http.ResponseWriter)
	SignInCodeError    error
	SignInCodeResponse *auth.AuthenticationInfo

	UpdateUserAssert   func(identifier string, request *http.Request)
	UpdateUserError    error
	UpdateUserResponse *auth.TOTPResponse
}

func (m MockTOTP) SignUp(identifier string, user *auth.User) (*auth.TOTPResponse, error) {
	if m.SignUpAssert != nil {
		m.SignUpAssert(identifier, user)
	}
	return m.SignUpResponse, m.SignUpError
}

func (m MockTOTP) SignInCode(identifier string, code string, r *http.Request, loginOptions *auth.LoginOptions, w http.ResponseWriter) (*auth.AuthenticationInfo, error) {
	if m.SignInCodeAssert != nil {
		m.SignInCodeAssert(identifier, code, r, loginOptions, w)
	}
	return m.SignInCodeResponse, m.SignInCodeError
}

func (m MockTOTP) UpdateUser(identifier string, request *http.Request) (*auth.TOTPResponse, error) {
	if m.UpdateUserAssert != nil {
		m.UpdateUserAssert(identifier, request)
	}
	return m.UpdateUserResponse, m.UpdateUserError
}

// Mock OAuth

type MockOAuth struct {
	StartAssert   func(provider auth.OAuthProvider, returnURL string, r *http.Request, loginOptions *auth.LoginOptions, w http.ResponseWriter)
	StartError    error
	StartResponse string

	ExchangeTokenAssert   func(code string, w http.ResponseWriter)
	ExchangeTokenError    error
	ExchangeTokenResponse *auth.AuthenticationInfo
}

func (m MockOAuth) Start(provider auth.OAuthProvider, returnURL string, r *http.Request, loginOptions *auth.LoginOptions, w http.ResponseWriter) (string, error) {
	if m.StartAssert != nil {
		m.StartAssert(provider, returnURL, r, loginOptions, w)
	}
	return m.StartResponse, m.StartError
}

func (m MockOAuth) ExchangeToken(code string, w http.ResponseWriter) (*auth.AuthenticationInfo, error) {
	if m.ExchangeTokenAssert != nil {
		m.ExchangeTokenAssert(code, w)
	}
	return m.ExchangeTokenResponse, m.ExchangeTokenError
}

// Mock SAML

type MockSAML struct {
	StartAssert   func(tenant string, returnURL string, r *http.Request, loginOptions *auth.LoginOptions, w http.ResponseWriter)
	StartError    error
	StartResponse string

	ExchangeTokenAssert   func(code string, w http.ResponseWriter)
	ExchangeTokenError    error
	ExchangeTokenResponse *auth.AuthenticationInfo
}

func (m MockSAML) Start(tenant string, returnURL string, r *http.Request, loginOptions *auth.LoginOptions, w http.ResponseWriter) (redirectURL string, err error) {
	if m.StartAssert != nil {
		m.StartAssert(tenant, returnURL, r, loginOptions, w)
	}
	return m.StartResponse, m.StartError
}

func (m MockSAML) ExchangeToken(code string, w http.ResponseWriter) (*auth.AuthenticationInfo, error) {
	if m.ExchangeTokenAssert != nil {
		m.ExchangeTokenAssert(code, w)
	}
	return m.ExchangeTokenResponse, m.ExchangeTokenError
}

// Mock WebAuthn

type MockWebAuthn struct {
	SignUpStartAssert   func(identifier string, user *auth.User, origin string)
	SignUpStartError    error
	SignUpStartResponse *auth.WebAuthnTransactionResponse

	SignUpFinishAssert   func(finishRequest *auth.WebAuthnFinishRequest, w http.ResponseWriter)
	SignUpFinishError    error
	SignUpFinishResponse *auth.AuthenticationInfo

	SignInStartAssert   func(identifier string, origin string, r *http.Request, loginOptions *auth.LoginOptions)
	SignInStartError    error
	SignInStartResponse *auth.WebAuthnTransactionResponse

	SignInFinishAssert   func(finishRequest *auth.WebAuthnFinishRequest, w http.ResponseWriter)
	SignInFinishError    error
	SignInFinishResponse *auth.AuthenticationInfo

	SignUpOrInStartAssert   func(identifier string, origin string)
	SignUpOrInStartError    error
	SignUpOrInStartResponse *auth.WebAuthnTransactionResponse

	UpdateUserDeviceStartAssert   func(identifier string, origin string, request *http.Request)
	UpdateUserDeviceStartError    error
	UpdateUserDeviceStartResponse *auth.WebAuthnTransactionResponse

	UpdateUserDeviceFinishAssert func(finishRequest *auth.WebAuthnFinishRequest)
	UpdateUserDeviceFinishError  error
}

func (m MockWebAuthn) SignUpStart(identifier string, user *auth.User, origin string) (*auth.WebAuthnTransactionResponse, error) {
	if m.SignUpStartAssert != nil {
		m.SignUpStartAssert(identifier, user, origin)
	}
	return m.SignUpStartResponse, m.SignUpStartError
}

func (m MockWebAuthn) SignUpFinish(finishRequest *auth.WebAuthnFinishRequest, w http.ResponseWriter) (*auth.AuthenticationInfo, error) {
	if m.SignUpFinishAssert != nil {
		m.SignUpFinishAssert(finishRequest, w)
	}
	return m.SignUpFinishResponse, m.SignUpFinishError
}

func (m MockWebAuthn) SignInStart(identifier string, origin string, r *http.Request, loginOptions *auth.LoginOptions) (*auth.WebAuthnTransactionResponse, error) {
	if m.SignInStartAssert != nil {
		m.SignInStartAssert(identifier, origin, r, loginOptions)
	}
	return m.SignInStartResponse, m.SignInStartError
}

func (m MockWebAuthn) SignInFinish(finishRequest *auth.WebAuthnFinishRequest, w http.ResponseWriter) (*auth.AuthenticationInfo, error) {
	if m.SignInFinishAssert != nil {
		m.SignInFinishAssert(finishRequest, w)
	}
	return m.SignInFinishResponse, m.SignInFinishError
}

func (m MockWebAuthn) SignUpOrInStart(identifier string, origin string) (*auth.WebAuthnTransactionResponse, error) {
	if m.SignUpOrInStartAssert != nil {
		m.SignUpOrInStartAssert(identifier, origin)
	}
	return m.SignUpOrInStartResponse, m.SignUpOrInStartError
}

func (m MockWebAuthn) UpdateUserDeviceStart(identifier string, origin string, request *http.Request) (*auth.WebAuthnTransactionResponse, error) {
	if m.UpdateUserDeviceStartAssert != nil {
		m.UpdateUserDeviceStartAssert(identifier, origin, request)
	}
	return m.UpdateUserDeviceStartResponse, m.UpdateUserDeviceStartError
}

func (m MockWebAuthn) UpdateUserDeviceFinish(finishRequest *auth.WebAuthnFinishRequest) error {
	if m.UpdateUserDeviceFinishAssert != nil {
		m.UpdateUserDeviceFinishAssert(finishRequest)
	}
	return m.UpdateUserDeviceFinishError
}

// Mock Others

type MockOthers struct {
	ValidateSessionAssert          func(request *http.Request, w http.ResponseWriter)
	ValidateSessionError           error
	ValidateSessionResponse        *auth.Token
	ValidateSessionResponseSuccess bool

	ValidateSessionTokensAssert          func(sessionToken, refreshToken string)
	ValidateSessionTokensError           error
	ValidateSessionTokensResponse        *auth.Token
	ValidateSessionTokensResponseSuccess bool

	RefreshSessionAssert          func(request *http.Request, w http.ResponseWriter)
	RefreshSessionError           error
	RefreshSessionResponse        *auth.Token
	RefreshSessionResponseSuccess bool

	ExchangeAccessKeyAssert          func(accessKey string)
	ExchangeAccessKeyError           error
	ExchangeAccessKeyResponse        *auth.Token
	ExchangeAccessKeyResponseSuccess bool

	ValidatePermissionsAssert   func(token *auth.Token, permissions []string)
	ValidatePermissionsResponse bool

	ValidateTenantPermissionsAssert   func(token *auth.Token, tenant string, permissions []string)
	ValidateTenantPermissionsResponse bool

	ValidateRolesAssert   func(token *auth.Token, roles []string)
	ValidateRolesResponse bool

	ValidateTenantRolesAssert   func(token *auth.Token, tenant string, roles []string)
	ValidateTenantRolesResponse bool

	LogoutAssert func(request *http.Request, w http.ResponseWriter)
	LogoutError  error

	LogoutAllAssert func(request *http.Request, w http.ResponseWriter)
	LogoutAllError  error

	MeAssert   func(request *http.Request)
	MeError    error
	MeResponse *auth.UserResponse
}

func (m MockOthers) ValidateSession(request *http.Request, w http.ResponseWriter) (bool, *auth.Token, error) {
	if m.ValidateSessionAssert != nil {
		m.ValidateSessionAssert(request, w)
	}
	return m.ValidateSessionResponseSuccess, m.ValidateSessionResponse, m.ValidateSessionError
}

func (m MockOthers) ValidateSessionTokens(sessionToken, refreshToken string) (bool, *auth.Token, error) {
	if m.ValidateSessionTokensAssert != nil {
		m.ValidateSessionTokensAssert(sessionToken, refreshToken)
	}
	return m.ValidateSessionTokensResponseSuccess, m.ValidateSessionTokensResponse, m.ValidateSessionTokensError
}

func (m MockOthers) RefreshSession(request *http.Request, w http.ResponseWriter) (bool, *auth.Token, error) {
	if m.RefreshSessionAssert != nil {
		m.RefreshSessionAssert(request, w)
	}
	return m.RefreshSessionResponseSuccess, m.RefreshSessionResponse, m.RefreshSessionError
}

func (m MockOthers) ExchangeAccessKey(accessKey string) (bool, *auth.Token, error) {
	if m.ExchangeAccessKeyAssert != nil {
		m.ExchangeAccessKeyAssert(accessKey)
	}
	return m.ExchangeAccessKeyResponseSuccess, m.ExchangeAccessKeyResponse, m.ExchangeAccessKeyError
}

func (m MockOthers) ValidatePermissions(token *auth.Token, permissions []string) bool {
	if m.ValidatePermissionsAssert != nil {
		m.ValidatePermissionsAssert(token, permissions)
	}
	return m.ValidatePermissionsResponse
}

func (m MockOthers) ValidateTenantPermissions(token *auth.Token, tenant string, permissions []string) bool {
	if m.ValidateTenantPermissionsAssert != nil {
		m.ValidateTenantPermissionsAssert(token, tenant, permissions)
	}
	return m.ValidateTenantPermissionsResponse
}

func (m MockOthers) ValidateRoles(token *auth.Token, roles []string) bool {
	if m.ValidateRolesAssert != nil {
		m.ValidateRolesAssert(token, roles)
	}
	return m.ValidateRolesResponse
}

func (m MockOthers) ValidateTenantRoles(token *auth.Token, tenant string, roles []string) bool {
	if m.ValidateTenantRolesAssert != nil {
		m.ValidateTenantRolesAssert(token, tenant, roles)
	}
	return m.ValidateTenantRolesResponse
}

func (m MockOthers) Logout(request *http.Request, w http.ResponseWriter) error {
	if m.LogoutAssert != nil {
		m.LogoutAssert(request, w)
	}
	return m.LogoutError
}

func (m MockOthers) LogoutAll(request *http.Request, w http.ResponseWriter) error {
	if m.LogoutAllAssert != nil {
		m.LogoutAllAssert(request, w)
	}
	return m.LogoutAllError
}

func (m MockOthers) Me(request *http.Request) (*auth.UserResponse, error) {
	if m.MeAssert != nil {
		m.MeAssert(request)
	}
	return m.MeResponse, m.MeError
}
