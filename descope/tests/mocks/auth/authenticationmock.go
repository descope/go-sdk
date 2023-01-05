package mocksauth

import (
	"net/http"

	"github.com/descope/go-sdk/descope/auth"
)

type MockAuthentication struct {
	*MockMagicLink
	*MockEnchantedLink
	*MockOTP
	*MockTOTP
	*MockOAuth
	*MockSAML
	*MockWebAuthn
	MockSession
}

func (m *MockAuthentication) MagicLink() auth.MagicLink {
	return m.MockMagicLink
}

func (m *MockAuthentication) EnchantedLink() auth.EnchantedLink {
	return m.MockEnchantedLink
}

func (m *MockAuthentication) OTP() auth.OTP {
	return m.MockOTP
}

func (m *MockAuthentication) TOTP() auth.TOTP {
	return m.MockTOTP
}

func (m *MockAuthentication) OAuth() auth.OAuth {
	return m.MockOAuth
}

func (m *MockAuthentication) SAML() auth.SAML {
	return m.MockSAML
}

func (m *MockAuthentication) WebAuthn() auth.WebAuthn {
	return m.MockWebAuthn
}

// Mock MagicLink

type MockMagicLink struct {
	SignInAssert func(method auth.DeliveryMethod, loginID, URI string, r *http.Request, loginOptions *auth.LoginOptions)
	SignInError  error

	SignUpAssert func(method auth.DeliveryMethod, loginID, URI string, user *auth.User)
	SignUpError  error

	SignUpOrInAssert func(method auth.DeliveryMethod, loginID string, URI string)
	SignUpOrInError  error

	VerifyAssert   func(token string, w http.ResponseWriter) (*auth.AuthenticationInfo, error)
	VerifyError    error
	VerifyResponse *auth.AuthenticationInfo

	UpdateUserEmailAssert func(loginID, email, URI string, r *http.Request)
	UpdateUserEmailError  error

	UpdateUserPhoneAssert func(method auth.DeliveryMethod, loginID, phone, URI string, r *http.Request)
	UpdateUserPhoneError  error
}

func (m *MockMagicLink) SignIn(method auth.DeliveryMethod, loginID, URI string, r *http.Request, loginOptions *auth.LoginOptions) error {
	if m.SignInAssert != nil {
		m.SignInAssert(method, loginID, URI, r, loginOptions)
	}
	return m.SignInError
}

func (m *MockMagicLink) SignUp(method auth.DeliveryMethod, loginID, URI string, user *auth.User) error {
	if m.SignUpAssert != nil {
		m.SignUpAssert(method, loginID, URI, user)
	}
	return m.SignUpError
}

func (m *MockMagicLink) SignUpOrIn(method auth.DeliveryMethod, loginID string, URI string) error {
	if m.SignUpOrInAssert != nil {
		m.SignUpOrInAssert(method, loginID, URI)
	}
	return m.SignUpOrInError
}

func (m *MockMagicLink) Verify(token string, w http.ResponseWriter) (*auth.AuthenticationInfo, error) {
	if m.VerifyAssert != nil {
		m.VerifyAssert(token, w)
	}
	return m.VerifyResponse, m.VerifyError
}

func (m *MockMagicLink) UpdateUserEmail(loginID, email, URI string, r *http.Request) error {
	if m.UpdateUserEmailAssert != nil {
		m.UpdateUserEmailAssert(loginID, email, URI, r)
	}
	return m.UpdateUserEmailError
}

func (m *MockMagicLink) UpdateUserPhone(method auth.DeliveryMethod, loginID, phone, URI string, r *http.Request) error {
	if m.UpdateUserPhoneAssert != nil {
		m.UpdateUserPhoneAssert(method, loginID, phone, URI, r)
	}
	return m.UpdateUserPhoneError
}

// Mock EnchantedLink

type MockEnchantedLink struct {
	SignInAssert   func(loginID, URI string, r *http.Request, loginOptions *auth.LoginOptions)
	SignInError    error
	SignInResponse *auth.EnchantedLinkResponse

	SignUpAssert   func(loginID, URI string, user *auth.User)
	SignUpError    error
	SignUpResponse *auth.EnchantedLinkResponse

	SignUpOrInAssert   func(loginID string, URI string)
	SignUpOrInError    error
	SignUpOrInResponse *auth.EnchantedLinkResponse

	GetSessionAssert   func(pendingRef string, w http.ResponseWriter)
	GetSessionResponse *auth.AuthenticationInfo
	GetSessionError    error

	VerifyAssert func(token string) (*auth.AuthenticationInfo, error)
	VerifyError  error

	UpdateUserEmailAssert   func(loginID, email, URI string, r *http.Request)
	UpdateUserEmailError    error
	UpdateUserEmailResponse *auth.EnchantedLinkResponse

	UpdateUserPhoneAssert func(method auth.DeliveryMethod, loginID, phone, URI string, r *http.Request)
	UpdateUserPhoneError  error
}

func (m *MockEnchantedLink) SignIn(loginID, URI string, r *http.Request, loginOptions *auth.LoginOptions) (*auth.EnchantedLinkResponse, error) {
	if m.SignInAssert != nil {
		m.SignInAssert(loginID, URI, r, loginOptions)
	}
	return m.SignInResponse, m.SignInError
}

func (m *MockEnchantedLink) SignUp(loginID, URI string, user *auth.User) (*auth.EnchantedLinkResponse, error) {
	if m.SignUpAssert != nil {
		m.SignUpAssert(loginID, URI, user)
	}
	return m.SignUpResponse, m.SignUpError
}

func (m *MockEnchantedLink) SignUpOrIn(loginID string, URI string) (*auth.EnchantedLinkResponse, error) {
	if m.SignUpOrInAssert != nil {
		m.SignUpOrInAssert(loginID, URI)
	}
	return m.SignUpOrInResponse, m.SignUpOrInError
}

func (m *MockEnchantedLink) GetSession(pendingRef string, w http.ResponseWriter) (*auth.AuthenticationInfo, error) {
	if m.GetSessionAssert != nil {
		m.GetSessionAssert(pendingRef, w)
	}
	return m.GetSessionResponse, m.GetSessionError
}

func (m *MockEnchantedLink) Verify(token string) error {
	if m.VerifyAssert != nil {
		m.VerifyAssert(token)
	}
	return m.VerifyError
}

func (m *MockEnchantedLink) UpdateUserEmail(loginID, email, URI string, r *http.Request) (*auth.EnchantedLinkResponse, error) {
	if m.UpdateUserEmailAssert != nil {
		m.UpdateUserEmailAssert(loginID, email, URI, r)
	}
	return m.UpdateUserEmailResponse, m.UpdateUserEmailError
}

// Mock OTP

type MockOTP struct {
	SignInAssert func(method auth.DeliveryMethod, loginID string, r *http.Request, loginOptions *auth.LoginOptions)
	SignInError  error

	SignUpAssert func(method auth.DeliveryMethod, loginID string, user *auth.User)
	SignUpError  error

	SignUpOrInAssert func(method auth.DeliveryMethod, loginID string)
	SignUpOrInError  error

	VerifyCodeAssert   func(method auth.DeliveryMethod, loginID string, code string, w http.ResponseWriter)
	VerifyCodeError    error
	VerifyCodeResponse *auth.AuthenticationInfo

	UpdateUserEmailAssert func(loginID, email string, r *http.Request)
	UpdateUserEmailError  error

	UpdateUserPhoneAssert func(method auth.DeliveryMethod, loginID, phone string, r *http.Request)
	UpdateUserPhoneError  error
}

func (m *MockOTP) SignIn(method auth.DeliveryMethod, loginID string, r *http.Request, loginOptions *auth.LoginOptions) error {
	if m.SignInAssert != nil {
		m.SignInAssert(method, loginID, r, loginOptions)
	}
	return m.SignInError
}

func (m *MockOTP) SignUp(method auth.DeliveryMethod, loginID string, user *auth.User) error {
	if m.SignUpAssert != nil {
		m.SignUpAssert(method, loginID, user)
	}
	return m.SignUpError
}

func (m *MockOTP) SignUpOrIn(method auth.DeliveryMethod, loginID string) error {
	if m.SignUpOrInAssert != nil {
		m.SignUpOrInAssert(method, loginID)
	}
	return m.SignUpOrInError
}

func (m *MockOTP) VerifyCode(method auth.DeliveryMethod, loginID string, code string, w http.ResponseWriter) (*auth.AuthenticationInfo, error) {
	if m.VerifyCodeAssert != nil {
		m.VerifyCodeAssert(method, loginID, code, w)
	}
	return m.VerifyCodeResponse, m.VerifyCodeError
}

func (m *MockOTP) UpdateUserEmail(loginID, email string, r *http.Request) error {
	if m.UpdateUserEmailAssert != nil {
		m.UpdateUserEmailAssert(loginID, email, r)
	}
	return m.UpdateUserEmailError
}

func (m *MockOTP) UpdateUserPhone(method auth.DeliveryMethod, loginID, phone string, r *http.Request) error {
	if m.UpdateUserPhoneAssert != nil {
		m.UpdateUserPhoneAssert(method, loginID, phone, r)
	}
	return m.UpdateUserPhoneError
}

// Mock TOTP

type MockTOTP struct {
	SignUpAssert   func(loginID string, user *auth.User)
	SignUpError    error
	SignUpResponse *auth.TOTPResponse

	SignInCodeAssert   func(loginID string, code string, r *http.Request, loginOptions *auth.LoginOptions, w http.ResponseWriter)
	SignInCodeError    error
	SignInCodeResponse *auth.AuthenticationInfo

	UpdateUserAssert   func(loginID string, r *http.Request)
	UpdateUserError    error
	UpdateUserResponse *auth.TOTPResponse
}

func (m *MockTOTP) SignUp(loginID string, user *auth.User) (*auth.TOTPResponse, error) {
	if m.SignUpAssert != nil {
		m.SignUpAssert(loginID, user)
	}
	return m.SignUpResponse, m.SignUpError
}

func (m *MockTOTP) SignInCode(loginID string, code string, r *http.Request, loginOptions *auth.LoginOptions, w http.ResponseWriter) (*auth.AuthenticationInfo, error) {
	if m.SignInCodeAssert != nil {
		m.SignInCodeAssert(loginID, code, r, loginOptions, w)
	}
	return m.SignInCodeResponse, m.SignInCodeError
}

func (m *MockTOTP) UpdateUser(loginID string, r *http.Request) (*auth.TOTPResponse, error) {
	if m.UpdateUserAssert != nil {
		m.UpdateUserAssert(loginID, r)
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

func (m *MockOAuth) Start(provider auth.OAuthProvider, returnURL string, r *http.Request, loginOptions *auth.LoginOptions, w http.ResponseWriter) (string, error) {
	if m.StartAssert != nil {
		m.StartAssert(provider, returnURL, r, loginOptions, w)
	}
	return m.StartResponse, m.StartError
}

func (m *MockOAuth) ExchangeToken(code string, w http.ResponseWriter) (*auth.AuthenticationInfo, error) {
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

func (m *MockSAML) Start(tenant string, returnURL string, r *http.Request, loginOptions *auth.LoginOptions, w http.ResponseWriter) (redirectURL string, err error) {
	if m.StartAssert != nil {
		m.StartAssert(tenant, returnURL, r, loginOptions, w)
	}
	return m.StartResponse, m.StartError
}

func (m *MockSAML) ExchangeToken(code string, w http.ResponseWriter) (*auth.AuthenticationInfo, error) {
	if m.ExchangeTokenAssert != nil {
		m.ExchangeTokenAssert(code, w)
	}
	return m.ExchangeTokenResponse, m.ExchangeTokenError
}

// Mock WebAuthn

type MockWebAuthn struct {
	SignUpStartAssert   func(loginID string, user *auth.User, origin string)
	SignUpStartError    error
	SignUpStartResponse *auth.WebAuthnTransactionResponse

	SignUpFinishAssert   func(finishRequest *auth.WebAuthnFinishRequest, w http.ResponseWriter)
	SignUpFinishError    error
	SignUpFinishResponse *auth.AuthenticationInfo

	SignInStartAssert   func(loginID string, origin string, r *http.Request, loginOptions *auth.LoginOptions)
	SignInStartError    error
	SignInStartResponse *auth.WebAuthnTransactionResponse

	SignInFinishAssert   func(finishRequest *auth.WebAuthnFinishRequest, w http.ResponseWriter)
	SignInFinishError    error
	SignInFinishResponse *auth.AuthenticationInfo

	SignUpOrInStartAssert   func(loginID string, origin string)
	SignUpOrInStartError    error
	SignUpOrInStartResponse *auth.WebAuthnTransactionResponse

	UpdateUserDeviceStartAssert   func(loginID string, origin string, r *http.Request)
	UpdateUserDeviceStartError    error
	UpdateUserDeviceStartResponse *auth.WebAuthnTransactionResponse

	UpdateUserDeviceFinishAssert func(finishRequest *auth.WebAuthnFinishRequest)
	UpdateUserDeviceFinishError  error
}

func (m *MockWebAuthn) SignUpStart(loginID string, user *auth.User, origin string) (*auth.WebAuthnTransactionResponse, error) {
	if m.SignUpStartAssert != nil {
		m.SignUpStartAssert(loginID, user, origin)
	}
	return m.SignUpStartResponse, m.SignUpStartError
}

func (m *MockWebAuthn) SignUpFinish(finishRequest *auth.WebAuthnFinishRequest, w http.ResponseWriter) (*auth.AuthenticationInfo, error) {
	if m.SignUpFinishAssert != nil {
		m.SignUpFinishAssert(finishRequest, w)
	}
	return m.SignUpFinishResponse, m.SignUpFinishError
}

func (m *MockWebAuthn) SignInStart(loginID string, origin string, r *http.Request, loginOptions *auth.LoginOptions) (*auth.WebAuthnTransactionResponse, error) {
	if m.SignInStartAssert != nil {
		m.SignInStartAssert(loginID, origin, r, loginOptions)
	}
	return m.SignInStartResponse, m.SignInStartError
}

func (m *MockWebAuthn) SignInFinish(finishRequest *auth.WebAuthnFinishRequest, w http.ResponseWriter) (*auth.AuthenticationInfo, error) {
	if m.SignInFinishAssert != nil {
		m.SignInFinishAssert(finishRequest, w)
	}
	return m.SignInFinishResponse, m.SignInFinishError
}

func (m *MockWebAuthn) SignUpOrInStart(loginID string, origin string) (*auth.WebAuthnTransactionResponse, error) {
	if m.SignUpOrInStartAssert != nil {
		m.SignUpOrInStartAssert(loginID, origin)
	}
	return m.SignUpOrInStartResponse, m.SignUpOrInStartError
}

func (m *MockWebAuthn) UpdateUserDeviceStart(loginID string, origin string, r *http.Request) (*auth.WebAuthnTransactionResponse, error) {
	if m.UpdateUserDeviceStartAssert != nil {
		m.UpdateUserDeviceStartAssert(loginID, origin, r)
	}
	return m.UpdateUserDeviceStartResponse, m.UpdateUserDeviceStartError
}

func (m *MockWebAuthn) UpdateUserDeviceFinish(finishRequest *auth.WebAuthnFinishRequest) error {
	if m.UpdateUserDeviceFinishAssert != nil {
		m.UpdateUserDeviceFinishAssert(finishRequest)
	}
	return m.UpdateUserDeviceFinishError
}

// Mock Session

type MockSession struct {
	ValidateSessionAssert          func(r *http.Request, w http.ResponseWriter)
	ValidateSessionError           error
	ValidateSessionResponse        *auth.Token
	ValidateSessionResponseFailure bool

	ValidateSessionTokensAssert          func(sessionToken, refreshToken string)
	ValidateSessionTokensError           error
	ValidateSessionTokensResponse        *auth.Token
	ValidateSessionTokensResponseFailure bool

	RefreshSessionAssert          func(r *http.Request, w http.ResponseWriter)
	RefreshSessionError           error
	RefreshSessionResponse        *auth.Token
	RefreshSessionResponseFailure bool

	ExchangeAccessKeyAssert          func(accessKey string)
	ExchangeAccessKeyError           error
	ExchangeAccessKeyResponse        *auth.Token
	ExchangeAccessKeyResponseFailure bool

	ValidatePermissionsAssert   func(token *auth.Token, permissions []string)
	ValidatePermissionsResponse bool

	ValidateTenantPermissionsAssert   func(token *auth.Token, tenant string, permissions []string)
	ValidateTenantPermissionsResponse bool

	ValidateRolesAssert   func(token *auth.Token, roles []string)
	ValidateRolesResponse bool

	ValidateTenantRolesAssert   func(token *auth.Token, tenant string, roles []string)
	ValidateTenantRolesResponse bool

	LogoutAssert func(r *http.Request, w http.ResponseWriter)
	LogoutError  error

	LogoutAllAssert func(r *http.Request, w http.ResponseWriter)
	LogoutAllError  error

	MeAssert   func(r *http.Request)
	MeError    error
	MeResponse *auth.UserResponse
}

func (m MockSession) ValidateSession(r *http.Request, w http.ResponseWriter) (bool, *auth.Token, error) {
	if m.ValidateSessionAssert != nil {
		m.ValidateSessionAssert(r, w)
	}
	return !m.ValidateSessionResponseFailure, m.ValidateSessionResponse, m.ValidateSessionError
}

func (m *MockSession) ValidateSessionTokens(sessionToken, refreshToken string) (bool, *auth.Token, error) {
	if m.ValidateSessionTokensAssert != nil {
		m.ValidateSessionTokensAssert(sessionToken, refreshToken)
	}
	return !m.ValidateSessionTokensResponseFailure, m.ValidateSessionTokensResponse, m.ValidateSessionTokensError
}

func (m *MockSession) RefreshSession(r *http.Request, w http.ResponseWriter) (bool, *auth.Token, error) {
	if m.RefreshSessionAssert != nil {
		m.RefreshSessionAssert(r, w)
	}
	return !m.RefreshSessionResponseFailure, m.RefreshSessionResponse, m.RefreshSessionError
}

func (m *MockSession) ExchangeAccessKey(accessKey string) (bool, *auth.Token, error) {
	if m.ExchangeAccessKeyAssert != nil {
		m.ExchangeAccessKeyAssert(accessKey)
	}
	return !m.ExchangeAccessKeyResponseFailure, m.ExchangeAccessKeyResponse, m.ExchangeAccessKeyError
}

func (m *MockSession) ValidatePermissions(token *auth.Token, permissions []string) bool {
	if m.ValidatePermissionsAssert != nil {
		m.ValidatePermissionsAssert(token, permissions)
	}
	return m.ValidatePermissionsResponse
}

func (m *MockSession) ValidateTenantPermissions(token *auth.Token, tenant string, permissions []string) bool {
	if m.ValidateTenantPermissionsAssert != nil {
		m.ValidateTenantPermissionsAssert(token, tenant, permissions)
	}
	return m.ValidateTenantPermissionsResponse
}

func (m *MockSession) ValidateRoles(token *auth.Token, roles []string) bool {
	if m.ValidateRolesAssert != nil {
		m.ValidateRolesAssert(token, roles)
	}
	return m.ValidateRolesResponse
}

func (m *MockSession) ValidateTenantRoles(token *auth.Token, tenant string, roles []string) bool {
	if m.ValidateTenantRolesAssert != nil {
		m.ValidateTenantRolesAssert(token, tenant, roles)
	}
	return m.ValidateTenantRolesResponse
}

func (m *MockSession) Logout(r *http.Request, w http.ResponseWriter) error {
	if m.LogoutAssert != nil {
		m.LogoutAssert(r, w)
	}
	return m.LogoutError
}

func (m *MockSession) LogoutAll(r *http.Request, w http.ResponseWriter) error {
	if m.LogoutAllAssert != nil {
		m.LogoutAllAssert(r, w)
	}
	return m.LogoutAllError
}

func (m *MockSession) Me(r *http.Request) (*auth.UserResponse, error) {
	if m.MeAssert != nil {
		m.MeAssert(r)
	}
	return m.MeResponse, m.MeError
}
