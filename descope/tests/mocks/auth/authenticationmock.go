package mocksauth

import (
	"context"
	"net/http"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/sdk"
)

type MockAuthentication struct {
	*MockMagicLink
	*MockEnchantedLink
	*MockOTP
	*MockTOTP
	*MockNOTP
	*MockPassword
	*MockOAuth
	*MockSAML
	*MockSSO
	*MockWebAuthn
	MockSession
}

func (m *MockAuthentication) MagicLink() sdk.MagicLink {
	return m.MockMagicLink
}

func (m *MockAuthentication) EnchantedLink() sdk.EnchantedLink {
	return m.MockEnchantedLink
}

func (m *MockAuthentication) OTP() sdk.OTP {
	return m.MockOTP
}

func (m *MockAuthentication) TOTP() sdk.TOTP {
	return m.MockTOTP
}

func (m *MockAuthentication) NOTP() sdk.NOTP {
	return m.MockNOTP
}

func (m *MockAuthentication) Password() sdk.Password {
	return m.MockPassword
}

func (m *MockAuthentication) OAuth() sdk.OAuth {
	return m.MockOAuth
}

func (m *MockAuthentication) SAML() sdk.SAML {
	return m.MockSAML
}

func (m *MockAuthentication) SSO() sdk.SSOServiceProvider {
	return m.MockSSO
}

func (m *MockAuthentication) WebAuthn() sdk.WebAuthn {
	return m.MockWebAuthn
}

// Mock MagicLink

type MockMagicLink struct {
	SignInAssert func(method descope.DeliveryMethod, loginID, URI string, r *http.Request, loginOptions *descope.LoginOptions)
	SignInError  error

	SignUpAssert func(method descope.DeliveryMethod, loginID, URI string, user *descope.User, signUpOptions *descope.SignUpOptions)
	SignUpError  error

	SignUpOrInAssert func(method descope.DeliveryMethod, loginID string, URI string, signUpOptions *descope.SignUpOptions)
	SignUpOrInError  error

	VerifyAssert   func(token string, w http.ResponseWriter) (*descope.AuthenticationInfo, error)
	VerifyError    error
	VerifyResponse *descope.AuthenticationInfo

	UpdateUserEmailAssert func(loginID, email, URI string, updateOptions *descope.UpdateOptions, r *http.Request)
	UpdateUserEmailError  error

	UpdateUserPhoneAssert func(method descope.DeliveryMethod, loginID, phone, URI string, updateOptions *descope.UpdateOptions, r *http.Request)
	UpdateUserPhoneError  error
}

func (m *MockMagicLink) SignIn(_ context.Context, method descope.DeliveryMethod, loginID, URI string, r *http.Request, loginOptions *descope.LoginOptions) (string, error) {
	if m.SignInAssert != nil {
		m.SignInAssert(method, loginID, URI, r, loginOptions)
	}
	return "", m.SignInError
}

func (m *MockMagicLink) SignUp(_ context.Context, method descope.DeliveryMethod, loginID, URI string, user *descope.User, signUpOptions *descope.SignUpOptions) (string, error) {
	if m.SignUpAssert != nil {
		m.SignUpAssert(method, loginID, URI, user, signUpOptions)
	}
	return "", m.SignUpError
}

func (m *MockMagicLink) SignUpOrIn(_ context.Context, method descope.DeliveryMethod, loginID string, URI string, signUpOptions *descope.SignUpOptions) (string, error) {
	if m.SignUpOrInAssert != nil {
		m.SignUpOrInAssert(method, loginID, URI, signUpOptions)
	}
	return "", m.SignUpOrInError
}

func (m *MockMagicLink) Verify(_ context.Context, token string, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	if m.VerifyAssert != nil {
		m.VerifyAssert(token, w)
	}
	return m.VerifyResponse, m.VerifyError
}

func (m *MockMagicLink) UpdateUserEmail(_ context.Context, loginID, email, URI string, updateOptions *descope.UpdateOptions, r *http.Request) (string, error) {
	if m.UpdateUserEmailAssert != nil {
		m.UpdateUserEmailAssert(loginID, email, URI, updateOptions, r)
	}
	return "", m.UpdateUserEmailError
}

func (m *MockMagicLink) UpdateUserPhone(_ context.Context, method descope.DeliveryMethod, loginID, phone, URI string, updateOptions *descope.UpdateOptions, r *http.Request) (string, error) {
	if m.UpdateUserPhoneAssert != nil {
		m.UpdateUserPhoneAssert(method, loginID, phone, URI, updateOptions, r)
	}
	return "", m.UpdateUserPhoneError
}

// Mock EnchantedLink

type MockEnchantedLink struct {
	SignInAssert   func(loginID, URI string, r *http.Request, loginOptions *descope.LoginOptions)
	SignInError    error
	SignInResponse *descope.EnchantedLinkResponse

	SignUpAssert   func(loginID, URI string, user *descope.User, signUpOptions *descope.SignUpOptions)
	SignUpError    error
	SignUpResponse *descope.EnchantedLinkResponse

	SignUpOrInAssert   func(loginID string, URI string, signUpOptions *descope.SignUpOptions)
	SignUpOrInError    error
	SignUpOrInResponse *descope.EnchantedLinkResponse

	GetSessionAssert   func(pendingRef string, w http.ResponseWriter)
	GetSessionResponse *descope.AuthenticationInfo
	GetSessionError    error

	VerifyAssert func(token string) (*descope.AuthenticationInfo, error)
	VerifyError  error

	UpdateUserEmailAssert   func(loginID, email, URI string, updateOptions *descope.UpdateOptions, r *http.Request)
	UpdateUserEmailError    error
	UpdateUserEmailResponse *descope.EnchantedLinkResponse
}

func (m *MockEnchantedLink) SignIn(_ context.Context, loginID, URI string, r *http.Request, loginOptions *descope.LoginOptions) (*descope.EnchantedLinkResponse, error) {
	if m.SignInAssert != nil {
		m.SignInAssert(loginID, URI, r, loginOptions)
	}
	return m.SignInResponse, m.SignInError
}

func (m *MockEnchantedLink) SignUp(_ context.Context, loginID, URI string, user *descope.User, signUpOptions *descope.SignUpOptions) (*descope.EnchantedLinkResponse, error) {
	if m.SignUpAssert != nil {
		m.SignUpAssert(loginID, URI, user, signUpOptions)
	}
	return m.SignUpResponse, m.SignUpError
}

func (m *MockEnchantedLink) SignUpOrIn(_ context.Context, loginID string, URI string, signUpOptions *descope.SignUpOptions) (*descope.EnchantedLinkResponse, error) {
	if m.SignUpOrInAssert != nil {
		m.SignUpOrInAssert(loginID, URI, signUpOptions)
	}
	return m.SignUpOrInResponse, m.SignUpOrInError
}

func (m *MockEnchantedLink) GetSession(_ context.Context, pendingRef string, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	if m.GetSessionAssert != nil {
		m.GetSessionAssert(pendingRef, w)
	}
	return m.GetSessionResponse, m.GetSessionError
}

func (m *MockEnchantedLink) Verify(_ context.Context, token string) error {
	if m.VerifyAssert != nil {
		m.VerifyAssert(token)
	}
	return m.VerifyError
}

func (m *MockEnchantedLink) UpdateUserEmail(_ context.Context, loginID, email, URI string, updateOptions *descope.UpdateOptions, r *http.Request) (*descope.EnchantedLinkResponse, error) {
	if m.UpdateUserEmailAssert != nil {
		m.UpdateUserEmailAssert(loginID, email, URI, updateOptions, r)
	}
	return m.UpdateUserEmailResponse, m.UpdateUserEmailError
}

// Mock OTP

type MockOTP struct {
	SignInAssert func(method descope.DeliveryMethod, loginID string, r *http.Request, loginOptions *descope.LoginOptions)
	SignInError  error

	SignUpAssert func(method descope.DeliveryMethod, loginID string, user *descope.User, signUpOptions *descope.SignUpOptions)
	SignUpError  error

	SignUpOrInAssert func(method descope.DeliveryMethod, loginID string, signUpOptions *descope.SignUpOptions)
	SignUpOrInError  error

	VerifyCodeAssert   func(method descope.DeliveryMethod, loginID string, code string, w http.ResponseWriter)
	VerifyCodeError    error
	VerifyCodeResponse *descope.AuthenticationInfo

	UpdateUserEmailAssert func(loginID, email string, updateOptions *descope.UpdateOptions, r *http.Request)
	UpdateUserEmailError  error

	UpdateUserPhoneAssert func(method descope.DeliveryMethod, loginID, phone string, updateOptions *descope.UpdateOptions, r *http.Request)
	UpdateUserPhoneError  error
}

func (m *MockOTP) SignIn(_ context.Context, method descope.DeliveryMethod, loginID string, r *http.Request, loginOptions *descope.LoginOptions) (string, error) {
	if m.SignInAssert != nil {
		m.SignInAssert(method, loginID, r, loginOptions)
	}
	return "", m.SignInError
}

func (m *MockOTP) SignUp(_ context.Context, method descope.DeliveryMethod, loginID string, user *descope.User, signUpOptions *descope.SignUpOptions) (string, error) {
	if m.SignUpAssert != nil {
		m.SignUpAssert(method, loginID, user, signUpOptions)
	}
	return "", m.SignUpError
}

func (m *MockOTP) SignUpOrIn(_ context.Context, method descope.DeliveryMethod, loginID string, signUpOptions *descope.SignUpOptions) (string, error) {
	if m.SignUpOrInAssert != nil {
		m.SignUpOrInAssert(method, loginID, signUpOptions)
	}
	return "", m.SignUpOrInError
}

func (m *MockOTP) VerifyCode(_ context.Context, method descope.DeliveryMethod, loginID string, code string, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	if m.VerifyCodeAssert != nil {
		m.VerifyCodeAssert(method, loginID, code, w)
	}
	return m.VerifyCodeResponse, m.VerifyCodeError
}

func (m *MockOTP) UpdateUserEmail(_ context.Context, loginID, email string, updateOptions *descope.UpdateOptions, r *http.Request) (string, error) {
	if m.UpdateUserEmailAssert != nil {
		m.UpdateUserEmailAssert(loginID, email, updateOptions, r)
	}
	return "", m.UpdateUserEmailError
}

func (m *MockOTP) UpdateUserPhone(_ context.Context, method descope.DeliveryMethod, loginID, phone string, updateOptions *descope.UpdateOptions, r *http.Request) (string, error) {
	if m.UpdateUserPhoneAssert != nil {
		m.UpdateUserPhoneAssert(method, loginID, phone, updateOptions, r)
	}
	return "", m.UpdateUserPhoneError
}

// Mock TOTP

type MockTOTP struct {
	SignUpAssert   func(loginID string, user *descope.User)
	SignUpError    error
	SignUpResponse *descope.TOTPResponse

	SignInCodeAssert   func(loginID string, code string, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter)
	SignInCodeError    error
	SignInCodeResponse *descope.AuthenticationInfo

	UpdateUserAssert   func(loginID string, r *http.Request)
	UpdateUserError    error
	UpdateUserResponse *descope.TOTPResponse
}

func (m *MockTOTP) SignUp(_ context.Context, loginID string, user *descope.User) (*descope.TOTPResponse, error) {
	if m.SignUpAssert != nil {
		m.SignUpAssert(loginID, user)
	}
	return m.SignUpResponse, m.SignUpError
}

func (m *MockTOTP) SignInCode(_ context.Context, loginID string, code string, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	if m.SignInCodeAssert != nil {
		m.SignInCodeAssert(loginID, code, r, loginOptions, w)
	}
	return m.SignInCodeResponse, m.SignInCodeError
}

func (m *MockTOTP) UpdateUser(_ context.Context, loginID string, r *http.Request) (*descope.TOTPResponse, error) {
	if m.UpdateUserAssert != nil {
		m.UpdateUserAssert(loginID, r)
	}
	return m.UpdateUserResponse, m.UpdateUserError
}

// Mock NOTP

type MockNOTP struct {
	SignInAssert   func(loginID string, r *http.Request, loginOptions *descope.LoginOptions)
	SignInError    error
	SignInResponse *descope.NOTPResponse

	SignUpAssert   func(loginID string, user *descope.User, signUpOptions *descope.SignUpOptions)
	SignUpError    error
	SignUpResponse *descope.NOTPResponse

	SignUpOrInAssert   func(loginID string, signUpOptions *descope.SignUpOptions)
	SignUpOrInError    error
	SignUpOrInResponse *descope.NOTPResponse

	GetSessionAssert   func(pendingRef string, w http.ResponseWriter)
	GetSessionResponse *descope.AuthenticationInfo
	GetSessionError    error
}

func (m *MockNOTP) SignIn(_ context.Context, loginID string, r *http.Request, loginOptions *descope.LoginOptions) (*descope.NOTPResponse, error) {
	if m.SignInAssert != nil {
		m.SignInAssert(loginID, r, loginOptions)
	}
	return m.SignInResponse, m.SignInError
}

func (m *MockNOTP) SignUp(_ context.Context, loginID string, user *descope.User, signUpOptions *descope.SignUpOptions) (*descope.NOTPResponse, error) {
	if m.SignUpAssert != nil {
		m.SignUpAssert(loginID, user, signUpOptions)
	}
	return m.SignUpResponse, m.SignUpError
}

func (m *MockNOTP) SignUpOrIn(_ context.Context, loginID string, signUpOptions *descope.SignUpOptions) (*descope.NOTPResponse, error) {
	if m.SignUpOrInAssert != nil {
		m.SignUpOrInAssert(loginID, signUpOptions)
	}
	return m.SignUpOrInResponse, m.SignUpOrInError
}

func (m *MockNOTP) GetSession(_ context.Context, pendingRef string, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	if m.GetSessionAssert != nil {
		m.GetSessionAssert(pendingRef, w)
	}
	return m.GetSessionResponse, m.GetSessionError
}

// Mock Password

type MockPassword struct {
	SignUpAssert   func(loginID string, user *descope.User, password string, w http.ResponseWriter)
	SignUpError    error
	SignUpResponse *descope.AuthenticationInfo

	SignInAssert   func(loginID string, password string, w http.ResponseWriter)
	SignInError    error
	SignInResponse *descope.AuthenticationInfo

	ResetAssert func(loginID, redirectURL string, templateOptions map[string]string)
	ResetError  error

	UpdateAssert func(loginID, newPassword string, r *http.Request)
	UpdateError  error

	ReplaceAssert   func(loginID, oldPassword, newPassword string, w http.ResponseWriter)
	ReplaceError    error
	ReplaceResponse *descope.AuthenticationInfo

	PolicyResponse *descope.PasswordPolicy
	PolicyError    error
}

func (m *MockPassword) SignUp(_ context.Context, loginID string, user *descope.User, password string, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	if m.SignUpAssert != nil {
		m.SignUpAssert(loginID, user, password, w)
	}
	return m.SignUpResponse, m.SignUpError
}

func (m *MockPassword) SignIn(_ context.Context, loginID string, password string, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	if m.SignInAssert != nil {
		m.SignInAssert(loginID, password, w)
	}
	return m.SignInResponse, m.SignInError
}

func (m *MockPassword) SendPasswordReset(_ context.Context, loginID, redirectURL string, templateOptions map[string]string) error {
	if m.ResetAssert != nil {
		m.ResetAssert(loginID, redirectURL, templateOptions)
	}
	return m.ResetError
}

func (m *MockPassword) UpdateUserPassword(_ context.Context, loginID, newPassword string, r *http.Request) error {
	if m.UpdateAssert != nil {
		m.UpdateAssert(loginID, newPassword, r)
	}
	return m.ResetError
}

func (m *MockPassword) ReplaceUserPassword(_ context.Context, loginID, oldPassword, newPassword string, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	if m.ReplaceAssert != nil {
		m.ReplaceAssert(loginID, oldPassword, newPassword, w)
	}
	return m.ReplaceResponse, m.ReplaceError
}

func (m *MockPassword) GetPasswordPolicy(_ context.Context) (*descope.PasswordPolicy, error) {
	return m.PolicyResponse, m.PolicyError
}

// Mock OAuth

type MockOAuth struct {
	StartAssert   func(provider descope.OAuthProvider, redirectURL string, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter)
	StartError    error
	StartResponse string

	SignUpOrInAssert   func(provider descope.OAuthProvider, redirectURL string, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter)
	SignUpOrInError    error
	SignUpOrInResponse string

	SignInAssert   func(provider descope.OAuthProvider, redirectURL string, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter)
	SignInError    error
	SignInResponse string

	SignUpAssert   func(provider descope.OAuthProvider, redirectURL string, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter)
	SignUpError    error
	SignUpResponse string

	UpdateUserAssert   func(provider descope.OAuthProvider, redirectURL string, allowAllMerge bool, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter)
	UpdateUserError    error
	UpdateUserResponse string

	ExchangeTokenAssert   func(code string, w http.ResponseWriter)
	ExchangeTokenError    error
	ExchangeTokenResponse *descope.AuthenticationInfo
}

func (m *MockOAuth) Start(_ context.Context, provider descope.OAuthProvider, redirectURL string, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter) (string, error) {
	if m.StartAssert != nil {
		m.StartAssert(provider, redirectURL, r, loginOptions, w)
	}
	return m.StartResponse, m.StartError
}

func (m *MockOAuth) SignUpOrIn(_ context.Context, provider descope.OAuthProvider, redirectURL string, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter) (string, error) {
	if m.SignUpOrInAssert != nil {
		m.SignUpOrInAssert(provider, redirectURL, r, loginOptions, w)
	}
	return m.SignUpOrInResponse, m.SignUpOrInError
}

func (m *MockOAuth) SignIn(_ context.Context, provider descope.OAuthProvider, redirectURL string, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter) (string, error) {
	if m.SignInAssert != nil {
		m.SignInAssert(provider, redirectURL, r, loginOptions, w)
	}
	return m.SignInResponse, m.SignInError
}

func (m *MockOAuth) SignUp(_ context.Context, provider descope.OAuthProvider, redirectURL string, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter) (string, error) {
	if m.SignUpAssert != nil {
		m.SignUpAssert(provider, redirectURL, r, loginOptions, w)
	}
	return m.SignUpResponse, m.SignUpError
}

func (m *MockOAuth) UpdateUser(_ context.Context, provider descope.OAuthProvider, redirectURL string, allowAllMerge bool, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter) (string, error) {
	if m.UpdateUserAssert != nil {
		m.UpdateUserAssert(provider, redirectURL, allowAllMerge, r, loginOptions, w)
	}
	return m.UpdateUserResponse, m.UpdateUserError
}

func (m *MockOAuth) ExchangeToken(_ context.Context, code string, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	if m.ExchangeTokenAssert != nil {
		m.ExchangeTokenAssert(code, w)
	}
	return m.ExchangeTokenResponse, m.ExchangeTokenError
}

// Mock SAML

type MockSAML struct {
	StartAssert   func(tenant string, redirectURL string, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter)
	StartError    error
	StartResponse string

	ExchangeTokenAssert   func(code string, w http.ResponseWriter)
	ExchangeTokenError    error
	ExchangeTokenResponse *descope.AuthenticationInfo
}

func (m *MockSAML) Start(_ context.Context, tenant string, redirectURL string, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter) (string, error) {
	if m.StartAssert != nil {
		m.StartAssert(tenant, redirectURL, r, loginOptions, w)
	}
	return m.StartResponse, m.StartError
}

func (m *MockSAML) ExchangeToken(_ context.Context, code string, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	if m.ExchangeTokenAssert != nil {
		m.ExchangeTokenAssert(code, w)
	}
	return m.ExchangeTokenResponse, m.ExchangeTokenError
}

// Mock SSO

type MockSSO struct {
	StartAssert   func(tenant string, redirectURL string, prompt string, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter)
	StartError    error
	StartResponse string

	ExchangeTokenAssert   func(code string, w http.ResponseWriter)
	ExchangeTokenError    error
	ExchangeTokenResponse *descope.AuthenticationInfo
}

func (m *MockSSO) Start(_ context.Context, tenant string, redirectURL string, prompt string, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter) (string, error) {
	if m.StartAssert != nil {
		m.StartAssert(tenant, redirectURL, prompt, r, loginOptions, w)
	}
	return m.StartResponse, m.StartError
}

func (m *MockSSO) ExchangeToken(_ context.Context, code string, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	if m.ExchangeTokenAssert != nil {
		m.ExchangeTokenAssert(code, w)
	}
	return m.ExchangeTokenResponse, m.ExchangeTokenError
}

// Mock WebAuthn

type MockWebAuthn struct {
	SignUpStartAssert   func(loginID string, user *descope.User, origin string)
	SignUpStartError    error
	SignUpStartResponse *descope.WebAuthnTransactionResponse

	SignUpFinishAssert   func(finishRequest *descope.WebAuthnFinishRequest, w http.ResponseWriter)
	SignUpFinishError    error
	SignUpFinishResponse *descope.AuthenticationInfo

	SignInStartAssert   func(loginID string, origin string, r *http.Request, loginOptions *descope.LoginOptions)
	SignInStartError    error
	SignInStartResponse *descope.WebAuthnTransactionResponse

	SignInFinishAssert   func(finishRequest *descope.WebAuthnFinishRequest, w http.ResponseWriter)
	SignInFinishError    error
	SignInFinishResponse *descope.AuthenticationInfo

	SignUpOrInStartAssert   func(loginID string, origin string)
	SignUpOrInStartError    error
	SignUpOrInStartResponse *descope.WebAuthnTransactionResponse

	UpdateUserDeviceStartAssert   func(loginID string, origin string, r *http.Request)
	UpdateUserDeviceStartError    error
	UpdateUserDeviceStartResponse *descope.WebAuthnTransactionResponse

	UpdateUserDeviceFinishAssert func(finishRequest *descope.WebAuthnFinishRequest)
	UpdateUserDeviceFinishError  error
}

func (m *MockWebAuthn) SignUpStart(_ context.Context, loginID string, user *descope.User, origin string) (*descope.WebAuthnTransactionResponse, error) {
	if m.SignUpStartAssert != nil {
		m.SignUpStartAssert(loginID, user, origin)
	}
	return m.SignUpStartResponse, m.SignUpStartError
}

func (m *MockWebAuthn) SignUpFinish(_ context.Context, finishRequest *descope.WebAuthnFinishRequest, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	if m.SignUpFinishAssert != nil {
		m.SignUpFinishAssert(finishRequest, w)
	}
	return m.SignUpFinishResponse, m.SignUpFinishError
}

func (m *MockWebAuthn) SignInStart(_ context.Context, loginID string, origin string, r *http.Request, loginOptions *descope.LoginOptions) (*descope.WebAuthnTransactionResponse, error) {
	if m.SignInStartAssert != nil {
		m.SignInStartAssert(loginID, origin, r, loginOptions)
	}
	return m.SignInStartResponse, m.SignInStartError
}

func (m *MockWebAuthn) SignInFinish(_ context.Context, finishRequest *descope.WebAuthnFinishRequest, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	if m.SignInFinishAssert != nil {
		m.SignInFinishAssert(finishRequest, w)
	}
	return m.SignInFinishResponse, m.SignInFinishError
}

func (m *MockWebAuthn) SignUpOrInStart(_ context.Context, loginID string, origin string) (*descope.WebAuthnTransactionResponse, error) {
	if m.SignUpOrInStartAssert != nil {
		m.SignUpOrInStartAssert(loginID, origin)
	}
	return m.SignUpOrInStartResponse, m.SignUpOrInStartError
}

func (m *MockWebAuthn) UpdateUserDeviceStart(_ context.Context, loginID string, origin string, r *http.Request) (*descope.WebAuthnTransactionResponse, error) {
	if m.UpdateUserDeviceStartAssert != nil {
		m.UpdateUserDeviceStartAssert(loginID, origin, r)
	}
	return m.UpdateUserDeviceStartResponse, m.UpdateUserDeviceStartError
}

func (m *MockWebAuthn) UpdateUserDeviceFinish(_ context.Context, finishRequest *descope.WebAuthnFinishRequest) error {
	if m.UpdateUserDeviceFinishAssert != nil {
		m.UpdateUserDeviceFinishAssert(finishRequest)
	}
	return m.UpdateUserDeviceFinishError
}

// Mock Session

type MockSession struct {
	ValidateAndRefreshSessionAssert          func(r *http.Request, w http.ResponseWriter)
	ValidateAndRefreshSessionError           error
	ValidateAndRefreshSessionResponse        *descope.Token
	ValidateAndRefreshSessionResponseFailure bool

	ValidateAndRefreshSessionTokensAssert          func(sessionToken, refreshToken string)
	ValidateAndRefreshSessionTokensError           error
	ValidateAndRefreshSessionTokensResponse        *descope.Token
	ValidateAndRefreshSessionTokensResponseFailure bool

	ValidateSessionAssert          func(r *http.Request)
	ValidateSessionError           error
	ValidateSessionResponse        *descope.Token
	ValidateSessionResponseFailure bool

	ValidateSessionTokenAssert          func(sessionToken string)
	ValidateSessionTokenError           error
	ValidateSessionTokenResponse        *descope.Token
	ValidateSessionTokenResponseFailure bool

	RefreshSessionAssert          func(r *http.Request, w http.ResponseWriter)
	RefreshSessionTokenAssert     func(refreshToken string)
	RefreshSessionError           error
	RefreshSessionResponse        *descope.Token
	RefreshSessionResponseFailure bool
	RefreshSessionResponseArray   []*descope.Token
	RefreshSessionResponseCounter int

	ExchangeAccessKeyAssert          func(accessKey string, loginOptions *descope.AccessKeyLoginOptions)
	ExchangeAccessKeyError           error
	ExchangeAccessKeyResponse        *descope.Token
	ExchangeAccessKeyResponseFailure bool

	ValidatePermissionsAssert   func(token *descope.Token, permissions []string)
	ValidatePermissionsResponse bool

	GetMatchedPermissionsAssert   func(token *descope.Token, permissions []string)
	GetMatchedPermissionsResponse []string

	ValidateTenantPermissionsAssert   func(token *descope.Token, tenant string, permissions []string)
	ValidateTenantPermissionsResponse bool

	GetMatchedTenantPermissionsAssert   func(token *descope.Token, tenant string, permissions []string)
	GetMatchedTenantPermissionsResponse []string

	ValidateRolesAssert   func(token *descope.Token, roles []string)
	ValidateRolesResponse bool

	GetMatchedRolesAssert   func(token *descope.Token, roles []string)
	GetMatchedRolesResponse []string

	ValidateTenantRolesAssert   func(token *descope.Token, tenant string, roles []string)
	ValidateTenantRolesResponse bool

	GetMatchedTenantRolesAssert   func(token *descope.Token, tenant string, roles []string)
	GetMatchedTenantRolesResponse []string

	SelectTenantWithRequestAssert   func(tenantID string, r *http.Request, w http.ResponseWriter)
	SelectTenantWithRequestResponse *descope.AuthenticationInfo
	SelectTenantWithRequestError    error

	SelectTenantWithTokenAssert   func(tenantID string, refreshToken string)
	SelectTenantWithTokenResponse *descope.AuthenticationInfo
	SelectTenantWithTokenError    error

	LogoutAssert func(r *http.Request, w http.ResponseWriter)
	LogoutError  error

	LogoutAllAssert func(r *http.Request, w http.ResponseWriter)
	LogoutAllError  error

	MeAssert   func(r *http.Request)
	MeError    error
	MeResponse *descope.UserResponse

	HistoryAssert   func(r *http.Request)
	HistoryError    error
	HistoryResponse []*descope.UserHistoryResponse
}

func (m *MockSession) ValidateSessionWithRequest(r *http.Request) (bool, *descope.Token, error) {
	if m.ValidateSessionAssert != nil {
		m.ValidateSessionAssert(r)
	}
	return !m.ValidateSessionResponseFailure, m.ValidateSessionResponse, m.ValidateSessionError
}

func (m *MockSession) ValidateSessionWithToken(_ context.Context, sessionToken string) (bool, *descope.Token, error) {
	if m.ValidateSessionTokenAssert != nil {
		m.ValidateSessionTokenAssert(sessionToken)
	}
	return !m.ValidateSessionTokenResponseFailure, m.ValidateSessionTokenResponse, m.ValidateSessionTokenError
}

func (m *MockSession) RefreshSessionWithRequest(r *http.Request, w http.ResponseWriter) (bool, *descope.Token, error) {
	if m.RefreshSessionResponseFailure {
		return false, nil, m.RefreshSessionError
	}

	if m.RefreshSessionAssert != nil {
		m.RefreshSessionAssert(r, w)
	}

	if len(m.RefreshSessionResponseArray) > 0 && m.RefreshSessionResponseCounter < len(m.RefreshSessionResponseArray) {
		currentRefreshResponse := m.RefreshSessionResponseArray[m.RefreshSessionResponseCounter]
		m.RefreshSessionResponseCounter++
		return true, currentRefreshResponse, nil
	}

	if m.RefreshSessionResponse != nil {
		return true, m.RefreshSessionResponse, nil
	}

	return !m.RefreshSessionResponseFailure, m.RefreshSessionResponse, m.RefreshSessionError
}

func (m *MockSession) RefreshSessionWithToken(_ context.Context, refreshToken string) (bool, *descope.Token, error) {
	if m.RefreshSessionResponseFailure {
		return false, nil, m.RefreshSessionError
	}

	if m.RefreshSessionTokenAssert != nil {
		m.RefreshSessionTokenAssert(refreshToken)
	}

	if len(m.RefreshSessionResponseArray) > 0 && m.RefreshSessionResponseCounter < len(m.RefreshSessionResponseArray) {
		currentRefreshResponse := m.RefreshSessionResponseArray[m.RefreshSessionResponseCounter]
		m.RefreshSessionResponseCounter++
		return true, currentRefreshResponse, nil
	}

	if m.RefreshSessionResponse != nil {
		return true, m.RefreshSessionResponse, nil
	}

	return !m.RefreshSessionResponseFailure, m.RefreshSessionResponse, m.RefreshSessionError
}

func (m *MockSession) ValidateAndRefreshSessionWithRequest(r *http.Request, w http.ResponseWriter) (bool, *descope.Token, error) {
	if m.ValidateAndRefreshSessionAssert != nil {
		m.ValidateAndRefreshSessionAssert(r, w)
	}
	return !m.ValidateAndRefreshSessionResponseFailure, m.ValidateAndRefreshSessionResponse, m.ValidateAndRefreshSessionError
}
func (m *MockSession) ValidateAndRefreshSessionWithTokens(_ context.Context, sessionToken, refreshToken string) (bool, *descope.Token, error) {
	if m.ValidateAndRefreshSessionTokensAssert != nil {
		m.ValidateAndRefreshSessionTokensAssert(sessionToken, refreshToken)
	}
	return !m.ValidateAndRefreshSessionTokensResponseFailure, m.ValidateAndRefreshSessionTokensResponse, m.ValidateAndRefreshSessionTokensError
}

func (m *MockSession) ExchangeAccessKey(_ context.Context, accessKey string, loginOptions *descope.AccessKeyLoginOptions) (bool, *descope.Token, error) {
	if m.ExchangeAccessKeyAssert != nil {
		m.ExchangeAccessKeyAssert(accessKey, loginOptions)
	}
	return !m.ExchangeAccessKeyResponseFailure, m.ExchangeAccessKeyResponse, m.ExchangeAccessKeyError
}

func (m *MockSession) ValidatePermissions(_ context.Context, token *descope.Token, permissions []string) bool {
	if m.ValidatePermissionsAssert != nil {
		m.ValidatePermissionsAssert(token, permissions)
	}
	return m.ValidatePermissionsResponse
}

func (m *MockSession) GetMatchedPermissions(_ context.Context, token *descope.Token, permissions []string) []string {
	if m.GetMatchedPermissionsAssert != nil {
		m.GetMatchedPermissionsAssert(token, permissions)
	}

	return m.GetMatchedPermissionsResponse
}

func (m *MockSession) ValidateTenantPermissions(_ context.Context, token *descope.Token, tenant string, permissions []string) bool {
	if m.ValidateTenantPermissionsAssert != nil {
		m.ValidateTenantPermissionsAssert(token, tenant, permissions)
	}
	return m.ValidateTenantPermissionsResponse
}

func (m *MockSession) GetMatchedTenantPermissions(_ context.Context, token *descope.Token, tenant string, permissions []string) []string {
	if m.GetMatchedTenantPermissionsAssert != nil {
		m.GetMatchedTenantPermissionsAssert(token, tenant, permissions)
	}

	return m.GetMatchedTenantPermissionsResponse
}

func (m *MockSession) ValidateRoles(_ context.Context, token *descope.Token, roles []string) bool {
	if m.ValidateRolesAssert != nil {
		m.ValidateRolesAssert(token, roles)
	}
	return m.ValidateRolesResponse
}

func (m *MockSession) GetMatchedRoles(_ context.Context, token *descope.Token, roles []string) []string {
	if m.GetMatchedRolesAssert != nil {
		m.GetMatchedRolesAssert(token, roles)
	}

	return m.GetMatchedRolesResponse
}

func (m *MockSession) ValidateTenantRoles(_ context.Context, token *descope.Token, tenant string, roles []string) bool {
	if m.ValidateTenantRolesAssert != nil {
		m.ValidateTenantRolesAssert(token, tenant, roles)
	}
	return m.ValidateTenantRolesResponse
}

func (m *MockSession) GetMatchedTenantRoles(_ context.Context, token *descope.Token, tenant string, roles []string) []string {
	if m.GetMatchedTenantRolesAssert != nil {
		m.GetMatchedTenantRolesAssert(token, tenant, roles)
	}

	return m.GetMatchedTenantRolesResponse
}

func (m *MockSession) SelectTenantWithRequest(_ context.Context, tenantID string, request *http.Request, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	if m.SelectTenantWithRequestAssert != nil {
		m.SelectTenantWithRequestAssert(tenantID, request, w)
	}
	return m.SelectTenantWithRequestResponse, m.SelectTenantWithRequestError
}

func (m *MockSession) SelectTenantWithToken(_ context.Context, tenantID string, refreshToken string) (*descope.AuthenticationInfo, error) {
	if m.SelectTenantWithTokenAssert != nil {
		m.SelectTenantWithTokenAssert(tenantID, refreshToken)
	}
	return m.SelectTenantWithTokenResponse, m.SelectTenantWithTokenError
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

func (m *MockSession) Me(r *http.Request) (*descope.UserResponse, error) {
	if m.MeAssert != nil {
		m.MeAssert(r)
	}
	return m.MeResponse, m.MeError
}

func (m *MockSession) History(r *http.Request) ([]*descope.UserHistoryResponse, error) {
	if m.HistoryAssert != nil {
		m.HistoryAssert(r)
	}
	return m.HistoryResponse, m.HistoryError
}
