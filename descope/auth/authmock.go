package auth

import (
	"net/http"
)

type MockDescopeAuthentication struct {
	SignInOTPResponseError                      error
	SignUpOTPResponseError                      error
	SignUpOrInOTPResponseError                  error
	VerifyCodeResponseInfo                      *AuthenticationInfo
	AssertUpdateUserEmailOTP                    func(identifier string, email string, request *http.Request)
	UpdateUserEmailOTPResponseError             error
	AssertUpdateUserPhoneOTP                    func(method DeliveryMethod, identifier string, email string, request *http.Request)
	UpdateUserPhoneOTPResponseError             error
	VerifyCodeResponseError                     error
	ValidateSessionResponseNotOK                bool
	ValidateSessionResponseInfo                 *Token
	ValidateSessionResponseError                error
	GetMagicLinkSessionResponseInfo             *AuthenticationInfo
	GetMagicLinkSessionResponseError            error
	LogoutResponseError                         error
	AssertSignInOTP                             func(method DeliveryMethod, identifier string)
	AssertSignUpOTP                             func(method DeliveryMethod, identifier string, user *User)
	AssertSignUpOrInOTP                         func(method DeliveryMethod, identifier string)
	AssertVerifyCode                            func(method DeliveryMethod, identifier string, code string)
	AssertSignUpTOTP                            func(identifier string, user *User)
	SignUpTOTPResponse                          *TOTPResponse
	SignUpTOTPResponseError                     error
	AssertUpdateTOTP                            func(identifier string)
	UpdateTOTPResponse                          *TOTPResponse
	UpdateTOTPResponseError                     error
	AssertVerifyTOTPCode                        func(identifier string, code string)
	VerifyTOTPCodeResponseInfo                  *AuthenticationInfo
	VerifyTOTPCodeResponseError                 error
	AssertOAuthStart                            func(provider OAuthProvider, landingURL string)
	AssertOAuthResponseURL                      string
	OAuthStartResponseError                     error
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
	AssertExchangeToken                         func(code string, options ...Option)
	ExchangeTokenResponseInfo                   *AuthenticationInfo
	ExchangeTokenResponseError                  error
	AssertSAMLStart                             func(tenant string, landingURL string, options ...Option)
	AssertSAMLStartResponseURL                  string
	SAMLStartResponseError                      error
	AssertVerifyMagicLink                       func(token string)
	SignUpWebAuthnStartResponseError            error
	SignUpWebAuthnStartResponseTransaction      *WebAuthnTransactionResponse
	SignUpWebAuthnFinishResponseError           error
	SignUpWebAuthnFinishResponseInfo            *AuthenticationInfo
	SignInWebAuthnStartResponseError            error
	SignInWebAuthnStartResponseTransaction      *WebAuthnTransactionResponse
	SignInWebAuthnFinishResponseError           error
	SignInWebAuthnFinishResponseInfo            *AuthenticationInfo
}

func (m MockDescopeAuthentication) SignInOTP(method DeliveryMethod, identifier string) error {
	if m.AssertSignInOTP != nil {
		m.AssertSignInOTP(method, identifier)
	}
	return m.SignInOTPResponseError
}

func (m MockDescopeAuthentication) SignUpOTP(method DeliveryMethod, identifier string, user *User) error {
	if m.AssertSignUpOTP != nil {
		m.AssertSignUpOTP(method, identifier, user)
	}
	return m.SignUpOTPResponseError
}

func (m MockDescopeAuthentication) SignUpOrInOTP(method DeliveryMethod, identifier string) error {
	if m.AssertSignUpOrInOTP != nil {
		m.AssertSignUpOrInOTP(method, identifier)
	}
	return m.SignUpOrInOTPResponseError
}

func (m MockDescopeAuthentication) SignUpTOTP(identifier string, user *User) (*TOTPResponse, error) {
	if m.AssertSignUpTOTP != nil {
		m.AssertSignUpTOTP(identifier, user)
	}
	return m.SignUpTOTPResponse, m.SignUpTOTPResponseError
}

func (m MockDescopeAuthentication) UpdateUserTOTP(identifier string, _ *http.Request) (*TOTPResponse, error) {
	if m.AssertUpdateTOTP != nil {
		m.AssertUpdateTOTP(identifier)
	}
	return m.UpdateTOTPResponse, m.UpdateTOTPResponseError
}

func (m MockDescopeAuthentication) VerifyTOTPCode(identifier string, code string, _ http.ResponseWriter) (*AuthenticationInfo, error) {
	return m.VerifyTOTPCodeWithOptions(identifier, code, nil)
}

func (m MockDescopeAuthentication) VerifyTOTPCodeWithOptions(identifier string, code string, _ ...Option) (*AuthenticationInfo, error) {
	if m.AssertVerifyTOTPCode != nil {
		m.AssertVerifyTOTPCode(identifier, code)
	}
	return m.VerifyTOTPCodeResponseInfo, m.VerifyTOTPCodeResponseError
}

func (m MockDescopeAuthentication) UpdateUserEmailOTP(identifier, email string, request *http.Request) error {
	if m.AssertUpdateUserEmailOTP != nil {
		m.AssertUpdateUserEmailOTP(identifier, email, request)
	}
	return m.UpdateUserEmailOTPResponseError
}

func (m MockDescopeAuthentication) UpdateUserPhoneOTP(method DeliveryMethod, identifier, email string, request *http.Request) error {
	if m.AssertUpdateUserPhoneOTP != nil {
		m.AssertUpdateUserPhoneOTP(method, identifier, email, request)
	}
	return m.UpdateUserPhoneOTPResponseError
}

func (m MockDescopeAuthentication) VerifyCode(method DeliveryMethod, identifier string, code string, _ http.ResponseWriter) (*AuthenticationInfo, error) {
	if m.AssertVerifyCode != nil {
		m.AssertVerifyCode(method, identifier, code)
	}
	return m.VerifyCodeResponseInfo, m.VerifyCodeResponseError
}

func (m MockDescopeAuthentication) VerifyCodeWithOptions(method DeliveryMethod, identifier string, code string, _ ...Option) (*AuthenticationInfo, error) {
	if m.AssertVerifyCode != nil {
		m.AssertVerifyCode(method, identifier, code)
	}
	return m.VerifyCodeResponseInfo, m.VerifyCodeResponseError
}

func (m MockDescopeAuthentication) SignInMagicLink(method DeliveryMethod, identifier, URI string) error {
	if m.AssertSignInMagicLink != nil {
		m.AssertSignInMagicLink(method, identifier, URI)
	}
	return m.SignInMagicLinkResponseError
}

func (m MockDescopeAuthentication) SignUpMagicLink(method DeliveryMethod, identifier, URI string, user *User) error {
	if m.AssertSignUpMagicLink != nil {
		m.AssertSignUpMagicLink(method, identifier, URI, user)
	}
	return m.SignUpMagicLinkResponseError
}

func (m MockDescopeAuthentication) SignUpOrInMagicLink(method DeliveryMethod, identifier string, URI string) error {
	if m.AssertSignUpOrInMagicLink != nil {
		m.AssertSignUpOrInMagicLink(method, identifier, URI)
	}
	return m.SignUpOrInMagicLinkResponseError
}

func (m MockDescopeAuthentication) SignInMagicLinkCrossDevice(method DeliveryMethod, identifier, URI string) (*MagicLinkResponse, error) {
	if m.AssertSignInMagicLinkCrossDevice != nil {
		m.AssertSignInMagicLinkCrossDevice(method, identifier, URI)
	}
	return m.MagicLinkPendingLinkCrossDeviceResponse, m.SignInMagicLinkCrossDeviceResponseError
}

func (m MockDescopeAuthentication) SignUpMagicLinkCrossDevice(method DeliveryMethod, identifier, URI string, user *User) (*MagicLinkResponse, error) {
	if m.AssertSignUpMagicLinkCrossDevice != nil {
		m.AssertSignUpMagicLinkCrossDevice(method, identifier, URI, user)
	}
	return m.MagicLinkPendingLinkCrossDeviceResponse, m.SignUpMagicLinkCrossDeviceResponseError
}

func (m MockDescopeAuthentication) SignUpOrInMagicLinkCrossDevice(method DeliveryMethod, identifier string, URI string) (*MagicLinkResponse, error) {
	if m.AssertSignUpOrInMagicLinkCrossDevice != nil {
		m.AssertSignUpOrInMagicLinkCrossDevice(method, identifier, URI)
	}
	return m.MagicLinkPendingLinkCrossDeviceResponse, m.SignUpOrInMagicLinkCrossDeviceResponseError
}

func (m MockDescopeAuthentication) UpdateUserEmailMagicLink(identifier, email, URI string, request *http.Request) error {
	if m.AssertUpdateUserEmailMagicLink != nil {
		m.AssertUpdateUserEmailMagicLink(identifier, email, URI, request)
	}
	return m.UpdateUserEmailMagicLinkResponseError
}

func (m MockDescopeAuthentication) UpdateUserEmailMagicLinkCrossDevice(identifier, email, URI string, request *http.Request) (*MagicLinkResponse, error) {
	if m.AssertUpdateUserEmailMagicLinkCrossDevice != nil {
		m.AssertUpdateUserEmailMagicLinkCrossDevice(identifier, email, URI, request)
	}
	return m.UpdateUserEmailMagicLinkCrossDeviceResponse, m.UpdateUserEmailMagicLinkCrossDeviceError
}

func (m MockDescopeAuthentication) UpdateUserPhoneMagicLink(method DeliveryMethod, identifier, email, URI string, request *http.Request) error {
	if m.AssertUpdateUserPhoneMagicLink != nil {
		m.AssertUpdateUserPhoneMagicLink(method, identifier, email, URI, request)
	}
	return m.UpdateUserPhoneMagicLinkResponseError
}

func (m MockDescopeAuthentication) UpdateUserPhoneMagicLinkCrossDevice(method DeliveryMethod, identifier, email, URI string, request *http.Request) (*MagicLinkResponse, error) {
	if m.AssertUpdateUserPhoneMagicLinkCrossDevice != nil {
		m.AssertUpdateUserPhoneMagicLinkCrossDevice(method, identifier, email, URI, request)
	}
	return m.UpdateUserPhoneMagicLinkCrossDeviceResponse, m.UpdateUserPhoneMagicLinkCrossDeviceError
}

func (m MockDescopeAuthentication) GetMagicLinkSession(pendingRef string, _ http.ResponseWriter) (*AuthenticationInfo, error) {
	if m.AssertGetMagicLinkSession != nil {
		m.AssertGetMagicLinkSession(pendingRef)
	}
	return m.GetMagicLinkSessionResponseInfo, m.GetMagicLinkSessionResponseError
}

func (m MockDescopeAuthentication) GetMagicLinkSessionWithOptions(_ string, _ ...Option) (*AuthenticationInfo, error) {
	return m.GetMagicLinkSessionResponseInfo, m.GetMagicLinkSessionResponseError
}

func (m MockDescopeAuthentication) OAuthStart(provider OAuthProvider, returnURL string, w http.ResponseWriter) (string, error) {
	return m.OAuthStartWithOptions(provider, returnURL, WithResponseOption(w))
}

func (m MockDescopeAuthentication) OAuthStartWithOptions(provider OAuthProvider, returnURL string, _ ...Option) (string, error) {
	if m.AssertOAuthStart != nil {
		m.AssertOAuthStart(provider, returnURL)
	}
	return m.AssertOAuthResponseURL, m.OAuthStartResponseError
}

func (m MockDescopeAuthentication) ExchangeToken(code string, w http.ResponseWriter) (*AuthenticationInfo, error) {
	return m.ExchangeTokenWithOptions(code, WithResponseOption(w))
}

func (m MockDescopeAuthentication) ExchangeTokenWithOptions(code string, options ...Option) (*AuthenticationInfo, error) {
	if m.AssertExchangeToken != nil {
		m.AssertExchangeToken(code, options...)
	}
	return m.ExchangeTokenResponseInfo, m.ExchangeTokenResponseError
}

func (m MockDescopeAuthentication) SAMLStart(tenant string, returnURL string, w http.ResponseWriter) (string, error) {
	return m.SAMLStartWithOptions(tenant, returnURL, WithResponseOption(w))
}

func (m MockDescopeAuthentication) SAMLStartWithOptions(tenant string, returnURL string, option ...Option) (string, error) {
	if m.AssertSAMLStart != nil {
		m.AssertSAMLStart(tenant, returnURL, option...)
	}
	return m.AssertSAMLStartResponseURL, m.SAMLStartResponseError
}

func (m MockDescopeAuthentication) VerifyMagicLink(token string, _ http.ResponseWriter) (*AuthenticationInfo, error) {
	if m.AssertVerifyMagicLink != nil {
		m.AssertVerifyMagicLink(token)
	}
	return m.VerifyCodeResponseInfo, m.VerifyCodeResponseError
}

func (m MockDescopeAuthentication) VerifyMagicLinkWithOptions(token string, _ ...Option) (*AuthenticationInfo, error) {
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

func (m MockDescopeAuthentication) Logout(_ *http.Request, _ http.ResponseWriter) error {
	return m.LogoutResponseError
}

func (m MockDescopeAuthentication) LogoutWithOptions(_ *http.Request, _ ...Option) error {
	return m.LogoutResponseError
}

func (m MockDescopeAuthentication) SignUpWebAuthnStart(_ *User) (*WebAuthnTransactionResponse, error) {
	return m.SignUpWebAuthnStartResponseTransaction, m.SignUpWebAuthnStartResponseError
}

func (m MockDescopeAuthentication) SignUpWebAuthnFinish(_ *WebAuthnFinishRequest, _ http.ResponseWriter) (*AuthenticationInfo, error) {
	return m.SignUpWebAuthnFinishResponseInfo, m.SignUpWebAuthnFinishResponseError
}

func (m MockDescopeAuthentication) SignUpWebAuthnFinishWithOptions(_ *WebAuthnFinishRequest, _ ...Option) (*AuthenticationInfo, error) {
	return m.SignUpWebAuthnFinishResponseInfo, m.SignUpWebAuthnFinishResponseError
}

func (m MockDescopeAuthentication) SignInWebAuthnStart(string) (*WebAuthnTransactionResponse, error) {
	return m.SignInWebAuthnStartResponseTransaction, m.SignInWebAuthnStartResponseError
}

func (m MockDescopeAuthentication) SignInWebAuthnFinish(_ *WebAuthnFinishRequest, _ http.ResponseWriter) (*AuthenticationInfo, error) {
	return m.SignInWebAuthnFinishResponseInfo, m.SignInWebAuthnFinishResponseError
}

func (m MockDescopeAuthentication) SignInWebAuthnFinishWithOptions(_ *WebAuthnFinishRequest, _ ...Option) (*AuthenticationInfo, error) {
	return m.SignInWebAuthnFinishResponseInfo, m.SignInWebAuthnFinishResponseError
}
