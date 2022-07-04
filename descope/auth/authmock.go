package auth

import "net/http"

type MockDescopeAuthentication struct {
	SignInOTPResponseError                      error
	SignUpOTPResponseError                      error
	SignUpOrInOTPResponseError                  error
	VerifyCodeResponseInfo                      *AuthenticationInfo
	VerifyCodeResponseError                     error
	ValidateSessionResponseNotOK                bool
	ValidateSessionResponseInfo                 *AuthenticationInfo
	ValidateSessionResponseError                error
	GetMagicLinkSessionResponseInfo             *AuthenticationInfo
	GetMagicLinkSessionResponseError            error
	LogoutResponseError                         error
	AssertSignInOTP                             func(method DeliveryMethod, identifier string)
	AssertSignUpOTP                             func(method DeliveryMethod, identifier string, user *User)
	AssertSignUpOrInOTP                         func(method DeliveryMethod, identifier string)
	AssertVerifyCode                            func(method DeliveryMethod, identifier string, code string)
	AssertOAuthStart                            func(provider OAuthProvider)
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

func (m MockDescopeAuthentication) GetMagicLinkSession(pendingRef string, _ http.ResponseWriter) (*AuthenticationInfo, error) {
	if m.AssertGetMagicLinkSession != nil {
		m.AssertGetMagicLinkSession(pendingRef)
	}
	return m.GetMagicLinkSessionResponseInfo, m.GetMagicLinkSessionResponseError
}

func (m MockDescopeAuthentication) GetMagicLinkSessionWithOptions(_ string, _ ...Option) (*AuthenticationInfo, error) {
	return m.GetMagicLinkSessionResponseInfo, m.GetMagicLinkSessionResponseError
}

func (m MockDescopeAuthentication) OAuthStart(provider OAuthProvider, _ http.ResponseWriter) (string, error) {
	if m.AssertOAuthStart != nil {
		m.AssertOAuthStart(provider)
	}
	return m.AssertOAuthResponseURL, m.OAuthStartResponseError
}

func (m MockDescopeAuthentication) OAuthStartWithOptions(provider OAuthProvider, _ ...Option) (string, error) {
	if m.AssertOAuthStart != nil {
		m.AssertOAuthStart(provider)
	}
	return m.AssertOAuthResponseURL, m.OAuthStartResponseError
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

func (m MockDescopeAuthentication) ValidateSession(_ *http.Request, _ http.ResponseWriter) (bool, *AuthenticationInfo, error) {
	return !m.ValidateSessionResponseNotOK, m.ValidateSessionResponseInfo, m.ValidateSessionResponseError
}

func (m MockDescopeAuthentication) ValidateSessionWithOptions(_ *http.Request, _ ...Option) (bool, *AuthenticationInfo, error) {
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
