package auth

import "net/http"

type MockDescopeAuthentication struct {
	SignInOTPResponseError         error
	SignUpOTPResponseError         error
	VerifyCodeResponseInfo         *AuthenticationInfo
	VerifyCodeResponseError        error
	ValidateSessionResponseNotOK   bool
	ValidateSessionResponseInfo    *AuthenticationInfo
	ValidateSessionResponseError   error
	GetPendingSessionResponseInfo  *AuthenticationInfo
	GetPendingSessionResponseError error
	LogoutResponseError            error
	AssertSignInOTP                func(method DeliveryMethod, identifier string)
	AssertSignUpOTP                func(method DeliveryMethod, identifier string, user *User)
	AssertVerifyCode               func(method DeliveryMethod, identifier string, code string)
	AssertOAuthStart               func(provider OAuthProvider)
	AssertOAuthResponseURL         string
	OAuthStartResponseError        error
	AssertSignInMagicLink          func(method DeliveryMethod, identifier, URI string, crossDevice bool)
	AssertSignUpMagicLink          func(method DeliveryMethod, identifier, URI string, user *User, crossDevice bool)
	MagicLinkPendingLinkResponse   *MagicLinkResponse
	AssertVerifyMagicLink          func(token string)
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

func (m MockDescopeAuthentication) SignInMagicLink(method DeliveryMethod, identifier, URI string, crossDevice bool) (*MagicLinkResponse, error) {
	if m.AssertSignInOTP != nil {
		m.AssertSignInMagicLink(method, identifier, URI, crossDevice)
	}
	return m.MagicLinkPendingLinkResponse, m.SignInOTPResponseError
}

func (m MockDescopeAuthentication) SignUpMagicLink(method DeliveryMethod, identifier, URI string, crossDevice bool, user *User) (*MagicLinkResponse, error) {
	if m.AssertSignUpOTP != nil {
		m.AssertSignUpMagicLink(method, identifier, URI, user, crossDevice)
	}
	return m.MagicLinkPendingLinkResponse, m.SignUpOTPResponseError
}

func (m MockDescopeAuthentication) GetPendingSession(_ string, _ http.ResponseWriter) (*AuthenticationInfo, error) {
	return m.GetPendingSessionResponseInfo, m.GetPendingSessionResponseError
}

func (m MockDescopeAuthentication) GetPendingSessionWithOptions(_ string, _ ...Option) (*AuthenticationInfo, error) {
	return m.GetPendingSessionResponseInfo, m.GetPendingSessionResponseError
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
	if m.AssertVerifyCode != nil {
		m.AssertVerifyMagicLink(token)
	}
	return m.VerifyCodeResponseInfo, m.VerifyCodeResponseError
}

func (m MockDescopeAuthentication) VerifyMagicLinkWithOptions(token string, _ ...Option) (*AuthenticationInfo, error) {
	if m.AssertVerifyCode != nil {
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
