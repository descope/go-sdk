package auth

import "net/http"

type MockDescopeAuth struct {
	SignInOTPResponseError       error
	SignUpOTPResponseError       error
	VerifyCodeResponseCookies    []*http.Cookie
	VerifyCodeResponseError      error
	ValidateSessionResponseNotOK bool
	ValidateSessionResponseToken string
	ValidateSessionResponseError error
	LogoutResponseError          error
	AssertSignInOTP              func(method DeliveryMethod, identifier string)
	AssertSignUpOTP              func(method DeliveryMethod, identifier string, user *User)
	AssertVerifyCode             func(method DeliveryMethod, identifier string, code string)
}

func (m MockDescopeAuth) SignInOTP(method DeliveryMethod, identifier string) error {
	if m.AssertSignInOTP != nil {
		m.AssertSignInOTP(method, identifier)
	}
	return m.SignInOTPResponseError
}

func (m MockDescopeAuth) SignUpOTP(method DeliveryMethod, identifier string, user *User) error {
	if m.AssertSignUpOTP != nil {
		m.AssertSignUpOTP(method, identifier, user)
	}
	return m.SignUpOTPResponseError
}

func (m MockDescopeAuth) VerifyCode(method DeliveryMethod, identifier string, code string, _ http.ResponseWriter) ([]*http.Cookie, error) {
	if m.AssertVerifyCode != nil {
		m.AssertVerifyCode(method, identifier, code)
	}
	return m.VerifyCodeResponseCookies, m.VerifyCodeResponseError
}

func (m MockDescopeAuth) VerifyCodeWithOptions(method DeliveryMethod, identifier string, code string, _ ...Option) ([]*http.Cookie, error) {
	if m.AssertVerifyCode != nil {
		m.AssertVerifyCode(method, identifier, code)
	}
	return m.VerifyCodeResponseCookies, m.VerifyCodeResponseError
}

func (m MockDescopeAuth) ValidateSession(_ *http.Request, _ http.ResponseWriter) (bool, string, error) {
	return !m.ValidateSessionResponseNotOK, m.ValidateSessionResponseToken, m.ValidateSessionResponseError
}

func (m MockDescopeAuth) ValidateSessionWithOptions(_ *http.Request, _ ...Option) (bool, string, error) {
	return !m.ValidateSessionResponseNotOK, m.ValidateSessionResponseToken, m.ValidateSessionResponseError
}

func (m MockDescopeAuth) Logout(_ *http.Request, _ http.ResponseWriter) error {
	return m.LogoutResponseError
}

func (m MockDescopeAuth) LogoutWithOptions(_ *http.Request, _ ...Option) error {
	return m.LogoutResponseError
}
