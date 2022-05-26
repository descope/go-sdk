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
}

func (m MockDescopeAuth) SignInOTP(_ DeliveryMethod, _ string) error {
	return m.SignInOTPResponseError
}

func (m MockDescopeAuth) SignUpOTP(_ DeliveryMethod, _ string, _ *User) error {
	return m.SignUpOTPResponseError
}

func (m MockDescopeAuth) VerifyCode(_ DeliveryMethod, _ string, _ string, _ http.ResponseWriter) ([]*http.Cookie, error) {
	return m.VerifyCodeResponseCookies, m.VerifyCodeResponseError
}

func (m MockDescopeAuth) VerifyCodeWithOptions(_ DeliveryMethod, _ string, _ string, _ ...Option) ([]*http.Cookie, error) {
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
