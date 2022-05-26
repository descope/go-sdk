package auth

import "net/http"

type MockDescopeAuth struct {
	SignInOTPResponseError         error
	SignUpOTPResponseError         error
	VerifyCodeResponseCookies      []*http.Cookie
	VerifyCodeResponseError        error
	ValidateSessionResponseNotOK   bool
	ValidateSessionResponseCookies []*http.Cookie
	ValidateSessionResponseError   error
	LogoutResponseCookies          []*http.Cookie
	LogoutResponseError            error
}

func (m MockDescopeAuth) SignInOTP(method DeliveryMethod, identifier string) error {
	return m.SignInOTPResponseError
}

func (m MockDescopeAuth) SignUpOTP(method DeliveryMethod, identifier string, user *User) error {
	return m.SignUpOTPResponseError
}

func (m MockDescopeAuth) VerifyCode(method DeliveryMethod, identifier string, code string, w http.ResponseWriter) ([]*http.Cookie, error) {
	return m.VerifyCodeResponseCookies, m.VerifyCodeResponseError
}

func (m MockDescopeAuth) VerifyCodeWithOptions(method DeliveryMethod, identifier string, code string, options ...Option) ([]*http.Cookie, error) {
	return m.VerifyCodeResponseCookies, m.VerifyCodeResponseError
}

func (m MockDescopeAuth) ValidateSession(request *http.Request, w http.ResponseWriter) (bool, []*http.Cookie, error) {
	return !m.ValidateSessionResponseNotOK, m.ValidateSessionResponseCookies, m.ValidateSessionResponseError
}

func (m MockDescopeAuth) ValidateSessionWithOptions(request *http.Request, options ...Option) (bool, []*http.Cookie, error) {
	return !m.ValidateSessionResponseNotOK, m.ValidateSessionResponseCookies, m.ValidateSessionResponseError
}

func (m MockDescopeAuth) Logout(request *http.Request, w http.ResponseWriter) ([]*http.Cookie, error) {
	return m.LogoutResponseCookies, m.LogoutResponseError
}

func (m MockDescopeAuth) LogoutWithOptions(request *http.Request, options ...Option) ([]*http.Cookie, error) {
	return m.LogoutResponseCookies, m.LogoutResponseError
}
