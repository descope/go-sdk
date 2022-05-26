package auth

import "net/http"

// Implementation sits in descope/auth/auth.go
type IAuth interface {
	// SignInOTP - used to login a user based on the given identifier, either email or a phone.
	// choose the selected delivery method for verification. (see auth/DeliveryMethod)
	// returns an error upon failure.
	SignInOTP(method DeliveryMethod, identifier string) error

	// SignUpOTP - used to create a new user based on the given identifier either email or a phone.
	// choose the selected delivery method for verification. (see auth/DeliveryMethod)
	// optional to add user metadata for farther user details such as name and more.
	// returns an error upon failure.
	SignUpOTP(method DeliveryMethod, identifier string, user *User) error

	// VerifyCode - used to verify a SignIn/SignUp based on the given identifier either an email or a phone
	// followed by the code used to verify and authenticate the user.
	// returns a list of cookies or an error upon failure.
	VerifyCode(method DeliveryMethod, identifier string, code string, w *http.ResponseWriter) ([]*http.Cookie, error)

	VerifyCodeWithOptions(method DeliveryMethod, identifier string, code string, w *http.ResponseWriter) ([]*http.Cookie, error)

	// ValidateSession - used to validate a session of a given request.
	// Should be called before any private API call that requires authorization.
	// returns true upon success or false and/or error upon failure.
	ValidateSession(r *http.Request, w *http.ResponseWriter) (bool, []*http.Cookie, error)

	ValidateSessionWithOptions(r *http.Request, w *http.ResponseWriter) (bool, []*http.Cookie, error)

	// Logout - used to perform logout from all active devices. This will revoke the given tokens
	// and will also revoke existing session cookies.
	Logout(r *http.Request, w *http.ResponseWriter) ([]*http.Cookie, error)

	LogoutWithOptions(r *http.Request, w *http.ResponseWriter) (bool, []*http.Cookie, error)
}
