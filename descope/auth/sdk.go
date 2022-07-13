package auth

import (
	"net/http"
)

// Implementation in descope/auth/auth.go
type Authentication interface {
	// SignInOTP - Use to login a user based on the given identifier either email or a phone
	// and choose the selected delivery method for verification. (see auth/DeliveryMethod)
	// returns an error upon failure.
	SignInOTP(method DeliveryMethod, identifier string) error
	// SignUpOTP - Use to create a new user based on the given identifier either email or a phone.
	// choose the selected delivery method for verification. (see auth/DeliveryMethod)
	// optional to add user metadata for farther user details such as name and more.
	// returns an error upon failure.
	SignUpOTP(method DeliveryMethod, identifier string, user *User) error
	// SignUpOrInOTP - Use to login in using identifier, if user does not exists, a new user will be created
	// with the given identifier.
	SignUpOrInOTP(method DeliveryMethod, identifier string) error

	// SignUpTOTP - create a new user, and create a seed for it,
	// PAY ATTENTION that this is a different flow than OTP
	// The return value will allow to connect it to an authenticator app
	SignUpTOTP(identifier string, user *User) (*TOTPResponse, error)
	// VerifyTOTPCode - Use to verify a SignIn/SignUp based on the given identifier
	// followed by the code used to verify and authenticate the user.
	// In case the request cookie can be renewed an automatic renewal is called and returns a new set of cookies to use.
	// Use the ResponseWriter (optional) to apply the cookies to the response automatically.
	// returns a list of cookies or an error upon failure.
	// This is a shortcut for VerifyTOTPCodeWithOptions(method, identifier, code, WithResponseOption(w))
	VerifyTOTPCode(identifier string, code string, w http.ResponseWriter) (*AuthenticationInfo, error)
	VerifyTOTPCodeWithOptions(identifier, code string, options ...Option) (*AuthenticationInfo, error)

	// VerifyCode - Use to verify a SignIn/SignUp based on the given identifier either an email or a phone
	// followed by the code used to verify and authenticate the user.
	// In case the request cookie can be renewed an automatic renewal is called and returns a new set of cookies to use.
	// Use the ResponseWriter (optional) to apply the cookies to the response automatically.
	// returns a list of cookies or an error upon failure.
	// This is a shortcut for VerifyCodeWithOptions(method, identifier, code, WithResponseOption(w))
	VerifyCode(method DeliveryMethod, identifier string, code string, w http.ResponseWriter) (*AuthenticationInfo, error)

	// VerifyCodeWithOptions - used to verify a SignIn/SignUp based on the given identifier either an email or a phone
	// followed by the code used to verify and authenticate the user.
	// returns a list of cookies or an error upon failure.
	VerifyCodeWithOptions(method DeliveryMethod, identifier string, code string, options ...Option) (*AuthenticationInfo, error)

	// SignInMagicLink - Use to login a user based on a magic link that will be sent either email or a phone
	// and choose the selected delivery method for verification (see auth/DeliveryMethod).
	// returns an error upon failure.
	SignInMagicLink(method DeliveryMethod, identifier, URI string) error
	// SignUpMagicLink - Use to create a new user based on the given identifier either email or a phone.
	// choose the selected delivery method for verification (see auth/DeliveryMethod).
	// optional to add user metadata for farther user details such as name and more.
	// returns an error upon failure.
	SignUpMagicLink(method DeliveryMethod, identifier, URI string, user *User) error
	// SignUpOrInMagicLink - Use to login in using identifier, if user does not exists, a new user will be created
	// with the given identifier.
	// choose the selected delivery method for verification (see auth/DeliveryMethod).
	// optional to add user metadata for farther user details such as name and more.
	// returns an error upon failure.
	SignUpOrInMagicLink(method DeliveryMethod, identifier string, URI string) error

	// SignInMagicLinkCrossDevice - Use to login a user based on a magic link that will be sent either email or a phone
	// and choose the selected delivery method for verification (see auth/DeliveryMethod).
	// it will return a pending reference to be used in GetMagicLinkSession, which should get the session once the link was verified.
	// returns an error upon failure.
	SignInMagicLinkCrossDevice(method DeliveryMethod, identifier, URI string) (*MagicLinkResponse, error)
	// SignUpMagicLinkCrossDevice - Use to create a new user based on the given identifier either email or a phone.
	// choose the selected delivery method for verification (see auth/DeliveryMethod).
	// optional to add user metadata for farther user details such as name and more.
	// it will return a pending reference to be used in GetMagicLinkSession, which should get the session once the link was verified.
	// returns an error upon failure.
	SignUpMagicLinkCrossDevice(method DeliveryMethod, identifier, URI string, user *User) (*MagicLinkResponse, error)
	// SignUpOrInMagicLinkCrossDevice - Use to login in using identifier, if user does not exists, a new user will be created
	// with the given identifier.
	// choose the selected delivery method for verification (see auth/DeliveryMethod).
	// optional to add user metadata for farther user details such as name and more.
	// it will return a pending reference to be used in GetMagicLinkSession, which should get the session once the link was verified.
	// returns an error upon failure.
	SignUpOrInMagicLinkCrossDevice(method DeliveryMethod, identifier string, URI string) (*MagicLinkResponse, error)

	// GetMagicLinkSession - Use to get a session that was generated by SignInMagicLink/SignUpMagicLink request, and verified with VerifyMagicLink request.
	// This is a shortcut for GetMagicLinkSessionWithOptions(method, code, WithResponseOption(w))
	GetMagicLinkSession(pendingRef string, w http.ResponseWriter) (*AuthenticationInfo, error)
	// GetMagicLinkSessionWithOptions - Use to get a session that was generated by SignInMagicLink/SignUpMagicLink request, and verified with VerifyMagicLink request.
	GetMagicLinkSessionWithOptions(pendingRef string, options ...Option) (*AuthenticationInfo, error)

	// VerifyMagicLink - Use to verify a SignInMagicLink/SignUpMagicLink request, based on the magic link token generated.
	// if the link was generated with crossDevice, the authentication info will be nil, and should returned with GetMagicLinkSession.
	// This is a shortcut for VerifyMagicLinkWithOptions(method, code, WithResponseOption(w))
	VerifyMagicLink(token string, w http.ResponseWriter) (*AuthenticationInfo, error)
	// VerifyMagicLinkWithOptions - used to verify a SignInMagicLink/SignUpMagicLink request, based on the magic link token generated.
	// if the link was generated with crossDevice, the authentication info will be nil, and should returned with GetMagicLinkSession.
	VerifyMagicLinkWithOptions(token string, options ...Option) (*AuthenticationInfo, error)

	// OAuthStart - Use to start an OAuth authentication using the given OAuthProvider.
	// returns an error upon failure and a string represent the redirect URL upon success.
	// Uses the response writer to automatically redirect the client to the provider url for authentication.
	// A successful authentication will result in a callback to the url defined in the current project settings.
	// This is a shortcut for OAuthStartWithOptions(provider, WithResponseOption(w))
	OAuthStart(provider OAuthProvider, returnURL string, w http.ResponseWriter) (string, error)
	// OAuthStartWithOptions - use to start an OAuth authentication using the given OAuthProvider and options.
	OAuthStartWithOptions(provider OAuthProvider, returnURL string, options ...Option) (string, error)
	// ExchangeToken - Finalize OAuth or SAML authentication
	// code should be extracted from the redirect URL of OAth/SAML authentication flow
	ExchangeToken(code string, w http.ResponseWriter) (*AuthenticationInfo, error)
	// ExchangeTokenWithOptions - Finalize OAuth or SAML authentication
	// code should be extracted from the redirect URL of OAth/SAML authentication flow
	ExchangeTokenWithOptions(code string, options ...Option) (*AuthenticationInfo, error)

	// SAMLStart will initiate a SAML login flow
	// return will be the redirect URL that needs to return to client
	// and finalize with the ExchangeToken call
	SAMLStart(tenant string, returnURL string, w http.ResponseWriter) (redirectURL string, err error)
	// SAMLStartWithOptions will initiate a SAML login flow
	// options are the options to return the data to front end
	// return will be the redirect URL that needs to return to client
	// and finalize with the ExchangeToken call
	SAMLStartWithOptions(tenant string, landingURL string, options ...Option) (redirectURL string, err error)

	// ValidateSession - Use to validate a session of a given request.
	// Should be called before any private API call that requires authorization.
	// In case the request cookie can be renewed an automatic renewal is called and returns a new set of cookies to use.
	// Use the ResponseWriter (optional) to apply the cookies to the response automatically.
	// returns true upon success or false and an error upon failure.
	// This is a shortcut for ValidateSessionWithOptions(r, WithResponseOption(w))
	ValidateSession(request *http.Request, w http.ResponseWriter) (bool, *Token, error)
	ValidateSessionWithOptions(request *http.Request, options ...Option) (bool, *Token, error)

	// SignUpWebAuthnStart - Use to start an authentication process with webauthn for the new user argument.
	// returns a transaction id response on successs and error upon failure.
	SignUpWebAuthnStart(user *User) (*WebAuthnTransactionResponse, error)
	// SignUpWebAuthnFinish - Use to finish an authentication process with a given transaction id and credentials after been signed
	// by the credentials navigator.
	// Use the ResponseWriter (optional) to apply the cookies to the response automatically.
	// This is a shortcut for SignUpWebAuthnFinishWithOptions(finishRequest, WithResponseOption(w))
	SignUpWebAuthnFinish(finishRequest *WebAuthnFinishRequest, w http.ResponseWriter) (*AuthenticationInfo, error)
	// SignUpWebAuthnFinishWithOptions - Use to finish an authentication process with a given transaction id and credentials after been signed
	// by the credentials navigator.
	SignUpWebAuthnFinishWithOptions(finishRequest *WebAuthnFinishRequest, options ...Option) (*AuthenticationInfo, error)

	// SignInWebAuthnStart - Use to start an authentication validation with webauthn for an existing user with the given identifier.
	// returns a transaction id response on successs and error upon failure.
	SignInWebAuthnStart(identifier string) (*WebAuthnTransactionResponse, error)
	// SignInWebAuthnFinish - Use to finish an authentication process with a given transaction id and credentials after been signed
	// by the credentials navigator.
	// Use the ResponseWriter (optional) to apply the cookies to the response automatically.
	// This is a shortcut for SignInWebAuthnFinishWithOptions(finishRequest, WithResponseOption(w))
	SignInWebAuthnFinish(finishRequest *WebAuthnFinishRequest, w http.ResponseWriter) (*AuthenticationInfo, error)
	// SignInWebAuthnFinishWithOptions - Use to finish an authentication process with a given transaction id and credentials after been signed
	// by the credentials navigator.
	SignInWebAuthnFinishWithOptions(finishRequest *WebAuthnFinishRequest, options ...Option) (*AuthenticationInfo, error)

	// Logout - Use to perform logout from all active devices. This will revoke the given tokens
	// and if given options will also remove existing session on the given response sent to the client.
	// Use the ResponseWriter (optional) to apply the cookies to the response automatically.
	// This is a shortcut for LogoutWithOptions(r, WithResponseOption(w))
	Logout(request *http.Request, w http.ResponseWriter) error
	// LogoutWithOptions - Use to perform logout from all active devices. This will revoke the given tokens
	// and if given options will also remove existing session on the given response.
	LogoutWithOptions(request *http.Request, options ...Option) error

	// UpdateUserEmailOTP - Use to a update email, and verify via OTP
	// ExternalID of user whom we want to update
	// Request is needed to obtain JWT and send it to Descope, for verification
	UpdateUserEmailOTP(identifier, email string, request *http.Request) error
	// UpdateUserEmailMagicLink - Use to update email and validate via magiclink
	// ExternalID of user whom we want to update
	// Request is needed to obtain JWT and send it to Descope, for verification
	UpdateUserEmailMagicLink(identifier, email, URI string, request *http.Request) error
	// UpdateUserEmailMagicLinkCrossDevice - Use to update email and validate via magiclink, with cross device options
	// ExternalID of user whom we want to update
	// Request is needed to obtain JWT and send it to Descope, for verification
	UpdateUserEmailMagicLinkCrossDevice(identifier, email, URI string, request *http.Request) (*MagicLinkResponse, error)
	// UpdateUserPhoneOTP - Use to update phone and validate via OTP
	// allowed methods are phone based methods - whatsapp and SMS
	// ExternalID of user whom we want to update
	// Request is needed to obtain JWT and send it to Descope, for verification
	UpdateUserPhoneOTP(method DeliveryMethod, identifier, phone string, request *http.Request) error
	// UpdateUserPhoneMagicLink - Use to update phone and validate via magiclink
	// allowed methods are phone based methods - whatsapp and SMS
	// ExternalID of user whom we want to update
	// Request is needed to obtain JWT and send it to Descope, for verification
	UpdateUserPhoneMagicLink(method DeliveryMethod, identifier, phone, URI string, request *http.Request) error
	// UpdateUserPhoneMagicLinkCrossDevice - Use to update email and validate via magiclink, with cross device options
	// allowed methods are phone based methods - whatsapp and SMS
	// ExternalID of user whom we want to update
	// Request is needed to obtain JWT and send it to Descope, for verification
	UpdateUserPhoneMagicLinkCrossDevice(method DeliveryMethod, identifier, phone, URI string, request *http.Request) (*MagicLinkResponse, error)

	// UpdateUserTOTP - set a seed to an existing user, so the user can use an authenticator app
	UpdateUserTOTP(identifier string, request *http.Request) (*TOTPResponse, error)
}
