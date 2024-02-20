package sdk

import (
	"context"
	"net/http"

	"github.com/descope/go-sdk/descope"
)

type MagicLink interface {
	// SignIn - Use to login a user based on a magic link that will be sent either email or a phone
	// and choose the selected delivery method for verification (see auth/DeliveryMethod).
	// returns the masked address where the link was sent (email or phone) or an error upon failure.
	SignIn(ctx context.Context, method descope.DeliveryMethod, loginID, URI string, r *http.Request, loginOptions *descope.LoginOptions) (maskedAddress string, err error)

	// SignUp - Use to create a new user based on the given loginID either email or a phone.
	// choose the selected delivery method for verification (see auth/DeliveryMethod).
	// optional to add user metadata for farther user details such as name and more.
	// returns the masked address where the link was sent (email or phone) or an error upon failure.
	SignUp(ctx context.Context, method descope.DeliveryMethod, loginID, URI string, user *descope.User, signUpOptions *descope.SignUpOptions) (maskedAddress string, err error)

	// SignUpOrIn - Use to login in using loginID, if user does not exist, a new user will be created
	// with the given loginID.
	// choose the selected delivery method for verification (see auth/DeliveryMethod).
	// optional to add user metadata for farther user details such as name and more.
	// returns the masked address where the link was sent (email or phone) or an error upon failure.
	SignUpOrIn(ctx context.Context, method descope.DeliveryMethod, loginID string, URI string, signUpOptions *descope.SignUpOptions) (maskedAddress string, err error)

	// Verify - Use to verify a SignIn/SignUp request, based on the magic link token generated.
	// if the link was generated with crossDevice, the authentication info will be nil, and should returned with GetSession.
	Verify(ctx context.Context, token string, w http.ResponseWriter) (*descope.AuthenticationInfo, error)

	// UpdateUserEmail - Use to update email and validate via magiclink
	// LoginID of user whom we want to update
	// UpdateOptions to determine whether to add email as a login id and if to merge with existing user in that case
	// Request is needed to obtain JWT and send it to Descope, for verification
	// returns the masked email where the link was sent or an error upon failure.
	UpdateUserEmail(ctx context.Context, loginID, email, URI string, updateOptions *descope.UpdateOptions, request *http.Request) (maskedAddress string, err error)

	// UpdateUserPhone - Use to update phone and validate via magiclink
	// allowed methods are phone based methods - whatsapp and SMS
	// LoginID of user whom we want to update
	// UpdateOptions to determine whether to add email as a login id and if to merge with existing user in that case
	// Request is needed to obtain JWT and send it to Descope, for verification
	// returns the masked phone where the link was sent or an error upon failure.
	UpdateUserPhone(ctx context.Context, method descope.DeliveryMethod, loginID, phone, URI string, updateOptions *descope.UpdateOptions, request *http.Request) (maskedAddress string, err error)
}

type EnchantedLink interface {
	// SignIn - Use to login a user based on an enchanted link that will be sent by email
	// the jwt would be returned on the getSession function at the end of the flow rather that on the verify.
	// returns an error upon failure.
	SignIn(ctx context.Context, loginID, URI string, r *http.Request, loginOptions *descope.LoginOptions) (*descope.EnchantedLinkResponse, error)

	// SignUp - Use to create a new user based on the given loginID either email or a phone.
	// optional to add user metadata for farther user details such as name and more.
	// returns an error upon failure.
	SignUp(ctx context.Context, loginID, URI string, user *descope.User, signUpOptions *descope.SignUpOptions) (*descope.EnchantedLinkResponse, error)

	// SignUpOrIn - Use to login in using loginID, if user does not exist, a new user will be created
	// with the given loginID.
	// optional to add user metadata for farther user details such as name and more.
	// returns an error upon failure.
	SignUpOrIn(ctx context.Context, loginID string, URI string, signUpOptions *descope.SignUpOptions) (*descope.EnchantedLinkResponse, error)

	// GetSession - Use to get a session that was generated by SignIn/SignUp request.
	// This function will return a proper JWT only after Verify succeed for this sign up/in.
	GetSession(ctx context.Context, pendingRef string, w http.ResponseWriter) (*descope.AuthenticationInfo, error)

	// Verify - Use to verify a SignIn/SignUp request, based on the enchanted link token generated.
	Verify(ctx context.Context, token string) error

	// UpdateUserEmail - Use to update email and validate via enchanted link
	// LoginID of user whom we want to update
	// UpdateOptions to determine whether to add email as a login id and if to merge with existing user in that case
	// Request is needed to obtain JWT and send it to Descope, for verification
	UpdateUserEmail(ctx context.Context, loginID, email, URI string, updateOptions *descope.UpdateOptions, request *http.Request) (*descope.EnchantedLinkResponse, error)
}

type OTP interface {
	// SignIn - Use to login a user based on the given loginID either email or a phone
	// and choose the selected delivery method for verification. (see auth/DeliveryMethod)
	// returns the masked address where the code was sent (email or phone) or an error upon failure.
	SignIn(ctx context.Context, method descope.DeliveryMethod, loginID string, r *http.Request, loginOptions *descope.LoginOptions) (maskedAddress string, err error)

	// SignUp - Use to create a new user based on the given loginID either email or a phone.
	// choose the selected delivery method for verification. (see auth/DeliveryMethod)
	// optional to add user metadata for farther user details such as name and more.
	// returns the masked address where the code was sent (email or phone) or an error upon failure.
	SignUp(ctx context.Context, method descope.DeliveryMethod, loginID string, user *descope.User, signUpOptions *descope.SignUpOptions) (maskedAddress string, err error)

	// SignUpOrIn - Use to login in using loginID, if user does not exist, a new user will be created
	// with the given loginID.
	// returns the masked address where the code was sent (email or phone) or an error upon failure.
	SignUpOrIn(ctx context.Context, method descope.DeliveryMethod, loginID string, signUpOptions *descope.SignUpOptions) (maskedAddress string, err error)

	// VerifyCode - Use to verify a SignIn/SignUp based on the given loginID either an email or a phone
	// followed by the code used to verify and authenticate the user.
	// In case the request cookie can be renewed an automatic renewal is called and returns a new set of cookies to use.
	// Use the ResponseWriter (optional) to apply the cookies to the response automatically.
	// returns a list of cookies or an error upon failure.
	VerifyCode(ctx context.Context, method descope.DeliveryMethod, loginID string, code string, w http.ResponseWriter) (*descope.AuthenticationInfo, error)

	// UpdateUserEmail - Use to a update email, and verify via OTP
	// LoginID of user whom we want to update
	// UpdateOptions to determine whether to add email as a login id and if to merge with existing user in that case
	// Request is needed to obtain JWT and send it to Descope, for verification
	// returns the masked email where the code was sent or an error upon failure.
	UpdateUserEmail(ctx context.Context, loginID, email string, updateOptions *descope.UpdateOptions, request *http.Request) (maskedAddress string, err error)

	// UpdateUserPhone - Use to update phone and validate via OTP
	// allowed methods are phone based methods - whatsapp and SMS
	// LoginID of user whom we want to update
	// UpdateOptions to determine whether to add email as a login id and if to merge with existing user in that case
	// Request is needed to obtain JWT and send it to Descope, for verification
	// returns the masked phone where the code was sent or an error upon failure.
	UpdateUserPhone(ctx context.Context, method descope.DeliveryMethod, loginID, phone string, updateOptions *descope.UpdateOptions, request *http.Request) (maskedAddress string, err error)
}

type TOTP interface {
	// SignUp - create a new user, and create a seed for it,
	// PAY ATTENTION that this is a different flow than OTP
	// The return value will allow to connect it to an authenticator app
	SignUp(ctx context.Context, loginID string, user *descope.User) (*descope.TOTPResponse, error)

	// SignInCode - Use to verify a SignIn/SignUp based on the given loginID
	// followed by the code used to verify and authenticate the user.
	// In case the request cookie can be renewed an automatic renewal is called and returns a new set of cookies to use.
	// Use the ResponseWriter (optional) to apply the cookies to the response automatically.
	// returns a list of cookies or an error upon failure.
	SignInCode(ctx context.Context, loginID string, code string, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter) (*descope.AuthenticationInfo, error)

	// UpdateUser - set a seed to an existing user, so the user can use an authenticator app
	UpdateUser(ctx context.Context, loginID string, request *http.Request) (*descope.TOTPResponse, error)
}

type Password interface {
	// SignUp - Use to create a new user that authenticates with a password.
	// Use the ResponseWriter (optional) to apply the cookies to the response automatically.
	// returns a list of cookies or an error upon failure.
	SignUp(ctx context.Context, loginID string, user *descope.User, password string, w http.ResponseWriter) (*descope.AuthenticationInfo, error)

	// SignIn - Use to login a user by authenticating with a password.
	// Use the ResponseWriter (optional) to apply the cookies to the response automatically.
	// returns a list of cookies or an error upon failure.
	SignIn(ctx context.Context, loginID string, password string, w http.ResponseWriter) (*descope.AuthenticationInfo, error)

	// SendPasswordReset - sends a password reset prompt to the user with the given
	// loginID according to the password settings defined in the Descope console.
	// The user must be verified according to the configured password reset method.
	// Once verified, use UpdateUserPassword to change the user's password.
	// redirectURL is an optional parameter that is used by Magic Link or Enchanted Link
	// if those are the chosen reset methods. See the Magic Link and Enchanted Link sections
	// for more details.
	// templateOptions is used to pass dynamic options for the messaging (email / text message) template
	SendPasswordReset(ctx context.Context, loginID, redirectURL string, templateOptions map[string]string) error

	// UpdateUserPassword - updates a user's password according to the given loginID.
	// This function requires the user to have an active session.
	// Request is needed to obtain a JWT and send it to Descope, for verification.
	// NewPassword must conform to the password policy defined in the password settings
	// in the Descope console.
	UpdateUserPassword(ctx context.Context, loginID, newPassword string, r *http.Request) error

	// ReplaceUserPassword - updates a user's password according to the given loginID.
	// This function requires the current or 'oldPassword' to be active.
	// If the user can be successfully authenticated using the oldPassword, the user's
	// password will be updated to newPassword.
	// NewPassword must conform to the password policy defined in the password settings
	// in the Descope console.
	ReplaceUserPassword(ctx context.Context, loginID, oldPassword, newPassword string, w http.ResponseWriter) (*descope.AuthenticationInfo, error)

	// GetPasswordPolicy - fetch the rules for valid passwords configured in the policy
	// in the Descope console. This can be used to implement client-side validation of new
	// user passwords for a better user experience. Either way, the comprehensive
	// policy is always enforced by Descope on the server side.
	GetPasswordPolicy(ctx context.Context) (*descope.PasswordPolicy, error)
}

type OAuth interface {
	// Start [Deprecated: Use SignUpOrIn instead] - Use to start an OAuth authentication using the given OAuthProvider.
	// returns an error upon failure and a string represent the redirect URL upon success.
	// Uses the response writer to automatically redirect the client to the provider url for authentication.
	// A successful authentication will result in a callback to the url defined in the current project settings.
	Start(ctx context.Context, provider descope.OAuthProvider, returnURL string, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter) (string, error)

	// SignUpOrIn - Use to start an OAuth authentication using the given OAuthProvider.
	// returns an error upon failure and a string represent the redirect URL upon success.
	// Uses the response writer to automatically redirect the client to the provider url for authentication.
	// A successful authentication will result in a callback to the url defined in the current project settings.
	SignUpOrIn(ctx context.Context, provider descope.OAuthProvider, returnURL string, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter) (string, error)

	// SignUp - Use to start an OAuth authentication using the given OAuthProvider and force a sign up only.
	// returns an error upon failure and a string represent the redirect URL upon success.
	// Uses the response writer to automatically redirect the client to the provider url for authentication.
	// A successful authentication will result in a callback to the url defined in the current project settings.
	SignUp(ctx context.Context, provider descope.OAuthProvider, returnURL string, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter) (string, error)

	// SignIn - Use to start an OAuth authentication using the given OAuthProvider and force a sign in only.
	// returns an error upon failure and a string represent the redirect URL upon success.
	// Uses the response writer to automatically redirect the client to the provider url for authentication.
	// A successful authentication will result in a callback to the url defined in the current project settings.
	SignIn(ctx context.Context, provider descope.OAuthProvider, returnURL string, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter) (string, error)

	// ExchangeToken - Finalize OAuth
	// code should be extracted from the redirect URL of OAth/SAML authentication flow
	ExchangeToken(ctx context.Context, code string, w http.ResponseWriter) (*descope.AuthenticationInfo, error)
}

/* Deprecated */
type SAML interface {
	// Start will initiate a SAML login flow
	// return will be the redirect URL that needs to return to client
	// and finalize with the ExchangeToken call
	Start(ctx context.Context, tenant string, returnURL string, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter) (redirectURL string, err error)

	// ExchangeToken - Finalize SAML authentication
	// code should be extracted from the redirect URL of OAth/SAML authentication flow
	ExchangeToken(ctx context.Context, code string, w http.ResponseWriter) (*descope.AuthenticationInfo, error)
}

type SSOServiceProvider interface {
	// Start will initiate a login flow based on tenant configuration (saml/oidc)
	// return will be the redirect URL that needs to return to client
	// and finalize with the ExchangeToken call
	// prompt argument relevant only in case tenant configured with AuthType OIDC
	Start(ctx context.Context, tenant string, returnURL string, prompt string, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter) (redirectURL string, err error)

	// ExchangeToken - Finalize tenant login authentication
	// code should be extracted from the redirect URL of SAML/OIDC authentication flow
	ExchangeToken(ctx context.Context, code string, w http.ResponseWriter) (*descope.AuthenticationInfo, error)
}

type WebAuthn interface {
	// SignUpStart - Use to start an authentication process with webauthn for the new user argument.
	// Origin is the origin of the URL for the web page where the webauthn operation is taking place, as returned
	// by calling document.location.origin via javascript.
	// returns a transaction id response on success and error upon failure.
	SignUpStart(ctx context.Context, loginID string, user *descope.User, origin string) (*descope.WebAuthnTransactionResponse, error)

	// SignUpFinish - Use to finish an authentication process with a given transaction id and credentials after been signed
	// by the credentials navigator.
	// Use the ResponseWriter (optional) to apply the cookies to the response automatically.
	SignUpFinish(ctx context.Context, finishRequest *descope.WebAuthnFinishRequest, w http.ResponseWriter) (*descope.AuthenticationInfo, error)

	// SignInStart - Use to start an authentication validation with webauthn for an existing user with the given loginID.
	// Origin is the origin of the URL for the web page where the webauthn operation is taking place, as returned
	// by calling document.location.origin via javascript.
	// returns a transaction id response on successs and error upon failure.
	SignInStart(ctx context.Context, loginID string, origin string, r *http.Request, loginOptions *descope.LoginOptions) (*descope.WebAuthnTransactionResponse, error)

	// SignInFinish - Use to finish an authentication process with a given transaction id and credentials after been signed
	// by the credentials navigator.
	// Use the ResponseWriter (optional) to apply the cookies to the response automatically.
	SignInFinish(ctx context.Context, finishRequest *descope.WebAuthnFinishRequest, w http.ResponseWriter) (*descope.AuthenticationInfo, error)

	// SignUpOrInStart - Use to start an authentication validation with webauthn, if user does not exist, a new user will be created
	// with the given loginID. The Create field in the response object determines which browser API should be called,
	// either navigator.credentials.create or navigator.credentials.get as well as whether to call SignUpFinish (if
	// Create is true) or SignInFinish (if Create is false) later to finalize the operation.
	// Origin is the origin of the URL for the web page where the webauthn operation is taking place, as returned
	// by calling document.location.origin via javascript.
	// returns a transaction id response on successs and error upon failure.
	SignUpOrInStart(ctx context.Context, loginID string, origin string) (*descope.WebAuthnTransactionResponse, error)

	// UpdateUserDeviceStart - Use to start an add webauthn device process for an existing user with the given loginID.
	// Request is needed to obtain JWT and send it to Descope, for verification.
	// Origin is the origin of the URL for the web page where the webauthn operation is taking place, as returned
	// by calling document.location.origin via javascript.
	// returns a transaction id response on success and error upon failure.
	UpdateUserDeviceStart(ctx context.Context, loginID string, origin string, request *http.Request) (*descope.WebAuthnTransactionResponse, error)

	// UpdateUserDeviceFinish - Use to finish an add webauthn device process with a given transaction id and credentials after been signed
	// by the credentials navigator.
	UpdateUserDeviceFinish(ctx context.Context, finishRequest *descope.WebAuthnFinishRequest) error
}

type Authentication interface {
	MagicLink() MagicLink
	EnchantedLink() EnchantedLink
	OTP() OTP
	TOTP() TOTP
	Password() Password
	OAuth() OAuth
	SAML() SAML
	SSO() SSOServiceProvider
	WebAuthn() WebAuthn

	// ValidateSessionWithRequest - Use to validate a session of a given request.
	// Should be called before any private API call that requires authorization.
	// Alternatively use ValidateSessionWithToken with the token directly.
	// returns true upon success or false, the session token and an error upon failure.
	ValidateSessionWithRequest(request *http.Request) (bool, *descope.Token, error)

	// ValidateSessionWithToken - Use to validate a session token directly.
	// Should be called before any private API call that requires authorization.
	// Alternatively use ValidateSessionWithRequest with the incoming request.
	// returns true upon success or false, the session token and an error upon failure.
	ValidateSessionWithToken(ctx context.Context, sessionToken string) (bool, *descope.Token, error)

	// ValidateSessionWithRequest - Use to refresh an expired session of a given request.
	// Should be called when a session has expired (failed validation) to renew it.
	// Use the ResponseWriter (optional) to apply the cookies to the response automatically.
	// Alternatively use RefreshSessionWithToken with the refresh token directly.
	// returns true upon success or false, the updated session token and an error upon failure.
	RefreshSessionWithRequest(request *http.Request, w http.ResponseWriter) (bool, *descope.Token, error)

	// RefreshSessionWithToken - Use to refresh an expired session with a given refresh token.
	// Should be called when a session has expired (failed validation) to renew it.
	// Alternatively use RefreshSessionWithRequest with the incoming request.
	// returns true upon success or false, the updated session token and an error upon failure.
	RefreshSessionWithToken(ctx context.Context, refreshToken string) (bool, *descope.Token, error)

	// ValidateAndRefreshSessionWithRequest - Use to validate a session of a given request.
	// Should be called before any private API call that requires authorization.
	// In case the request cookie can be renewed an automatic renewal is called and returns a new set of cookies to use.
	// Use the ResponseWriter (optional) to apply the cookies to the response automatically.
	// Alternatively use ValidateAndRefreshSessionWithTokens with the tokens directly.
	// returns true upon success or false, the potentially updated session token and an error upon failure.
	ValidateAndRefreshSessionWithRequest(request *http.Request, w http.ResponseWriter) (bool, *descope.Token, error)

	// ValidateAndRefreshSessionWithTokens - Use to validate a session with the session and refresh tokens.
	// Should be called before any private API call that requires authorization.
	// In case the request cookie can be renewed an automatic renewal is called and returns a new set of cookies to use.
	// Alternatively use ValidateAndRefreshSessionWithRequest with the incoming request.
	// returns true upon success or false, the potentially updated session token and an error upon failure.
	ValidateAndRefreshSessionWithTokens(ctx context.Context, sessionToken, refreshToken string) (bool, *descope.Token, error)

	// ExchangeAccessKey - Use to exchange an access key for a session token.
	ExchangeAccessKey(ctx context.Context, accessKey string) (bool, *descope.Token, error)

	// ValidatePermissions - Use to ensure that a validated session token has been granted
	// the specified permissions.
	// This is a shortcut for ValidateTenantPermissions(token, "", permissions)
	ValidatePermissions(ctx context.Context, token *descope.Token, permissions []string) bool

	// GetMatchedPermissions - Use toeRetrieves the permissions from top level token's claims
	// that match the specified permissions list
	GetMatchedPermissions(ctx context.Context, token *descope.Token, permissions []string) []string

	// ValidateTenantPermissions - Use to ensure that a validated session token has been
	// granted the specified permissions for a specific tenant.
	ValidateTenantPermissions(ctx context.Context, token *descope.Token, tenant string, permissions []string) bool

	// GetMatchedTenantPermissions - Use to retrieve the permissions token's claims of a specific tenant
	// that match the specified permissions list
	GetMatchedTenantPermissions(ctx context.Context, token *descope.Token, tenant string, permissions []string) []string

	// ValidateRoles - Use to ensure that a validated session token has been granted the
	// specified roles.
	// This is a shortcut for ValidateTenantRoles(token, "", roles)
	ValidateRoles(ctx context.Context, token *descope.Token, roles []string) bool

	// GetMatchedRoles - Use to retrieve the roles token's claims that match the specified roles list
	GetMatchedRoles(ctx context.Context, token *descope.Token, roles []string) []string

	// ValidateTenantRoles - Use to ensure that a validated session token has been granted
	// the specified roles for a specific tenant.
	ValidateTenantRoles(ctx context.Context, token *descope.Token, tenant string, roles []string) bool

	// GetMatchedTenantRoles - Use to retrieve the roles token's claims of a specific tenant
	// that match the specified roles list
	GetMatchedTenantRoles(ctx context.Context, token *descope.Token, tenant string, roles []string) []string

	// SelectTenantWithRequest - Adds a dedicated claim to the JWTs to indicate the tenant on which the user is currently authenticated
	SelectTenantWithRequest(ctx context.Context, tenantID string, request *http.Request, w http.ResponseWriter) (*descope.AuthenticationInfo, error)

	// SelectTenantWithToken - Adds a dedicated claim to the JWTs to indicate the tenant on which the user is currently authenticated
	SelectTenantWithToken(ctx context.Context, tenantID string, refreshToken string) (*descope.AuthenticationInfo, error)

	// Logout - Logs out from the current session and deletes the session and refresh cookies in the http response.
	// Use the ResponseWriter (optional) to apply the cookies to the response automatically.
	Logout(request *http.Request, w http.ResponseWriter) error

	// LogoutAll - Use to perform logout from all active sessions for the request user. This will revoke the given tokens
	// and if given options will also remove existing session on the given response sent to the client.
	// Use the ResponseWriter (optional) to apply the cookies to the response automatically.
	LogoutAll(request *http.Request, w http.ResponseWriter) error

	// Me - Use to retrieve current session user details. The request requires a valid refresh token.
	// returns the user details or error if the refresh token is not valid.
	Me(request *http.Request) (*descope.UserResponse, error)

	// History - Use to retrieve current session user history. The request requires a valid refresh token.
	// returns the user authentication history or error if the refresh token is not valid.
	History(request *http.Request) ([]*descope.UserHistoryResponse, error)
}
