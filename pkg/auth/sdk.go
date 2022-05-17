package auth

import "net/http"

type IAuth interface {
	// SignInOTP - use to login a user based on the given identifier either email or a phone
	// and choose the selected delivery method for verification.
	// returns an error upon failure.
	SignInOTP(method DeliveryMethod, identifier string) error
	// SignUpOTP - use to create a new user based on the given identifier either email or a phone
	// and choose the selected delivery method for verification.
	// optional to add user metadata for farther user details such as name and more.
	// returns an error upon failure.
	SignUpOTP(method DeliveryMethod, identifier string, user *User) error

	// VerifyCode - Use to verify a SignIn/SignUp based on the given identifier either an email or a phone
	// followed by the code used to verify and authenticate the user.
	// returns a list of set-cookie data or an error upon failure.
	VerifyCode(method DeliveryMethod, identifier string, code string) ([]*http.Cookie, error)
	// VerifyCodeEmail - Use to verify a SignIn/SignUp based on the email identifier
	// followed by the code used to verify and authenticate the user.
	// returns a list of set-cookie data or an error upon failure.
	VerifyCodeEmail(identifier string, code string) ([]*http.Cookie, error)
	// VerifyCodeSMS - Use to verify a SignIn/SignUp based on the phone identifier
	// followed by the code used to verify and authenticate the user.
	// returns a list of set-cookie data or an error upon failure.
	VerifyCodeSMS(identifier string, code string) ([]*http.Cookie, error)
	// VerifyCodeWhatsApp - Use to verify a SignIn/SignUp based on the phone identifier
	// followed by the code used to verify and authenticate the user.
	// returns a list of set-cookie data or an error upon failure.
	VerifyCodeWhatsApp(identifier string, code string) ([]*http.Cookie, error)

	// ValidateSessionRequest - Use to validate a session of a given request.
	// Should be called before any private API call that requires authorization.
	// returns true upon success or false and/or error upon failure.
	ValidateSessionRequest(request *http.Request) (bool, error)
	// ValidateSession - Use to validate a given token.
	// Should be called before any private API call that requires authorization.
	// returns true upon success or false and/or error upon failure.
	ValidateSession(token string) (bool, error)
}

// Conf - Configuration struct describes the configurational data for the authentication methods.
type Config struct {
	// ProjectID (required, "") - used to validate and authenticate against descope services.
	ProjectID string
	// PublicKey (optional, "") - used to override or implicitly use a dedicated public key in order to decrypt and validate the JWT tokens
	// during ValidateSession() and ValidateSessionRequest(). If empty, will attempt to fetch all public keys from the specified project id.
	PublicKey string

	// DefaultURL (optional, "https://descope.com") - override the default base URL used to communicate with descope services.
	DefaultURL string
	// DefaultClient (optional, http.DefaultClient) - override the default client used to Do the actual http request.
	DefaultClient IHttpClient
	// CustomDefaultHeaders (optional, nil) - add custom headers to all requests used to communicate with descope services.
	CustomDefaultHeaders map[string]string

	// LogLevel (optional, LogNone) - set a log level (Debug/Info/None) for the sdk to use when logging.
	LogLevel LogLevel
	// LoggerInterface (optional, log.Default()) - set the logger instance to use for logging with the sdk.
	Logger LoggerInterface
}
