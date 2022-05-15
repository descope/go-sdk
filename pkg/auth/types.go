package auth

import (
	"fmt"
	"net/http"
	"regexp"
)

const (
	defaultURL = "http://localhost:8080"
)

type Do func(r *http.Request) (*http.Response, error)

type IHttpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type LoggerInterface interface {
	Print(v ...interface{})
}

// Configuration struct describes the configurational data for the authentication methods.
type Config struct {
	ProjectID string
	PublicKey string

	DefaultURL           string
	DefaultClient        IHttpClient
	CustomDefaultHeaders map[string]string

	LogLevel LogLevel
	Logger   LoggerInterface
}

func (c *Config) doLog(l LogLevel, format string, args ...interface{}) {
	if c.LogLevel < l {
		return
	}
	c.Logger.Print(fmt.Sprintf(format, args...))
}

func (c *Config) LogDebug(format string, args ...interface{}) {
	c.doLog(LogDebug, format, args...)
}

func (c *Config) LogInfo(format string, args ...interface{}) {
	c.doLog(LogInfo, format, args...)
}

type LogLevel uint

const (
	LogNone  LogLevel = iota
	LogInfo  LogLevel = 1
	LogDebug LogLevel = 2
)

type User struct {
	Username string `json:"username,omitempty"`
	Name     string `json:"name,omitempty"`
	Phone    string `json:"phone,omitempty"`
	Email    string `json:"email,omitempty"`
}

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

type DeliveryMethod string

const (
	MethodWhatsApp DeliveryMethod = "whatsapp"
	MethodSMS      DeliveryMethod = "phone"
	MethodEmail    DeliveryMethod = "email"

	CookieDefaultName = "S"

	signInOTPPath  = "/v1/auth/signin/otp"
	signUpOTPPath  = "/v1/auth/signup/otp"
	verifyCodePath = "/v1/auth/code/verify"
)

var (
	phoneRegex = regexp.MustCompile(`^(?:(?:\(?(?:00|\+)([1-4]\d\d|[1-9]\d?)\)?)?[\-\.\ \\\/]?)?((?:\(?\d{1,}\)?[\-\.\ \\\/]?){0,})(?:[\-\.\ \\\/]?(?:#|ext\.?|extension|x)[\-\.\ \\\/]?(\d+))?$`)
	emailRegex = regexp.MustCompile("^(((([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+(\\.([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+)*)|((\\x22)((((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x21|[\\x23-\\x5b]|[\\x5d-\\x7e]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(\\([\\x01-\\x09\\x0b\\x0c\\x0d-\\x7f]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}]))))*(((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(\\x22)))@((([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])([a-zA-Z]|\\d|-|\\.|_|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.)+(([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])([a-zA-Z]|\\d|-|_|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.?$")
)
