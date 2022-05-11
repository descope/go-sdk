package auth

import (
	"fmt"
	"regexp"
)

const (
	defaultURI = "http://localhost:8080"
)

type iClient interface {
	post(path string, body interface{}) ([]byte, *WebError)
}

type LoggerInterface interface {
	Print(v ...interface{})
}

// Configuration struct describes the configurational data for the authentication methods.
type Config struct {
	ProjectID string
	PublicKey string

	LogLevel LogLevel
	Logger   LoggerInterface
}

func (c *Config) doLog(l LogLevel, format string, args ...interface{}) {
	if c.LogLevel < l {
		return
	}
	c.Logger.Print(fmt.Printf(format, args...))
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
	SignInEmail(email string) *WebError
	SignInSMS(phone string) *WebError
	SignInWhatsapp(phone string) *WebError

	SignUpEmail(email string, user *User) *WebError
	SignUpSMS(phone string, user *User) *WebError
	SignUpWhatsapp(phone string, user *User) *WebError

	VerifyCodeEmail(identifier string, code string) *WebError
	VerifyCodeSMS(identifier string, code string) *WebError
	VerifyCodeWhatsapp(identifier string, code string) *WebError
}

type Method string

const (
	methodWhatsapp Method = "whatsapp"
	methodPhone    Method = "phone"
	methodEmail    Method = "email"

	signInOTPPath  = "/v1/auth/signin/otp/"
	signUpOTPPath  = "/v1/auth/signup/otp/"
	verifyCodePath = "v1/auth/code/verify/"
)

var (
	phoneRegex = regexp.MustCompile(`^(?:(?:\(?(?:00|\+)([1-4]\d\d|[1-9]\d?)\)?)?[\-\.\ \\\/]?)?((?:\(?\d{1,}\)?[\-\.\ \\\/]?){0,})(?:[\-\.\ \\\/]?(?:#|ext\.?|extension|x)[\-\.\ \\\/]?(\d+))?$`)
	emailRegex = regexp.MustCompile("^(((([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+(\\.([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+)*)|((\\x22)((((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x21|[\\x23-\\x5b]|[\\x5d-\\x7e]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(\\([\\x01-\\x09\\x0b\\x0c\\x0d-\\x7f]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}]))))*(((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(\\x22)))@((([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])([a-zA-Z]|\\d|-|\\.|_|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.)+(([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])([a-zA-Z]|\\d|-|_|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.?$")
)
