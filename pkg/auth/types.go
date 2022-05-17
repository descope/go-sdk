package auth

import (
	"fmt"
	"log"
	"net/http"
	"regexp"
)

const (
	defaultURL = "https://descope.com"
)

type Do func(r *http.Request) (*http.Response, error)

type IHttpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type LoggerInterface interface {
	Print(v ...interface{})
}

func (c *Config) doLog(l LogLevel, format string, args ...interface{}) {
	if c.LogLevel < l {
		return
	}
	if c.Logger == nil {
		c.Logger = log.Default()
	}
	c.Logger.Print(fmt.Sprintf(format, args...))
}

func (c *Config) LogDebug(format string, args ...interface{}) {
	c.doLog(LogDebug, format, args...)
}

func (c *Config) LogInfo(format string, args ...interface{}) {
	c.doLog(LogInfo, format, args...)
}

func (c *Config) setProjectID() string {
	if c.ProjectID == "" {
		if projectID := GetProjectIDEnvVariable(); projectID != "" {
			c.ProjectID = projectID
		} else {
			return ""
		}
	}
	return c.ProjectID
}

func (c *Config) setPublicKey() string {
	if c.PublicKey == "" {
		if publicKey := GetPublicKeyEnvVariable(); publicKey != "" {
			c.PublicKey = publicKey
		} else {
			return ""
		}
	}
	return c.PublicKey
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

type DeliveryMethod string

type authenticationRequestBody struct {
	WhatsApp string `json:"whatsapp,omitempty"`
	Phone    string `json:"phone,omitempty"`
	Email    string `json:"email,omitempty"`
}

type authenticationSignInRequestBody struct {
	authenticationRequestBody `json:",inline"`
	User                      *User `json:"user"`
}

type authenticationVerifyRequestBody struct {
	authenticationRequestBody `json:",inline"`
	Code                      string `json:"code"`
}

func newAuthenticationRequestBody(method DeliveryMethod, value string) authenticationRequestBody {
	switch method {
	case MethodSMS:
		return authenticationRequestBody{Phone: value}
	case MethodWhatsApp:
		return authenticationRequestBody{WhatsApp: value}
	}

	return authenticationRequestBody{Email: value}
}

func newAuthenticationSignInRequestBody(method DeliveryMethod, value string, user *User) authenticationSignInRequestBody {
	a := newAuthenticationRequestBody(method, value)
	return authenticationSignInRequestBody{authenticationRequestBody: a, User: user}
}

func newAuthenticationVerifyRequestBody(method DeliveryMethod, value string, code string) authenticationVerifyRequestBody {
	a := newAuthenticationRequestBody(method, value)
	return authenticationVerifyRequestBody{authenticationRequestBody: a, Code: code}
}

const (
	MethodWhatsApp DeliveryMethod = "whatsapp"
	MethodSMS      DeliveryMethod = "phone"
	MethodEmail    DeliveryMethod = "email"

	signInOTPPath  = "/v1/auth/signin/otp"
	signUpOTPPath  = "/v1/auth/signup/otp"
	verifyCodePath = "/v1/auth/code/verify"

	publicKeyPath = "/v1/keys/"

	environmentVariablePublicKey = "DESCOPE_PUBLIC_KEY"
	environmentVariableProjectID = "DESCOPE_PROJECT_ID"

	contextProjectID = "project_id"

	CookieDefaultName = "S"
)

var (
	phoneRegex = regexp.MustCompile(`^(?:(?:\(?(?:00|\+)([1-4]\d\d|[1-9]\d?)\)?)?[\-\.\ \\\/]?)?((?:\(?\d{1,}\)?[\-\.\ \\\/]?){0,})(?:[\-\.\ \\\/]?(?:#|ext\.?|extension|x)[\-\.\ \\\/]?(\d+))?$`)
	emailRegex = regexp.MustCompile("^(((([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+(\\.([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+)*)|((\\x22)((((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x21|[\\x23-\\x5b]|[\\x5d-\\x7e]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(\\([\\x01-\\x09\\x0b\\x0c\\x0d-\\x7f]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}]))))*(((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(\\x22)))@((([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])([a-zA-Z]|\\d|-|\\.|_|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.)+(([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])([a-zA-Z]|\\d|-|_|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.?$")
)
