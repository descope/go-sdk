package auth

import (
	"net/http"
	"regexp"
	"time"

	"github.com/descope/go-sdk/descope/logger"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type AuthenticationInfo struct {
	SessionToken *Token
}

type Token struct {
	Expiration time.Time
	JWT        string
	ID         string
	Subject    string
	Claims     map[string]interface{}
}

func NewAuthenticationInfo(token *Token) *AuthenticationInfo {
	return &AuthenticationInfo{SessionToken: token}
}

// WithResponseOption - adds a response option to supported functions to allow
// automatic apply and renewal of the tokens to the response sent to the client.
func WithResponseOption(w http.ResponseWriter) Option {
	return newOption(responseOption{}, w)
}

type Option interface {
	Kind() interface{}
	Value() interface{}
}

type pair struct {
	kind  interface{}
	value interface{}
}

func (p *pair) Kind() interface{} {
	return p.kind
}

func (p *pair) Value() interface{} {
	return p.value
}

func newOption(kind, value interface{}) Option {
	return &pair{
		kind:  kind,
		value: value,
	}
}

type Options []Option

func (options Options) SetCookies(cookies []*http.Cookie) {
	for _, option := range options {
		if option != nil {
			switch option.Kind().(type) {
			case responseOption:
				val := option.Value()
				if val != nil {
					if w, ok := val.(http.ResponseWriter); ok {
						for i := range cookies {
							http.SetCookie(w, cookies[i])
						}
					} else {
						logger.LogDebug("Unexpected option value [%T]", val)
					}
				}
			}
		}
	}
}

type responseOption struct{}

func NewToken(JWT string, token jwt.Token) *Token {
	if token == nil {
		return nil
	}

	return &Token{
		JWT:        JWT,
		ID:         token.Issuer(),
		Subject:    token.Subject(),
		Expiration: token.Expiration(),
		Claims:     token.PrivateClaims(),
	}
}

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

type magicLinkAuthenticationRequestBody struct {
	WhatsApp string `json:"whatsapp,omitempty"`
	Phone    string `json:"phone,omitempty"`
	Email    string `json:"email,omitempty"`
	URI      string `json:"uri,omitempty"`
}

type magicLinkAuthenticationSignInRequestBody struct {
	magicLinkAuthenticationRequestBody `json:",inline"`
	User                               *User `json:"user"`
}

type magicLinkAuthenticationVerifyRequestBody struct {
	Token string `json:"token"`
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

func newMagicLinkAuthenticationRequestBody(method DeliveryMethod, value, URI string) magicLinkAuthenticationRequestBody {
	switch method {
	case MethodSMS:
		return magicLinkAuthenticationRequestBody{Phone: value, URI: URI}
	case MethodWhatsApp:
		return magicLinkAuthenticationRequestBody{WhatsApp: value, URI: URI}
	}

	return magicLinkAuthenticationRequestBody{Email: value, URI: URI}
}

func newMagicLinkAuthenticationSignUpRequestBody(method DeliveryMethod, value, URI string, user *User) magicLinkAuthenticationSignInRequestBody {
	b := newMagicLinkAuthenticationRequestBody(method, value, URI)
	return magicLinkAuthenticationSignInRequestBody{magicLinkAuthenticationRequestBody: b, User: user}
}

func newMagicLinkAuthenticationVerifyRequestBody(code string) magicLinkAuthenticationVerifyRequestBody {
	return magicLinkAuthenticationVerifyRequestBody{Token: code}
}

func newAuthenticationSignUpRequestBody(method DeliveryMethod, value string, user *User) authenticationSignInRequestBody {
	b := newAuthenticationRequestBody(method, value)
	return authenticationSignInRequestBody{authenticationRequestBody: b, User: user}
}

func newAuthenticationVerifyRequestBody(method DeliveryMethod, value string, code string) authenticationVerifyRequestBody {
	b := newAuthenticationRequestBody(method, value)
	return authenticationVerifyRequestBody{authenticationRequestBody: b, Code: code}
}

const (
	MethodWhatsApp DeliveryMethod = "whatsapp"
	MethodSMS      DeliveryMethod = "sms"
	MethodEmail    DeliveryMethod = "email"

	SessionCookieName = "DS"
	RefreshCookieName = "DSR"
)

var (
	phoneRegex = regexp.MustCompile(`^(?:(?:\(?(?:00|\+)([1-4]\d\d|[1-9]\d?)\)?)?[\-\.\ \\\/]?)?((?:\(?\d{1,}\)?[\-\.\ \\\/]?){0,})(?:[\-\.\ \\\/]?(?:#|ext\.?|extension|x)[\-\.\ \\\/]?(\d+))?$`)
	emailRegex = regexp.MustCompile("^(((([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+(\\.([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+)*)|((\\x22)((((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x21|[\\x23-\\x5b]|[\\x5d-\\x7e]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(\\([\\x01-\\x09\\x0b\\x0c\\x0d-\\x7f]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}]))))*(((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(\\x22)))@((([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])([a-zA-Z]|\\d|-|\\.|_|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.)+(([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])([a-zA-Z]|\\d|-|_|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.?$")
)
