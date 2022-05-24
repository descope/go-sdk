package auth

import (
	"net/http"
	"regexp"
)

type IJWTProvider interface {
	ProvideTokens() (string, string)
}

type requestJWTProvider struct {
	r *http.Request
}

var RequestJWTProvider = func(r *http.Request) *requestJWTProvider {
	return &requestJWTProvider{r: r}
}

func (p *requestJWTProvider) ProvideTokens() (sessionToken string, refreshToken string) {
	if sessionCookie, _ := p.r.Cookie(SessionCookieName); sessionCookie != nil {
		sessionToken = sessionCookie.Value
	}

	refreshCookie, err := p.r.Cookie(RefreshCookieName)
	if err != nil {
		return sessionToken, ""
	}
	return sessionToken, refreshCookie.Value
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
		switch option.Kind().(type) {
		case responseOption:
			w := option.Value().(http.ResponseWriter)
			for i := range cookies {
				http.SetCookie(w, cookies[i])
			}
		}
	}
}

type responseOption struct{}

// WithResponseOption - adds a response option to supported functions to allow
// automatic apply and renewal of the tokens to the response sent to the client.
func WithResponseOption(w http.ResponseWriter) Option {
	return newOption(responseOption{}, w)
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

func newAuthenticationRequestBody(method DeliveryMethod, value string) authenticationRequestBody {
	switch method {
	case MethodSMS:
		return authenticationRequestBody{Phone: value}
	case MethodWhatsApp:
		return authenticationRequestBody{WhatsApp: value}
	}

	return authenticationRequestBody{Email: value}
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

	signInV1AuthOTPPath  = "/v1/auth/signin/otp"
	signUpV1AuthOTPPath  = "/v1/auth/signup/otp"
	verifyCodeV1AuthPath = "/v1/auth/code/verify"
	logoutV1AuthPath     = "/v1/logoutall"

	publicKeyV1Path    = "/v1/keys/"
	refreshTokenV1Path = "/v1/refresh"

	SessionCookieName = "DS"
	RefreshCookieName = "DSR"
)

var (
	phoneRegex = regexp.MustCompile(`^(?:(?:\(?(?:00|\+)([1-4]\d\d|[1-9]\d?)\)?)?[\-\.\ \\\/]?)?((?:\(?\d{1,}\)?[\-\.\ \\\/]?){0,})(?:[\-\.\ \\\/]?(?:#|ext\.?|extension|x)[\-\.\ \\\/]?(\d+))?$`)
	emailRegex = regexp.MustCompile("^(((([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+(\\.([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+)*)|((\\x22)((((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x21|[\\x23-\\x5b]|[\\x5d-\\x7e]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(\\([\\x01-\\x09\\x0b\\x0c\\x0d-\\x7f]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}]))))*(((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(\\x22)))@((([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])([a-zA-Z]|\\d|-|\\.|_|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.)+(([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])([a-zA-Z]|\\d|-|_|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.?$")
)
