package auth

import (
	"net/http"
	"regexp"

	"github.com/descope/go-sdk/descope/logger"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type AuthenticationInfo struct {
	SessionToken *Token `json:"token,omitempty"`
	User         *User  `json:"user,omitempty"`
	FirstSeen    bool   `json:"firstSeen,omitempty"`
}

type WebAuthnTransactionResponse struct {
	TransactionID string `json:"transactionId,omitempty"`
	Options       string `json:"options,omitempty"`
}

type WebAuthnFinishRequest struct {
	TransactionID string `json:"transactionID,omitempty"`
	Response      string `json:"response,omitempty"`
}

type Token struct {
	Expiration int64                  `json:"expiration,omitempty"`
	JWT        string                 `json:"jwt,omitempty"`
	ID         string                 `json:"id,omitempty"`
	Subject    string                 `json:"subject,omitempty"`
	Claims     map[string]interface{} `json:"claims,omitempty"`
}
type JWTResponse struct {
	JWTS      []string `json:"jwts,omitempty"`
	User      *User    `json:"user,omitempty"`
	FirstSeen bool     `json:"firstSeen,omitempty"`
}

type MagicLinkResponse struct {
	PendingRef string `json:"pendingRef,omitempty"` // Pending referral code used to poll magic link authentication status
}

func NewAuthenticationInfo(jRes *JWTResponse, token *Token) *AuthenticationInfo {
	if jRes == nil {
		jRes = &JWTResponse{}
	}
	return &AuthenticationInfo{SessionToken: token, User: jRes.User, FirstSeen: jRes.FirstSeen}
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

func (options Options) CopyResponse(res *http.Response, body string) {
	for _, option := range options {
		if option != nil {
			switch option.Kind().(type) {
			case responseOption:
				val := option.Value()
				if val != nil {
					if w, ok := val.(http.ResponseWriter); ok {
						for key, header := range res.Header.Clone() {
							for i := range header {
								w.Header().Set(key, header[i])
							}
						}
						w.WriteHeader(res.StatusCode)
						w.Write([]byte(body))
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
		Expiration: token.Expiration().Unix(),
		Claims:     token.PrivateClaims(),
	}
}

type User struct {
	Name          string `json:"name,omitempty"`
	Phone         string `json:"phone,omitempty"`
	Email         string `json:"email,omitempty"`
	ExternalID    string `json:"externalID,omitempty"`
	VerifiedEmail bool   `json:"verifiedEmail,omitempty"`
	VerifiedPhone bool   `json:"verifiedPhone,omitempty"`
}

type authenticationRequestBody struct {
	ExternalID string `json:"externalID,omitempty"`
}

type authenticationSignUpRequestBody struct {
	WhatsApp string `json:"whatsapp,omitempty"`
	Phone    string `json:"phone,omitempty"`
	Email    string `json:"email,omitempty"`
	User     *User  `json:"user"`
}

type authenticationWebAuthnSignUpRequestBody struct {
	User *User `json:"user"`
}

type authenticationVerifyRequestBody struct {
	*authenticationRequestBody `json:",inline"`
	Code                       string `json:"code"`
}

type otpUpdateEmailRequestBody struct {
	ExternalID string `json:"externalID,omitempty"`
	Email      string `json:"email,omitempty"`
}

type otpUpdatePhoneRequestBody struct {
	ExternalID string `json:"externalID,omitempty"`
	Phone      string `json:"phone,omitempty"`
}

type magicLinkAuthenticationRequestBody struct {
	*authenticationRequestBody `json:",inline"`
	URI                        string `json:"URI,omitempty"`
	CrossDevice                bool   `json:"crossDevice,omitempty"`
}

type magicLinkAuthenticationSignUpRequestBody struct {
	*authenticationSignUpRequestBody `json:",inline"`
	URI                              string `json:"URI,omitempty"`
	CrossDevice                      bool   `json:"crossDevice,omitempty"`
}

type magicLinkUpdateEmailRequestBody struct {
	Email       string `json:"email,inline"`
	ExternalID  string `json:"externalID,inline"`
	URI         string `json:"URI,omitempty"`
	CrossDevice bool   `json:"crossDevice,omitempty"`
}

type magicLinkUpdatePhoneRequestBody struct {
	Phone       string `json:"phone,inline"`
	ExternalID  string `json:"externalID,inline"`
	URI         string `json:"URI,omitempty"`
	CrossDevice bool   `json:"crossDevice,omitempty"`
}

type magicLinkAuthenticationVerifyRequestBody struct {
	Token string `json:"token"`
}

type authenticationGetMagicLinkSessionBody struct {
	PendingRef string `json:"pendingRef"`
}

type exchangeTokenRequestBody struct {
	Code string `json:"code"`
}

func newSignInRequestBody(externalID string) *authenticationRequestBody {
	return &authenticationRequestBody{ExternalID: externalID}
}

func newSignUpRequestBody(method DeliveryMethod, value string) *authenticationSignUpRequestBody {
	switch method {
	case MethodSMS:
		return &authenticationSignUpRequestBody{Phone: value}
	case MethodWhatsApp:
		return &authenticationSignUpRequestBody{WhatsApp: value}
	}

	return &authenticationSignUpRequestBody{Email: value}
}

func newOTPUpdateEmailRequestBody(externalID, email string) *otpUpdateEmailRequestBody {
	return &otpUpdateEmailRequestBody{ExternalID: externalID, Email: email}
}

func newOTPUpdatePhoneRequestBody(externalID, phone string) *otpUpdatePhoneRequestBody {
	return &otpUpdatePhoneRequestBody{ExternalID: externalID, Phone: phone}
}

func newMagicLinkAuthenticationRequestBody(value, URI string, crossDevice bool) *magicLinkAuthenticationRequestBody {
	return &magicLinkAuthenticationRequestBody{authenticationRequestBody: newSignInRequestBody(value), URI: URI, CrossDevice: crossDevice}
}

func newMagicLinkAuthenticationSignUpRequestBody(method DeliveryMethod, value, URI string, user *User, crossDevice bool) *magicLinkAuthenticationSignUpRequestBody {
	b := newSignUpRequestBody(method, value)
	b.User = user
	return &magicLinkAuthenticationSignUpRequestBody{authenticationSignUpRequestBody: b, CrossDevice: crossDevice, URI: URI}
}

func newMagicLinkAuthenticationVerifyRequestBody(token string) *magicLinkAuthenticationVerifyRequestBody {
	return &magicLinkAuthenticationVerifyRequestBody{Token: token}
}

func newAuthenticationSignUpRequestBody(method DeliveryMethod, value string, user *User) *authenticationSignUpRequestBody {
	b := newSignUpRequestBody(method, value)
	b.User = user
	return b
}

func newAuthenticationVerifyRequestBody(value string, code string) *authenticationVerifyRequestBody {
	return &authenticationVerifyRequestBody{authenticationRequestBody: newSignInRequestBody(value), Code: code}
}

func newMagicLinkUpdateEmailRequestBody(externalID, email string, URI string, crossDevice bool) *magicLinkUpdateEmailRequestBody {
	return &magicLinkUpdateEmailRequestBody{ExternalID: externalID, Email: email, URI: URI, CrossDevice: crossDevice}
}

func newMagicLinkUpdatePhoneRequestBody(externalID, phone string, URI string, crossDevice bool) *magicLinkUpdatePhoneRequestBody {
	return &magicLinkUpdatePhoneRequestBody{ExternalID: externalID, Phone: phone, URI: URI, CrossDevice: crossDevice}
}

func newAuthenticationGetMagicLinkSessionBody(pendingRef string) *authenticationGetMagicLinkSessionBody {
	return &authenticationGetMagicLinkSessionBody{PendingRef: pendingRef}
}

func newExchangeTokenRequest(code string) *exchangeTokenRequestBody {
	return &exchangeTokenRequestBody{Code: code}
}

type DeliveryMethod string

type OAuthProvider string

type ContextKey string

const (
	MethodWhatsApp DeliveryMethod = "whatsapp"
	MethodSMS      DeliveryMethod = "sms"
	MethodEmail    DeliveryMethod = "email"

	OAuthFacebook  OAuthProvider = "facebook"
	OAuthGithub    OAuthProvider = "github"
	OAuthGoogle    OAuthProvider = "google"
	OAuthMicrosoft OAuthProvider = "microsoft"
	OAuthGitlab    OAuthProvider = "gitlab"
	OAuthApple     OAuthProvider = "apple"

	SessionCookieName = "DS"
	RefreshCookieName = "DSR"

	RedirectLocationCookieName = "Location"

	ContextUserIDProperty               = "DESCOPE_USER_ID"
	ContextUserIDPropertyKey ContextKey = ContextUserIDProperty
)

var (
	phoneRegex = regexp.MustCompile(`^(?:(?:\(?(?:00|\+)([1-4]\d\d|[1-9]\d?)\)?)?[\-\.\ \\\/]?)?((?:\(?\d{1,}\)?[\-\.\ \\\/]?){0,})(?:[\-\.\ \\\/]?(?:#|ext\.?|extension|x)[\-\.\ \\\/]?(\d+))?$`)
	emailRegex = regexp.MustCompile("^(((([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+(\\.([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+)*)|((\\x22)((((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x21|[\\x23-\\x5b]|[\\x5d-\\x7e]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(\\([\\x01-\\x09\\x0b\\x0c\\x0d-\\x7f]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}]))))*(((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(\\x22)))@((([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])([a-zA-Z]|\\d|-|\\.|_|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.)+(([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])([a-zA-Z]|\\d|-|_|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.?$")
)
