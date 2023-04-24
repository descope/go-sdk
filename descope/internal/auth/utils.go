package auth

import (
	"regexp"

	"github.com/descope/go-sdk/descope"
)

type authenticationRequestBody struct {
	LoginID      string                `json:"loginId,omitempty"`
	LoginOptions *descope.LoginOptions `json:"loginOptions,omitempty"`
}

type authenticationSignUpRequestBody struct {
	WhatsApp string        `json:"whatsapp,omitempty"`
	Phone    string        `json:"phone,omitempty"`
	Email    string        `json:"email,omitempty"`
	LoginID  string        `json:"loginId,omitempty"`
	User     *descope.User `json:"user"`
}

type authenticationWebAuthnSignUpRequestBody struct {
	LoginID string        `json:"loginId,omitempty"`
	Origin  string        `json:"origin"`
	User    *descope.User `json:"user"`
}

type authenticationWebAuthnSignInRequestBody struct {
	LoginID      string                `json:"loginId,omitempty"`
	Origin       string                `json:"origin"`
	LoginOptions *descope.LoginOptions `json:"loginOptions,omitempty"`
}

type authenticationWebAuthnAddDeviceRequestBody struct {
	LoginID string `json:"loginId,omitempty"`
	Origin  string `json:"origin"`
}

type authenticationPasswordSignUpRequestBody struct {
	LoginID  string        `json:"loginId,omitempty"`
	Password string        `json:"password"`
	User     *descope.User `json:"user"`
}

type authenticationPasswordSignInRequestBody struct {
	LoginID  string `json:"loginId,omitempty"`
	Password string `json:"password"`
}

type authenticationPasswordResetRequestBody struct {
	LoginID     string `json:"loginId,omitempty"`
	RedirectURL string `json:"redirectUrl,omitempty"`
}

type authenticationPasswordUpdateRequestBody struct {
	LoginID     string `json:"loginId,omitempty"`
	NewPassword string `json:"newPassword,omitempty"`
}

type authenticationPasswordReplaceRequestBody struct {
	LoginID     string `json:"loginId,omitempty"`
	OldPassword string `json:"oldPassword,omitempty"`
	NewPassword string `json:"newPassword,omitempty"`
}

type authenticationVerifyRequestBody struct {
	*authenticationRequestBody `json:",inline"`
	Code                       string `json:"code"`
}

type authenticationVerifyTOTPRequestBody struct {
	*authenticationVerifyRequestBody `json:",inline"`
	LoginOptions                     *descope.LoginOptions `json:"loginOptions,omitempty"`
}

type totpSignUpRequestBody struct {
	LoginID string        `json:"loginId,omitempty"`
	User    *descope.User `json:"user,omitempty"`
}

type otpUpdateEmailRequestBody struct {
	*descope.UpdateOptions `json:",inline"`
	LoginID                string `json:"loginId,omitempty"`
	Email                  string `json:"email,omitempty"`
}

type otpUpdatePhoneRequestBody struct {
	*descope.UpdateOptions `json:",inline"`
	LoginID                string `json:"loginId,omitempty"`
	Phone                  string `json:"phone,omitempty"`
}

type magicLinkAuthenticationRequestBody struct {
	*authenticationRequestBody `json:",inline"`
	URI                        string                `json:"URI,omitempty"`
	CrossDevice                bool                  `json:"crossDevice,omitempty"`
	LoginOptions               *descope.LoginOptions `json:"loginOptions,omitempty"`
}

type magicLinkAuthenticationSignUpRequestBody struct {
	*authenticationSignUpRequestBody `json:",inline"`
	URI                              string `json:"URI,omitempty"`
	CrossDevice                      bool   `json:"crossDevice,omitempty"`
}

type magicLinkUpdateEmailRequestBody struct {
	*descope.UpdateOptions `json:",inline"`
	Email                  string `json:"email,inline"`
	LoginID                string `json:"loginId,inline"`
	URI                    string `json:"URI,omitempty"`
	CrossDevice            bool   `json:"crossDevice,omitempty"`
}

type magicLinkUpdatePhoneRequestBody struct {
	*descope.UpdateOptions `json:",inline"`
	Phone                  string `json:"phone,inline"`
	LoginID                string `json:"loginId,inline"`
	URI                    string `json:"URI,omitempty"`
	CrossDevice            bool   `json:"crossDevice,omitempty"`
}

type magicLinkAuthenticationVerifyRequestBody struct {
	Token string `json:"token"`
}

type authenticationGetMagicLinkSessionBody struct {
	PendingRef string `json:"pendingRef"`
}

type exchangeTokenBody struct {
	Code string `json:"code"`
}

func newSignInRequestBody(loginID string, loginOptions *descope.LoginOptions) *authenticationRequestBody {
	return &authenticationRequestBody{LoginID: loginID, LoginOptions: loginOptions}
}

func newSignUpRequestBody(method descope.DeliveryMethod, user *descope.User) *authenticationSignUpRequestBody {
	switch method {
	case descope.MethodSMS:
		return &authenticationSignUpRequestBody{Phone: user.Phone}
	case descope.MethodWhatsApp:
		return &authenticationSignUpRequestBody{WhatsApp: user.Phone}
	}

	return &authenticationSignUpRequestBody{Email: user.Email}
}

func newSignUPTOTPRequestBody(loginID string, user *descope.User) *totpSignUpRequestBody {
	return &totpSignUpRequestBody{LoginID: loginID, User: user}
}

func newOTPUpdateEmailRequestBody(loginID, email string, updateOptions *descope.UpdateOptions) *otpUpdateEmailRequestBody {
	return &otpUpdateEmailRequestBody{LoginID: loginID, Email: email, UpdateOptions: updateOptions}
}

func newOTPUpdatePhoneRequestBody(loginID, phone string, updateOptions *descope.UpdateOptions) *otpUpdatePhoneRequestBody {
	return &otpUpdatePhoneRequestBody{LoginID: loginID, Phone: phone, UpdateOptions: updateOptions}
}

func newMagicLinkAuthenticationRequestBody(value, URI string, crossDevice bool, loginOptions *descope.LoginOptions) *magicLinkAuthenticationRequestBody {
	return &magicLinkAuthenticationRequestBody{authenticationRequestBody: newSignInRequestBody(value, loginOptions), URI: URI, CrossDevice: crossDevice, LoginOptions: loginOptions}
}

func newMagicLinkAuthenticationSignUpRequestBody(method descope.DeliveryMethod, loginID, URI string, user *descope.User, crossDevice bool) *magicLinkAuthenticationSignUpRequestBody {
	b := newSignUpRequestBody(method, user)
	b.User = user
	b.LoginID = loginID
	return &magicLinkAuthenticationSignUpRequestBody{authenticationSignUpRequestBody: b, CrossDevice: crossDevice, URI: URI}
}

func newMagicLinkAuthenticationVerifyRequestBody(token string) *magicLinkAuthenticationVerifyRequestBody {
	return &magicLinkAuthenticationVerifyRequestBody{Token: token}
}

func newAuthenticationSignUpRequestBody(method descope.DeliveryMethod, loginID string, user *descope.User) *authenticationSignUpRequestBody {
	b := newSignUpRequestBody(method, user)
	b.User = user
	b.LoginID = loginID
	return b
}

func newAuthenticationVerifyRequestBody(value string, code string) *authenticationVerifyRequestBody {
	return &authenticationVerifyRequestBody{authenticationRequestBody: newSignInRequestBody(value, nil), Code: code}
}

func newAuthenticationVerifyTOTPRequestBody(value string, code string, loginOptions *descope.LoginOptions) *authenticationVerifyTOTPRequestBody {
	return &authenticationVerifyTOTPRequestBody{authenticationVerifyRequestBody: newAuthenticationVerifyRequestBody(value, code), LoginOptions: loginOptions}
}

func newMagicLinkUpdateEmailRequestBody(loginID, email string, URI string, crossDevice bool, updateOptions *descope.UpdateOptions) *magicLinkUpdateEmailRequestBody {
	return &magicLinkUpdateEmailRequestBody{LoginID: loginID, Email: email, URI: URI, CrossDevice: crossDevice, UpdateOptions: updateOptions}
}

func newMagicLinkUpdatePhoneRequestBody(loginID, phone string, URI string, crossDevice bool, updateOptions *descope.UpdateOptions) *magicLinkUpdatePhoneRequestBody {
	return &magicLinkUpdatePhoneRequestBody{LoginID: loginID, Phone: phone, URI: URI, CrossDevice: crossDevice, UpdateOptions: updateOptions}
}

func newAuthenticationGetMagicLinkSessionBody(pendingRef string) *authenticationGetMagicLinkSessionBody {
	return &authenticationGetMagicLinkSessionBody{PendingRef: pendingRef}
}

func newExchangeTokenBody(code string) *exchangeTokenBody {
	return &exchangeTokenBody{Code: code}
}

const (
	claimAttributeName = "drn"
	claimPermissions   = "permissions"
	claimRoles         = "roles"
)

var (
	phoneRegex = regexp.MustCompile(`^(?:(?:\(?(?:00|\+)([1-4]\d\d|[1-9]\d?)\)?)?[\-\.\ \\\/]?)?((?:\(?\d{1,}\)?[\-\.\ \\\/]?){0,})(?:[\-\.\ \\\/]?(?:#|ext\.?|extension|x)[\-\.\ \\\/]?(\d+))?$`)
	emailRegex = regexp.MustCompile("^(((([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+(\\.([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+)*)|((\\x22)((((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x21|[\\x23-\\x5b]|[\\x5d-\\x7e]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(\\([\\x01-\\x09\\x0b\\x0c\\x0d-\\x7f]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}]))))*(((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(\\x22)))@((([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])([a-zA-Z]|\\d|-|\\.|_|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.)+(([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])([a-zA-Z]|\\d|-|_|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.?$")
)
