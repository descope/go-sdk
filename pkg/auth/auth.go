package auth

import (
	"os"
	"path"
	"regexp"
)

type User struct {
	Username string `json:username,omitempty`
	Name     string `json:name,omitempty`
	Phone    string `json:phone,omitempty`
	Email    string `json:email,omitempty`
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
	whatsappMethod Method = "whatsapp"
	phoneMethod    Method = "phone"
	emailMethod    Method = "email"

	signInOTPPath  = "/v1/auth/signin/otp/"
	signUpOTPPath  = "/v1/auth/signup/otp/"
	verifyCodePath = "v1/auth/code/verify/"
)

var (
	phoneRegex = regexp.MustCompile(`^(?:(?:\(?(?:00|\+)([1-4]\d\d|[1-9]\d?)\)?)?[\-\.\ \\\/]?)?((?:\(?\d{1,}\)?[\-\.\ \\\/]?){0,})(?:[\-\.\ \\\/]?(?:#|ext\.?|extension|x)[\-\.\ \\\/]?(\d+))?$`)
	emailRegex = regexp.MustCompile("^(((([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+(\\.([a-zA-Z]|\\d|[!#\\$%&'\\*\\+\\-\\/=\\?\\^_`{\\|}~]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])+)*)|((\\x22)((((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(([\\x01-\\x08\\x0b\\x0c\\x0e-\\x1f\\x7f]|\\x21|[\\x23-\\x5b]|[\\x5d-\\x7e]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(\\([\\x01-\\x09\\x0b\\x0c\\x0d-\\x7f]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}]))))*(((\\x20|\\x09)*(\\x0d\\x0a))?(\\x20|\\x09)+)?(\\x22)))@((([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])([a-zA-Z]|\\d|-|\\.|_|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*([a-zA-Z]|\\d|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.)+(([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])|(([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])([a-zA-Z]|\\d|-|_|~|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])*([a-zA-Z]|[\\x{00A0}-\\x{D7FF}\\x{F900}-\\x{FDCF}\\x{FDF0}-\\x{FFEF}])))\\.?$")
)

type Auth struct {
	client iClient
}

func NewAuth() *Auth {
	return &Auth{}
}

func (auth *Auth) SignInEmail(email string) *WebError {
	if auth.client == nil {
		if err := auth.prepareClient(); err != nil {
			return err
		}
	}

	if !emailRegex.MatchString(email) {
		return NewInvalidArgumentError("email")
	}

	_, err := auth.client.post(signInURL(emailMethod), map[string]interface{}{"identifiers": map[string]interface{}{"email": email}}) // TODO: internal struct
	return err
}

func (auth *Auth) SignInPhone(phone string) *WebError {
	if auth.client == nil {
		if err := auth.prepareClient(); err != nil {
			return err
		}
	}

	if !phoneRegex.MatchString(phone) {
		return NewInvalidArgumentError("phone")
	}

	_, err := auth.client.post(signInURL(phoneMethod), map[string]interface{}{"identifiers": map[string]interface{}{"phone": phone}})
	return err
}

func (auth *Auth) SignInWhatsapp(phone string) *WebError {
	if auth.client == nil {
		if err := auth.prepareClient(); err != nil {
			return err
		}
	}

	if !phoneRegex.MatchString(phone) {
		return NewInvalidArgumentError("phone")
	}

	_, err := auth.client.post(signInURL(whatsappMethod), map[string]interface{}{"identifiers": map[string]interface{}{"phone": phone}})
	return err
}

func (auth *Auth) SignUpEmail(email string, user *User) *WebError { // TODO: should be a struct (?)
	if auth.client == nil {
		if err := auth.prepareClient(); err != nil {
			return err
		}
	}

	if email == "" {
		return NewError("E...", "bad request") // TODO: add error code
	}

	if !emailRegex.MatchString(email) {
		return NewInvalidArgumentError("email")
	}

	_, err := auth.client.post(signUpURL(emailMethod), map[string]interface{}{"identifiers": map[string]interface{}{"email": email}, "user": user})
	return err
}

func (auth *Auth) SignUpSMS(phone string, user *User) *WebError { // TODO: should unify SMS and whatsapp phone base code?
	if auth.client == nil {
		if err := auth.prepareClient(); err != nil {
			return err
		}
	}

	if phone == "" {
		return NewError("E...", "bad request") // TODO: add error code
	}

	if !phoneRegex.MatchString(phone) {
		return NewInvalidArgumentError("phone")
	}

	_, err := auth.client.post(signUpURL(emailMethod), map[string]interface{}{"identifiers": map[string]interface{}{"phone": phone}, "user": user})
	return err
}

func (auth *Auth) SignUpWhatsapp(phone string, user *User) *WebError {
	if auth.client == nil {
		if err := auth.prepareClient(); err != nil {
			return err
		}
	}

	if phone == "" {
		return NewError("E...", "bad request") // TODO: add error code
	}

	if !phoneRegex.MatchString(phone) {
		return NewInvalidArgumentError("phone")
	}

	_, err := auth.client.post(signUpURL(emailMethod), map[string]interface{}{"identifiers": map[string]interface{}{"phone": phone}, "user": user})
	return err
}

func (auth *Auth) VerifyCode(identifier string, code string, method Method) *WebError {
	if auth.client == nil {
		if err := auth.prepareClient(); err != nil {
			return err
		}
	}

	if identifier == "" {
		return NewError(badRequestErrorCode, "bad request") // TODO: add error code
	}

	if method == "" {
		if phoneRegex.MatchString(identifier) {
			method = phoneMethod // TODO: where is whatsapp?
		}

		if emailRegex.MatchString(identifier) {
			method = emailMethod
		}
	}

	if method == "" {
		return NewInvalidArgumentError("identifier") // TODO: add error code
	}

	_, err := auth.client.post(verifyCodeURL(emailMethod), map[string]interface{}{"identifiers": map[string]interface{}{string(method): identifier}, "code": code})
	return err
}

func (auth *Auth) VerifyCodeEmail(identifier string, code string) *WebError {
	return auth.VerifyCode(identifier, code, emailMethod)
}

func (auth *Auth) VerifyCodeSMS(identifier string, code string) *WebError {
	return auth.VerifyCode(identifier, code, phoneMethod)
}

func (auth *Auth) VerifyCodeWhatsapp(identifier string, code string) *WebError {
	return auth.VerifyCode(identifier, code, whatsappMethod)
}

func (auth *Auth) prepareClient() *WebError {
	if projectID := os.Getenv("PROJECT_ID"); projectID == "" {
		return NewError("E00000", "missing project id env variable") // TODO: add error code
	} else {
		auth.client = newClient(projectID)
	}
	return nil
}

// TODO: prettify 
func signInURL(method Method) string {
	return path.Join(signInOTPPath, string(method))
}
func signUpURL(method Method) string {
	return path.Join(signUpOTPPath, string(method))
}
func verifyCodeURL(method Method) string {
	return path.Join(verifyCodePath, string(method))
}
