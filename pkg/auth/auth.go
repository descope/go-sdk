package auth

import (
	"log"
	"path"
)

type Auth struct {
	client iClient
	conf   *Config
}

func NewAuth(conf Config) *Auth {
	if conf.Logger == nil {
		conf.Logger = log.Default()
	}

	return &Auth{conf: &conf}
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

	_, err := auth.client.post(composeSignInURL(methodEmail), map[string]interface{}{"identifiers": map[string]interface{}{"email": email}}) // TODO: internal struct
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

	_, err := auth.client.post(composeSignInURL(methodPhone), map[string]interface{}{"identifiers": map[string]interface{}{"phone": phone}})
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

	_, err := auth.client.post(composeSignInURL(methodWhatsapp), map[string]interface{}{"identifiers": map[string]interface{}{"phone": phone}})
	return err
}

func (auth *Auth) SignUpEmail(email string, user *User) *WebError {
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

	_, err := auth.client.post(composeSignUpURL(methodEmail), map[string]interface{}{"identifiers": map[string]interface{}{"email": email}, "user": user})
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

	_, err := auth.client.post(composeSignUpURL(methodEmail), map[string]interface{}{"identifiers": map[string]interface{}{"phone": phone}, "user": user})
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

	_, err := auth.client.post(composeSignUpURL(methodEmail), map[string]interface{}{"identifiers": map[string]interface{}{"phone": phone}, "user": user})
	return err
}

func (auth *Auth) VerifyCode(identifier string, code string, method Method) *WebError {
	if auth.client == nil {
		if err := auth.prepareClient(); err != nil {
			return err
		}
	}

	if identifier == "" {
		return NewError(badRequestErrorCode, "bad request")
	}

	if method == "" {
		if phoneRegex.MatchString(identifier) {
			method = methodPhone // TODO: where is whatsapp?
		}

		if emailRegex.MatchString(identifier) {
			method = methodEmail
		}
	}

	if method == "" {
		return NewInvalidArgumentError("identifier")
	}

	_, err := auth.client.post(composeVerifyCodeURL(methodEmail), map[string]interface{}{"identifiers": map[string]interface{}{string(method): identifier}, "code": code})
	return err
}

func (auth *Auth) VerifyCodeEmail(identifier string, code string) *WebError {
	return auth.VerifyCode(identifier, code, methodEmail)
}

func (auth *Auth) VerifyCodeSMS(identifier string, code string) *WebError {
	return auth.VerifyCode(identifier, code, methodPhone)
}

func (auth *Auth) VerifyCodeWhatsapp(identifier string, code string) *WebError {
	return auth.VerifyCode(identifier, code, methodWhatsapp)
}

func (auth *Auth) prepareClient() *WebError {
	if auth.conf.ProjectID == "" {
		return NewError("E00000", "missing project id env variable") // TODO: add error code
	} else {
		auth.client = newClient(auth.conf)
	}
	return nil
}

func composeURL(base string, method Method) string {
	return path.Join(base, string(method))
}

func composeSignInURL(method Method) string {
	return composeURL(signInOTPPath, method)
}
func composeSignUpURL(method Method) string {
	return composeURL(signUpOTPPath, method)
}
func composeVerifyCodeURL(method Method) string {
	return composeURL(verifyCodePath, method)
}
