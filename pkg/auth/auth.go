package auth

import (
	"log"
	"path"
)

type Auth struct {
	client IClient
	conf   *Config
}

func NewAuth(conf Config) *Auth {
	if conf.Logger == nil {
		conf.Logger = log.Default()
	}

	return &Auth{conf: &conf}
}

func (auth *Auth) SignInOTP(method DeliveryMethod, identifier string) error {
	if auth.client == nil {
		if err := auth.prepareClient(); err != nil {
			return err
		}
	}

	if err := auth.verifyDeliveryMethod(method, identifier); err != nil {
		return err
	}

	_, err := auth.client.post(composeSignInURL(method), map[string]interface{}{"identifiers": map[string]interface{}{string(method): identifier}})
	return err
}

func (auth *Auth) SignUpOTP(method DeliveryMethod, identifier string, user *User) error {
	if auth.client == nil {
		if err := auth.prepareClient(); err != nil {
			return err
		}
	}

	if err := auth.verifyDeliveryMethod(method, identifier); err != nil {
		return err
	}

	_, err := auth.client.post(composeSignUpURL(method), map[string]interface{}{"identifiers": map[string]interface{}{string(method): identifier}, "user": user})
	return err
}

func (auth *Auth) VerifyCode(identifier string, code string, method DeliveryMethod) *WebError {
	if auth.client == nil {
		if err := auth.prepareClient(); err != nil {
			return err
		}
	}

	if method == "" {
		if phoneRegex.MatchString(identifier) {
			method = MethodSMS
		}

		if emailRegex.MatchString(identifier) {
			method = MethodEmail
		}

		if method == "" {
			return NewInvalidArgumentError("identifier")
		}
	} else if err := auth.verifyDeliveryMethod(method, identifier); err != nil {
		return err
	}

	_, err := auth.client.post(composeVerifyCodeURL(MethodEmail), map[string]interface{}{"identifiers": map[string]interface{}{string(method): identifier}, "code": code})
	return err
}

func (auth *Auth) VerifyCodeEmail(identifier string, code string) error {
	return auth.VerifyCode(identifier, code, MethodEmail)
}

func (auth *Auth) VerifyCodeSMS(identifier string, code string) error {
	return auth.VerifyCode(identifier, code, MethodSMS)
}

func (auth *Auth) VerifyCodeWhatsApp(identifier string, code string) error {
	return auth.VerifyCode(identifier, code, MethodWhatsApp)
}

func (*Auth) verifyDeliveryMethod(method DeliveryMethod, identifier string) *WebError {
	if identifier == "" {
		return NewError(badRequestErrorCode, "bad request")
	}

	switch method {
	case MethodEmail:
		if !emailRegex.MatchString(identifier) {
			return NewInvalidArgumentError("identifier")
		}
	case MethodSMS:
		if !phoneRegex.MatchString(identifier) {
			return NewInvalidArgumentError("identifier")
		}
	case MethodWhatsApp:
		if !phoneRegex.MatchString(identifier) {
			return NewInvalidArgumentError("identifier")
		}
	}
	return nil
}

func (auth *Auth) prepareClient() *WebError {
	if auth.conf.ProjectID == "" {
		return NewError("E00000", "missing project id env variable")
	}

	auth.client = newClient(auth.conf)
	return nil
}

func composeURL(base string, method DeliveryMethod) string {
	return path.Join(base, string(method))
}

func composeSignInURL(method DeliveryMethod) string {
	return composeURL(signInOTPPath, method)
}

func composeSignUpURL(method DeliveryMethod) string {
	return composeURL(signUpOTPPath, method)
}

func composeVerifyCodeURL(method DeliveryMethod) string {
	return composeURL(verifyCodePath, method)
}
