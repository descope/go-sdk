package auth

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
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

	_, _, err := auth.client.Post(composeSignInURL(method), map[string]interface{}{string(method): identifier})
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

	_, _, err := auth.client.Post(composeSignUpURL(method), map[string]interface{}{string(method): identifier, "user": user})
	return err
}

func (auth *Auth) VerifyCode(method DeliveryMethod, identifier string, code string) ([]*http.Cookie, error) {
	if auth.client == nil {
		if err := auth.prepareClient(); err != nil {
			return nil, err
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
			return nil, NewInvalidArgumentError("identifier")
		}
	} else if err := auth.verifyDeliveryMethod(method, identifier); err != nil {
		return nil, err
	}

	_, response, err := auth.client.Post(composeVerifyCodeURL(method), map[string]interface{}{string(method): identifier, "code": code})
	return response.Cookies(), err
}

func (auth *Auth) VerifyCodeEmail(identifier string, code string) ([]*http.Cookie, error) {
	return auth.VerifyCode(MethodEmail, identifier, code)
}

func (auth *Auth) VerifyCodeSMS(identifier string, code string) ([]*http.Cookie, error) {
	return auth.VerifyCode(MethodSMS, identifier, code)
}

func (auth *Auth) VerifyCodeWhatsApp(identifier string, code string) ([]*http.Cookie, error) {
	return auth.VerifyCode(MethodWhatsApp, identifier, code)
}

func (auth *Auth) ValidateSessionRequest(r *http.Request) (bool, error) {
	c, err := r.Cookie(CookieDefaultName)
	if err != nil {
		auth.conf.LogDebug("unable to find session cookie")
		return false, err
	}
	if c == nil {
		return false, nil
	}
	return auth.ValidateSession(c.Value)
}

func (auth *Auth) ValidateSession(signedToken string) (bool, error) {
	if auth.conf.PublicKey == "" {
		if publicKey := os.Getenv("PUBLIC_KEY"); publicKey != "" {
			auth.conf.PublicKey = publicKey
		} else {
			return false, fmt.Errorf("public key was not initialized")
		}
	}

	_, err := jwt.Parse([]byte(signedToken), jwt.WithKey(jwa.ES384, auth.conf.PublicKey))
	if errors.Is(err, jwt.ErrTokenExpired()) {
		auth.conf.LogDebug("token has expired")
		return false, nil
	}
	if errors.Is(err, jwt.ErrTokenNotYetValid()) {
		auth.conf.LogDebug("token is not yet valid")
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed verify token %s", err)
	}

	return true, nil
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

func (auth *Auth) prepareClient() error {
	if auth.conf.ProjectID == "" {
		if projectID := os.Getenv("PROJECT_ID"); projectID != "" {
			auth.conf.ProjectID = projectID
		} else {
			return fmt.Errorf("project id is missing. Make sure to add it in the configuration or the environment variable PROJECT_ID")
		}
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
