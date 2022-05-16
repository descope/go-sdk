package auth

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"path"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type Auth struct {
	client *client
	conf   *Config
}

func NewAuth(conf Config) *Auth {
	if conf.Logger == nil {
		conf.Logger = log.Default()
	}

	if conf.DefaultURL == "" {
		conf.DefaultURL = defaultURL
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

	_, err := auth.client.DoPostRequest(composeSignInURL(method), newAuthenticationRequestBody(method, identifier), nil)
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

	_, err := auth.client.DoPostRequest(composeSignUpURL(method), newAuthenticationSignInRequestBody(method, identifier, user), nil)
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

	httpResponse, err := auth.client.DoPostRequest(composeVerifyCodeURL(method), newAuthenticationVerifyRequestBody(method, identifier, code), nil)
	cookies := []*http.Cookie{}
	if httpResponse != nil {
		cookies = httpResponse.req.Cookies()
	}
	return cookies, err
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

func (auth *Auth) getAuthenticationKey() (jwk.Key, error) {
	if auth.conf.PublicKey == "" {
		if publicKey := GetPublicKey(); publicKey != "" {
			auth.conf.PublicKey = publicKey
		} else {
			return nil, fmt.Errorf("public key was not initialized")
		}
	}

	jk, err := jwk.ParseKey([]byte(auth.conf.PublicKey))
	if err != nil {
		auth.conf.LogDebug("unable to parse key")
		return nil, err
	}
	return jk, nil
}

func (auth *Auth) ValidateSession(signedToken string) (bool, error) {
	key, err := auth.getAuthenticationKey()
	if err != nil {
		return false, err
	}

	_, err = jwt.ParseString(signedToken, jwt.WithKey(jwa.ES384, key))
	if errors.Is(err, jwt.ErrTokenExpired()) {
		auth.conf.LogDebug("token has expired")
		return false, NewUnauthorizedError()
	}
	if errors.Is(err, jwt.ErrTokenNotYetValid()) {
		auth.conf.LogDebug("token is not yet valid")
		return false, NewUnauthorizedError()
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
		if projectID := GetProjectID(); projectID != "" {
			auth.conf.ProjectID = projectID
		} else {
			return fmt.Errorf("project id is missing. Make sure to add it in the configuration or the environment variable DESCOPE_PROJECT_ID")
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
