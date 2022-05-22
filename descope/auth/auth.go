package auth

import (
	goErrors "errors"
	"net/http"
	"path"

	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/errors"
	"github.com/descope/go-sdk/descope/logger"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type AuthParams struct {
	ProjectID string
	PublicKey string
}

type Auth struct {
	client             *api.Client
	conf               *AuthParams
	publicKeysProvider *provider
}

func NewAuth(conf AuthParams, c *api.Client) (*Auth, error) {
	authenticationObject := &Auth{conf: &conf, client: c}
	authenticationObject.publicKeysProvider = newProvider(c, authenticationObject.conf)
	return authenticationObject, nil
}

func (auth *Auth) SignInOTP(method DeliveryMethod, identifier string) error {
	if err := auth.verifyDeliveryMethod(method, identifier); err != nil {
		return err
	}

	_, err := auth.client.DoPostRequest(composeSignInURL(method), newAuthenticationRequestBody(method, identifier), nil)
	return err
}

func (auth *Auth) SignUpOTP(method DeliveryMethod, identifier string, user *User) error {
	if err := auth.verifyDeliveryMethod(method, identifier); err != nil {
		return err
	}

	_, err := auth.client.DoPostRequest(composeSignUpURL(method), newAuthenticationSignInRequestBody(method, identifier, user), nil)
	return err
}

func (auth *Auth) VerifyCode(method DeliveryMethod, identifier string, code string) ([]*http.Cookie, error) {
	if method == "" {
		if phoneRegex.MatchString(identifier) {
			method = MethodSMS
		}

		if emailRegex.MatchString(identifier) {
			method = MethodEmail
		}

		if method == "" {
			return nil, errors.NewInvalidArgumentError("identifier")
		}
	} else if err := auth.verifyDeliveryMethod(method, identifier); err != nil {
		return nil, err
	}

	httpResponse, err := auth.client.DoPostRequest(composeVerifyCodeURL(method), newAuthenticationVerifyRequestBody(method, identifier, code), nil)
	cookies := []*http.Cookie{}
	if httpResponse != nil {
		cookies = httpResponse.Res.Cookies()
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
		logger.LogDebug("unable to find session cookie")
		return false, err
	}
	return auth.validateSession(c.Value)
}

func (auth *Auth) validateSession(signedToken string) (bool, error) {
	_, err := jwt.ParseString(signedToken, jwt.WithKeyProvider(auth.publicKeysProvider))
	if !auth.publicKeysProvider.publicKeyExists() {
		return false, errors.NewNoPublicKeyError()
	}

	if goErrors.Is(err, jwt.ErrTokenExpired()) {
		logger.LogDebug("token has expired")
		return false, errors.NewUnauthorizedError()
	}
	if goErrors.Is(err, jwt.ErrTokenNotYetValid()) {
		logger.LogDebug("token is not yet valid")
		return false, errors.NewUnauthorizedError()
	}
	if err != nil {
		logger.LogDebug("failed to verify token [%s]", err)
		return false, errors.NewUnauthorizedError()
	}

	return true, nil
}

func (auth *Auth) AuthenticationMiddleWare(onFailure func(http.ResponseWriter, *http.Request, error), onSuccess func(http.ResponseWriter, *http.Request)) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ok, err := auth.ValidateSessionRequest(r); ok {
				if onSuccess != nil {
					onSuccess(w, r)
				} else {
					next.ServeHTTP(w, r)
				}
			} else {
				logger.LogDebug("request failed because token is invalid = " + err.Error())
				if onFailure != nil {
					onFailure(w, r, err)
				} else {
					w.WriteHeader(http.StatusUnauthorized)
				}
			}
		})
	}
}

func (*Auth) verifyDeliveryMethod(method DeliveryMethod, identifier string) *errors.WebError {
	if identifier == "" {
		return errors.NewError(errors.BadRequestErrorCode, "bad request")
	}

	switch method {
	case MethodEmail:
		if !emailRegex.MatchString(identifier) {
			return errors.NewInvalidArgumentError("identifier")
		}
	case MethodSMS:
		if !phoneRegex.MatchString(identifier) {
			return errors.NewInvalidArgumentError("identifier")
		}
	case MethodWhatsApp:
		if !phoneRegex.MatchString(identifier) {
			return errors.NewInvalidArgumentError("identifier")
		}
	}
	return nil
}

func composeURLMethod(base string, method DeliveryMethod) string {
	p := string(method)
	if method == MethodSMS {
		p = "sms"
	}
	return path.Join(base, p)
}

func composeSignInURL(method DeliveryMethod) string {
	return composeURLMethod(signInV1AuthOTPPath, method)
}

func composeSignUpURL(method DeliveryMethod) string {
	return composeURLMethod(signUpV1AuthOTPPath, method)
}

func composeVerifyCodeURL(method DeliveryMethod) string {
	return composeURLMethod(verifyCodeV1AuthPath, method)
}
