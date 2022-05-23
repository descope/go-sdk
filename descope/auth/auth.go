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

	_, err := auth.client.DoPostRequest(composeSignUpURL(method), newAuthenticationSignUpRequestBody(method, identifier, user), nil)
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
	sessionToken := ""
	if sessionCookie, _ := r.Cookie(SessionCookieName); sessionCookie != nil {
		sessionToken = sessionCookie.Value
	}
	refreshCookie, err := r.Cookie(RefreshCookieName)
	if err != nil {
		logger.LogDebug("unable to find refresh cookie")
		return false, err
	}

	ok, cookies, err := auth.validateSession(sessionToken, refreshCookie.Value)
	if ok {
		for _, cookie := range cookies {
			r.AddCookie(cookie)
		}
		return true, nil
	}
	return false, err
}

func (auth *Auth) validateSession(sessionToken string, refreshToken string) (bool, []*http.Cookie, error) {
	_, err := auth.validateJWT(sessionToken)
	if sessionToken != "" && !auth.publicKeysProvider.publicKeyExists() {
		return false, nil, errors.NewNoPublicKeyError()
	}
	if err != nil {
		// check refresh token
		_, err := auth.validateJWT(refreshToken)
		if ok, err := validateTokenError(err); !ok {
			return false, nil, err
		}
		// auto-refresh session token
		httpResponse, err := auth.client.DoGetRequest(refreshTokenV1Path, &api.HTTPRequest{
			Cookies: []*http.Cookie{{Name: SessionCookieName, Value: sessionToken}, {Name: RefreshCookieName, Value: refreshToken}},
		})
		if err != nil {
			return false, nil, errors.NewValidationError("Failed to auto-refresh token")
		}
		return true, httpResponse.Res.Cookies(), nil
	}
	if ok, err := validateTokenError(err); !ok {
		return false, nil, err
	}

	return true, nil, nil
}

func (auth *Auth) validateJWT(JWT string) (jwt.Token, error) {
	return jwt.Parse([]byte(JWT), jwt.WithKeyProvider(auth.publicKeysProvider), jwt.WithVerify(true), jwt.WithValidate(true))
}

func validateTokenError(err error) (bool, error) {
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

func (auth *Auth) AuthenticationMiddleware(onFailure func(http.ResponseWriter, *http.Request, error)) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ok, err := auth.ValidateSessionRequest(r); ok {
				next.ServeHTTP(w, r)
			} else {
				logger.LogDebug("request failed because token is invalid error: " + err.Error())
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
	return path.Join(base, string(method))
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
