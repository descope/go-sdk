package auth

import (
	"context"
	goErrors "errors"
	"net/http"
	"path"
	"time"

	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/errors"
	"github.com/descope/go-sdk/descope/logger"
	"github.com/descope/go-sdk/descope/utils"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type AuthParams struct {
	ProjectID string
	PublicKey string
}

type authenticationService struct {
	client             *api.Client
	conf               *AuthParams
	publicKeysProvider *provider
}

func NewAuth(conf AuthParams, c *api.Client) (*authenticationService, error) {
	authenticationObject := &authenticationService{conf: &conf, client: c}
	authenticationObject.publicKeysProvider = newProvider(c, authenticationObject.conf)
	return authenticationObject, nil
}

func getPendingRefFromResponse(httpResponse *api.HTTPResponse) (*MagicLinkResponse, error) {
	var response *MagicLinkResponse
	if err := utils.Unmarshal([]byte(httpResponse.BodyStr), &response); err != nil {
		logger.LogError("failed to load pending reference from response", err)
		return response, errors.InvalidPendingRefError
	}
	return response, nil
}

func (auth *authenticationService) Logout(request *http.Request, w http.ResponseWriter) error {
	return auth.LogoutWithOptions(request, WithResponseOption(w))
}

func (auth *authenticationService) LogoutWithOptions(request *http.Request, options ...Option) error {
	if request == nil {
		return errors.MissingProviderError
	}

	_, refreshToken := provideTokens(request)
	if refreshToken == "" {
		logger.LogDebug("unable to find tokens from cookies")
		return errors.RefreshTokenError
	}

	httpResponse, err := auth.client.DoGetRequest(api.Routes.Logout(), &api.HTTPRequest{}, refreshToken)
	if err != nil {
		return err
	}
	cookies := httpResponse.Res.Cookies()
	cookies = append(cookies, createCookie(&Token{JWT: "", Claims: map[string]interface{}{
		"cookieName": SessionCookieName,
		"path":       "/",
		"domain":     "",
	}}))
	cookies = append(cookies, createCookie(&Token{JWT: "", Claims: map[string]interface{}{
		"cookieName": RefreshCookieName,
		"path":       "/",
		"domain":     "",
	}}))
	Options(options).SetCookies(cookies)
	return nil
}

func (auth *authenticationService) ValidateSession(request *http.Request, w http.ResponseWriter) (bool, *Token, error) {
	return auth.ValidateSessionWithOptions(request, WithResponseOption(w))
}

func (auth *authenticationService) ValidateSessionWithOptions(request *http.Request, options ...Option) (bool, *Token, error) {
	if request == nil {
		return false, nil, errors.MissingProviderError
	}

	sessionToken, refreshToken := provideTokens(request)
	if refreshToken == "" || sessionToken == "" {
		logger.LogDebug("unable to find tokens from cookies")
		return false, nil, nil
	}

	return auth.validateSession(sessionToken, refreshToken, options...)
}

// AuthenticationMiddleware - middleware used to validate session and invoke if provided a failure and
// success callbacks after calling ValidateSession().
// onFailure will be called when the authentication failed, if empty, will write unauthorized (401) on the response writer.
// onSuccess will be called when the authentication suceeded, if empty, it will generate a new context with the descope user id associated with the given token and runs next.
func AuthenticationMiddleware(auth Authentication, onFailure func(http.ResponseWriter, *http.Request, error), onSuccess func(http.ResponseWriter, *http.Request, http.Handler, *Token)) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ok, token, err := auth.ValidateSession(r, w); ok {
				if onSuccess != nil {
					onSuccess(w, r, next, token)
				} else {
					newCtx := context.WithValue(r.Context(), ContextUserIDPropertyKey, token.ID)
					r = r.WithContext(newCtx)
					next.ServeHTTP(w, r)
				}
			} else {
				if err != nil {
					logger.LogError("request failed because token is invalid", err)
				}
				if onFailure != nil {
					onFailure(w, r, err)
				} else {
					w.WriteHeader(http.StatusUnauthorized)
				}
			}
		})
	}
}

func (auth *authenticationService) validateSession(sessionToken string, refreshToken string, options ...Option) (bool, *Token, error) {
	token, err := auth.validateJWT(sessionToken)
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
		httpResponse, err := auth.client.DoGetRequest(api.Routes.RefreshToken(), &api.HTTPRequest{}, refreshToken)
		if err != nil {
			return false, nil, errors.FailedToRefreshTokenError
		}
		info, err := auth.generateAuthenticationInfo(httpResponse, options...)
		if err != nil {
			return false, nil, err
		}
		return true, info.SessionToken, nil
	}

	return true, token, nil
}

func (auth *authenticationService) extractJWTResponse(bodyStr string) (*JWTResponse, error) {
	if bodyStr == "" {
		return nil, nil
	}
	jRes := JWTResponse{}
	err := utils.Unmarshal([]byte(bodyStr), &jRes)
	if err != nil {
		logger.LogError("unable to parse jwt response", err)
		return nil, err
	}
	return &jRes, nil
}

func (auth *authenticationService) extractTokens(jRes *JWTResponse) ([]*Token, error) {

	if jRes == nil || len(jRes.JWTS) == 0 {
		return nil, nil
	}
	var tokens []*Token
	for i := range jRes.JWTS {
		token, err := auth.validateJWT(jRes.JWTS[i])
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, token)
	}
	return tokens, nil
}

func (auth *authenticationService) validateJWT(JWT string) (*Token, error) {
	token, err := jwt.Parse([]byte(JWT), jwt.WithKeyProvider(auth.publicKeysProvider), jwt.WithVerify(true), jwt.WithValidate(true))
	if err != nil {
		var parseErr error
		token, parseErr = jwt.Parse([]byte(JWT), jwt.WithKeyProvider(auth.publicKeysProvider), jwt.WithVerify(false), jwt.WithValidate(false))
		if parseErr != nil {
			err = parseErr
		}
	}
	return NewToken(JWT, token), err
}

func (*authenticationService) verifyDeliveryMethod(method DeliveryMethod, identifier string, user *User) *errors.WebError {
	varName := "identifier"
	if identifier == "" {
		return errors.NewInvalidArgumentError(varName)
	}

	switch method {
	case MethodEmail:
		if len(user.Email) == 0 {
			user.Email = identifier
		} else {
			varName = "user.Email"
		}
		if !emailRegex.MatchString(user.Email) {
			return errors.NewInvalidArgumentError(varName)
		}
	case MethodSMS:
		if len(user.Phone) == 0 {
			user.Phone = identifier
		} else {
			varName = "user.Phone"
		}
		if !phoneRegex.MatchString(user.Phone) {
			return errors.NewInvalidArgumentError(varName)
		}
	case MethodWhatsApp:
		if len(user.Phone) == 0 {
			user.Phone = identifier
		} else {
			varName = "user.Phone"
		}
		if !phoneRegex.MatchString(user.Phone) {
			return errors.NewInvalidArgumentError(varName)
		}
	}
	return nil
}

func (auth *authenticationService) generateAuthenticationInfo(httpResponse *api.HTTPResponse, options ...Option) (*AuthenticationInfo, error) {
	jwtResponse, err := auth.extractJWTResponse(httpResponse.BodyStr)
	if err != nil {
		return nil, err
	}
	tokens, err := auth.extractTokens(jwtResponse)
	if err != nil {
		logger.LogError("unable to extract tokens from request [%s]", err, httpResponse.Req.URL)
		return nil, err
	}
	cookies := httpResponse.Res.Cookies()
	var token *Token
	for i := range tokens {
		ck := createCookie(tokens[i])
		if ck != nil {
			cookies = append(cookies, ck)
		}
		if tokens[i].Claims["cookieName"] == SessionCookieName {
			token = tokens[i]
		}
	}
	Options(options).SetCookies(cookies)
	return NewAuthenticationInfo(jwtResponse, token), err
}

func getValidRefreshToken(r *http.Request) (string, error) {
	_, refreshToken := provideTokens(r)
	if refreshToken == "" {
		logger.LogDebug("unable to find tokens from cookies")
		return "", errors.RefreshTokenError
	}
	return refreshToken, nil
}

func createCookie(token *Token) *http.Cookie {
	if token != nil {
		path, _ := token.Claims["cookiePath"].(string)
		domain, _ := token.Claims["cookieDomain"].(string)
		name, _ := token.Claims["cookieName"].(string)
		maxAge, _ := token.Claims["cookieMaxAge"].(float64)
		expiration, _ := token.Claims["cookieExpiration"].(float64)
		return &http.Cookie{
			Path:     path,
			Domain:   domain,
			Name:     name,
			Value:    token.JWT,
			HttpOnly: true,
			MaxAge:   int(maxAge),
			Expires:  time.Unix(int64(expiration), 0),
			SameSite: http.SameSiteNoneMode,
			Secure:   true,
		}
	}
	return nil
}

func provideTokens(r *http.Request) (string, string) {
	sessionToken := ""
	if sessionCookie, _ := r.Cookie(SessionCookieName); sessionCookie != nil {
		sessionToken = sessionCookie.Value
	}

	refreshCookie, err := r.Cookie(RefreshCookieName)
	if err != nil {
		return sessionToken, ""
	}
	return sessionToken, refreshCookie.Value
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
		logger.LogError("failed to verify token", err)
		return false, errors.NewUnauthorizedError()
	}
	return true, nil
}

func composeURLMethod(base string, method DeliveryMethod) string {
	return path.Join(base, string(method))
}

func composeSignInURL(method DeliveryMethod) string {
	return composeURLMethod(api.Routes.SignInOTP(), method)
}

func composeSignUpURL(method DeliveryMethod) string {
	return composeURLMethod(api.Routes.SignUpOTP(), method)
}

func composeSignUpOrInURL(method DeliveryMethod) string {
	return composeURLMethod(api.Routes.SignUpOrInOTP(), method)
}

func composeSignUpTOTPURL() string {
	return api.Routes.SignUpTOTP()
}

func composeUpdateTOTPURL() string {
	return api.Routes.UpdateTOTP()
}

func composeVerifyCodeURL(method DeliveryMethod) string {
	return composeURLMethod(api.Routes.VerifyCode(), method)
}

func composeVerifyTOTPCodeURL() string {
	return api.Routes.VerifyTOTPCode()
}

func composeMagicLinkSignInURL(method DeliveryMethod) string {
	return composeURLMethod(api.Routes.SignInMagicLink(), method)
}

func composeMagicLinkSignUpURL(method DeliveryMethod) string {
	return composeURLMethod(api.Routes.SignUpMagicLink(), method)
}

func composeMagicLinkSignUpOrInURL(method DeliveryMethod) string {
	return composeURLMethod(api.Routes.SignUpOrInMagicLink(), method)
}

func composeVerifyMagicLinkURL() string {
	return api.Routes.VerifyMagicLink()
}

func composeOAuthURL() string {
	return api.Routes.OAuthStart()
}

func composeExchangeTokenURL() string {
	return api.Routes.ExchangeToken()
}

func composeSAMLStartURL() string {
	return api.Routes.SAMLStart()
}

func composeGetMagicLinkSession() string {
	return api.Routes.GetMagicLinkSession()
}

func composeUpdateUserEmailOTP() string {
	return api.Routes.UpdateUserEmailOTP()
}

func composeUpdateUserEmailMagicLink() string {
	return api.Routes.UpdateUserEmailMagiclink()
}

func composeUpdateUserPhoneOTP(method DeliveryMethod) string {
	return composeURLMethod(api.Routes.UpdateUserPhoneOTP(), method)
}

func composeUpdateUserPhoneMagicLink(method DeliveryMethod) string {
	return composeURLMethod(api.Routes.UpdateUserPhoneMagicLink(), method)
}
