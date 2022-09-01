package auth

import (
	"context"
	goErrors "errors"
	"net/http"
	"path"
	"strings"
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

type authenticationsBase struct {
	client             *api.Client
	conf               *AuthParams
	publicKeysProvider *provider
}

type authenticationService struct {
	authenticationsBase

	otp       OTP
	magicLink MagicLink
	totp      TOTP
	webAuthn  WebAuthn
	oauth     OAuth
	saml      SAML
}

func NewAuth(conf AuthParams, c *api.Client) (*authenticationService, error) {
	base := authenticationsBase{conf: &conf, client: c}
	base.publicKeysProvider = newProvider(c, base.conf)
	authenticationService := &authenticationService{authenticationsBase: base}
	authenticationService.otp = &otp{authenticationsBase: base}
	authenticationService.magicLink = &magicLink{authenticationsBase: base}
	authenticationService.oauth = &oauth{authenticationsBase: base}
	authenticationService.saml = &saml{authenticationsBase: base}
	authenticationService.webAuthn = &webAuthn{authenticationsBase: base}
	authenticationService.totp = &totp{authenticationsBase: base}
	return authenticationService, nil
}

func (auth *authenticationService) MagicLink() MagicLink {
	return auth.magicLink
}

func (auth *authenticationService) OTP() OTP {
	return auth.otp
}

func (auth *authenticationService) TOTP() TOTP {
	return auth.totp
}

func (auth *authenticationService) OAuth() OAuth {
	return auth.oauth
}

func (auth *authenticationService) SAML() SAML {
	return auth.saml
}

func (auth *authenticationService) WebAuthn() WebAuthn {
	return auth.webAuthn
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

	_, err := auth.validateJWT(refreshToken)
	if err != nil {
		logger.LogDebug("invalid refresh token")
		return errors.RefreshTokenError
	}

	httpResponse, err := auth.client.DoGetRequest(api.Routes.Logout(), &api.HTTPRequest{}, refreshToken)
	if err != nil {
		return err
	}
	cookies := httpResponse.Res.Cookies()

	jwtResponse, err := auth.extractJWTResponse(httpResponse.BodyStr)
	if err != nil {
		return err
	}
	if jwtResponse == nil {
		jwtResponse = &JWTResponse{}
	}
	if len(jwtResponse.CookiePath) == 0 {
		jwtResponse.CookiePath = "/"
	}
	jwtResponse.CookieMaxAge = 0
	jwtResponse.CookieExpiration = 0

	// delete cookies by not specifying max-age (e.i. max-age=0)
	cookies = append(cookies, createCookie(&Token{
		JWT:    "",
		Claims: map[string]interface{}{claimAttributeName: SessionCookieName},
	}, jwtResponse))
	cookies = append(cookies, createCookie(&Token{JWT: "",
		Claims: map[string]interface{}{claimAttributeName: RefreshCookieName},
	}, jwtResponse))
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

	// Allow either empty session or refresh tokens if all we want is to validate the session token
	sessionToken, refreshToken := provideTokens(request)
	if sessionToken == "" && refreshToken == "" {
		logger.LogDebug("unable to find token from cookies")
		return false, nil, nil
	}
	return auth.validateSession(sessionToken, refreshToken, false, options...)
}

func (auth *authenticationService) RefreshSession(request *http.Request, w http.ResponseWriter) (bool, *Token, error) {
	return auth.RefreshSessionWithOptions(request, WithResponseOption(w))
}

func (auth *authenticationService) RefreshSessionWithOptions(request *http.Request, options ...Option) (bool, *Token, error) {
	if request == nil {
		return false, nil, errors.MissingProviderError
	}

	// Allow either empty session or refresh tokens if all we want is to validate the session token
	sessionToken, refreshToken := provideTokens(request)
	if sessionToken == "" && refreshToken == "" {
		logger.LogDebug("unable to find token from cookies")
		return false, nil, nil
	}

	return auth.validateSession(sessionToken, refreshToken, true, options...)
}

// AuthenticationMiddleware - middleware used to validate session and invoke if provided a failure and
// success callbacks after calling ValidateSession().
// onFailure will be called when the authentication failed, if empty, will write unauthorized (401) on the response writer.
// onSuccess will be called when the authentication succeeded, if empty, it will generate a new context with the descope user id associated with the given token and runs next.
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

func (auth *authenticationService) validateSession(sessionToken string, refreshToken string, forceRefresh bool, options ...Option) (bool, *Token, error) {
	// Make sure to try and validate either JWT because in the process we make sure we have the public keys
	var token, tToken *Token
	var err, tErr error
	if sessionToken != "" {
		token, err = auth.validateJWT(sessionToken)
	}
	if refreshToken != "" {
		tToken, tErr = auth.validateJWT(refreshToken)
	}
	if !auth.publicKeysProvider.publicKeyExists() {
		logger.LogError("Cannot validate session, no public key available", err)
		return false, nil, errors.NewNoPublicKeyError()
	}
	if err == nil && sessionToken != "" && refreshToken != "" {
		if tErr == nil {
			token.RefreshExpiration = tToken.Expiration
		} else {
			logger.LogError("cannot validate refresh token, refresh expiration will not be available", tErr)
		}
	}
	if sessionToken == "" || err != nil || forceRefresh {
		// check refresh token
		if refreshToken == "" {
			return false, nil, err
		}
		if ok, err := validateTokenError(tErr); !ok {
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
		// No need to check for error again because validateTokenError will return false for any non-nil error
		info.SessionToken.RefreshExpiration = tToken.Expiration
		return true, info.SessionToken, nil
	}

	return true, token, nil
}

func (auth *authenticationsBase) extractJWTResponse(bodyStr string) (*JWTResponse, error) {
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

func (auth *authenticationsBase) collectJwts(jwt, rJwt string, tokens []*Token) ([]*Token, error) {
	var err error
	var token *Token
	if len(jwt) > 0 {
		var err1 error
		token, err1 = auth.validateJWT(jwt)
		if err1 == nil {
			tokens = append(tokens, token)
		} else {
			err = err1
		}
	}
	if len(rJwt) > 0 {
		token2, err2 := auth.validateJWT(rJwt)
		if err2 == nil {
			if token != nil {
				token.RefreshExpiration = token2.Expiration
			}
			token2.RefreshExpiration = token2.Expiration
			tokens = append(tokens, token2)
		} else {
			err = err2
		}
	}

	return tokens, err
}

func (auth *authenticationsBase) extractTokens(jRes *JWTResponse) ([]*Token, error) {

	if jRes == nil {
		return nil, nil
	}
	var tokens []*Token

	tokens, err := auth.collectJwts(jRes.SessionJwt, jRes.RefreshJwt, tokens)
	if err != nil {
		return nil, err
	}
	return tokens, nil
}

func (auth *authenticationsBase) validateJWT(JWT string) (*Token, error) {
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

func (*authenticationsBase) verifyDeliveryMethod(method DeliveryMethod, identifier string, user *User) *errors.WebError {
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

func (auth *authenticationsBase) exchangeTokenWithOptions(code string, url string, options ...Option) (*AuthenticationInfo, error) {
	if code == "" {
		return nil, errors.NewInvalidArgumentError("code")
	}

	httpResponse, err := auth.client.DoGetRequest(url, &api.HTTPRequest{QueryParams: map[string]string{"code": string(code)}}, "")
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(httpResponse, options...)
}

func (auth *authenticationsBase) generateAuthenticationInfo(httpResponse *api.HTTPResponse, options ...Option) (*AuthenticationInfo, error) {
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
		ck := createCookie(tokens[i], jwtResponse)
		if ck != nil {
			cookies = append(cookies, ck)
		}
		if tokens[i].Claims[claimAttributeName] == SessionCookieName {
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

func createCookie(token *Token, jwtRes *JWTResponse) *http.Cookie {

	if token != nil {
		name, _ := token.Claims[claimAttributeName].(string)
		return &http.Cookie{
			Path:     jwtRes.CookiePath,
			Domain:   jwtRes.CookieDomain,
			Name:     name,
			Value:    token.JWT,
			HttpOnly: true,
			MaxAge:   int(jwtRes.CookieMaxAge),
			Expires:  time.Unix(int64(jwtRes.CookieExpiration), 0),
			SameSite: http.SameSiteNoneMode,
			Secure:   true,
		}
	}
	return nil
}

func provideTokens(r *http.Request) (string, string) {
	sessionToken := ""
	// First, check the header for Bearer token
	// Header takes precedence over cookie
	reqToken := r.Header.Get(api.AuthorizationHeaderName)
	if splitToken := strings.Split(reqToken, api.BearerAuthorizationPrefix); len(splitToken) == 2 {
		sessionToken = splitToken[1]
	}

	if sessionToken == "" {
		if sessionCookie, _ := r.Cookie(SessionCookieName); sessionCookie != nil {
			sessionToken = sessionCookie.Value
		}
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

func getPendingRefFromResponse(httpResponse *api.HTTPResponse) (*MagicLinkResponse, error) {
	var response *MagicLinkResponse
	if err := utils.Unmarshal([]byte(httpResponse.BodyStr), &response); err != nil {
		logger.LogError("failed to load pending reference from response", err)
		return response, errors.InvalidPendingRefError
	}
	return response, nil
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

func composeOAuthExchangeTokenURL() string {
	return api.Routes.ExchangeTokenOAuth()
}

func composeSAMLStartURL() string {
	return api.Routes.SAMLStart()
}

func composeSAMLExchangeTokenURL() string {
	return api.Routes.ExchangeTokenSAML()
}

func composeGetSession() string {
	return api.Routes.GetMagicLinkSession()
}

func composeUpdateUserEmailOTP() string {
	return api.Routes.UpdateUserEmailOTP()
}

func composeUpdateUserEmailMagicLink() string {
	return api.Routes.UpdateUserEmailMagiclink()
}

func composeUpdateUserPhone(method DeliveryMethod) string {
	return composeURLMethod(api.Routes.UpdateUserPhoneMagicLink(), method)
}
