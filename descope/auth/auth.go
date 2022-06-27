package auth

import (
	goErrors "errors"
	"net/http"
	"path"

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

func (auth *authenticationService) SignInOTP(method DeliveryMethod, identifier string) error {
	if identifier == "" {
		return errors.NewInvalidArgumentError("identifier")
	}

	_, err := auth.client.DoPostRequest(composeSignInURL(method), newSignInRequestBody(identifier), nil, "")
	return err
}

func (auth *authenticationService) SignUpOTP(method DeliveryMethod, identifier string, user *User) error {
	if err := auth.verifyDeliveryMethod(method, identifier); err != nil {
		return err
	}

	_, err := auth.client.DoPostRequest(composeSignUpURL(method), newAuthenticationSignUpRequestBody(method, identifier, user), nil, "")
	return err
}

func (auth *authenticationService) VerifyCode(method DeliveryMethod, identifier string, code string, w http.ResponseWriter) (*AuthenticationInfo, error) {
	return auth.VerifyCodeWithOptions(method, identifier, code, WithResponseOption(w))
}

func (auth *authenticationService) VerifyCodeWithOptions(method DeliveryMethod, identifier string, code string, options ...Option) (*AuthenticationInfo, error) {
	if identifier == "" {
		return nil, errors.NewInvalidArgumentError("identifier")
	}
	if method == "" {
		if phoneRegex.MatchString(identifier) {
			method = MethodSMS
		}

		if emailRegex.MatchString(identifier) {
			method = MethodEmail
		}

		if method == "" {
			return nil, errors.NewInvalidArgumentError("method")
		}
	}

	httpResponse, err := auth.client.DoPostRequest(composeVerifyCodeURL(method), newAuthenticationVerifyRequestBody(identifier, code), nil, "")
	if err != nil {
		return nil, err
	}
	tokens, err := auth.extractTokens(httpResponse.BodyStr)
	if err != nil {
		logger.LogError("unable to extract tokens", err)
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
	return NewAuthenticationInfo(token), err
}

func getPendingRefFromResponse(httpResponse *api.HTTPResponse) (*MagicLinkResponse, error) {
	var response *MagicLinkResponse
	if err := utils.Unmarshal([]byte(httpResponse.BodyStr), &response); err != nil {
		logger.LogError("failed to load pending reference from response", err)
		return response, errors.InvalidPendingRefError
	}
	return response, nil
}

func (auth *authenticationService) SignInMagicLink(method DeliveryMethod, identifier, URI string) error {
	if identifier == "" {
		return errors.NewInvalidArgumentError("identifier")
	}
	_, err := auth.client.DoPostRequest(composeMagicLinkSignInURL(method), newMagicLinkAuthenticationRequestBody(identifier, URI, false), nil, "")
	return err
}

func (auth *authenticationService) SignUpMagicLink(method DeliveryMethod, identifier, URI string, user *User) error {
	if err := auth.verifyDeliveryMethod(method, identifier); err != nil {
		return err
	}

	_, err := auth.client.DoPostRequest(composeMagicLinkSignUpURL(method), newMagicLinkAuthenticationSignUpRequestBody(method, identifier, URI, user, false), nil, "")
	return err
}

func (auth *authenticationService) SignInMagicLinkCrossDevice(method DeliveryMethod, identifier, URI string) (*MagicLinkResponse, error) {
	if identifier == "" {
		return nil, errors.NewInvalidArgumentError("identifier")
	}
	httpResponse, err := auth.client.DoPostRequest(composeMagicLinkSignInURL(method), newMagicLinkAuthenticationRequestBody(identifier, URI, true), nil, "")
	if err != nil {
		return nil, err
	}
	return getPendingRefFromResponse(httpResponse)
}

func (auth *authenticationService) SignUpMagicLinkCrossDevice(method DeliveryMethod, identifier, URI string, user *User) (*MagicLinkResponse, error) {
	if err := auth.verifyDeliveryMethod(method, identifier); err != nil {
		return nil, err
	}

	httpResponse, err := auth.client.DoPostRequest(composeMagicLinkSignUpURL(method), newMagicLinkAuthenticationSignUpRequestBody(method, identifier, URI, user, true), nil, "")
	if err != nil {
		return nil, err
	}
	return getPendingRefFromResponse(httpResponse)
}

func (auth *authenticationService) GetMagicLinkSession(pendingRef string, w http.ResponseWriter) (*AuthenticationInfo, error) {
	return auth.GetMagicLinkSessionWithOptions(pendingRef, WithResponseOption(w))
}

func (auth *authenticationService) GetMagicLinkSessionWithOptions(pendingRef string, options ...Option) (*AuthenticationInfo, error) {
	httpResponse, err := auth.client.DoPostRequest(composeGetMagicLinkSession(), newAuthenticationGetMagicLinkSessionBody(pendingRef), nil, "")
	if err != nil {
		if err == errors.UnauthorizedError {
			return nil, errors.PendingSessionTokenError
		}
		return nil, err
	}
	return auth.authenticationInfoFromResponse(httpResponse, options...)
}

func (auth *authenticationService) VerifyMagicLink(token string, w http.ResponseWriter) (*AuthenticationInfo, error) {
	return auth.VerifyMagicLinkWithOptions(token, WithResponseOption(w))
}

// extracts authentication info from response cookies, and set it on options
func (auth *authenticationService) authenticationInfoFromResponse(httpResponse *api.HTTPResponse, options ...Option) (*AuthenticationInfo, error) {
	tokens, err := auth.extractTokens(httpResponse.BodyStr)
	if err != nil {
		logger.LogError("unable to validate refreshed token", err)
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
	return NewAuthenticationInfo(token), nil
}

func (auth *authenticationService) VerifyMagicLinkWithOptions(token string, options ...Option) (*AuthenticationInfo, error) {
	httpResponse, err := auth.client.DoPostRequest(composeVerifyMagicLinkURL(), newMagicLinkAuthenticationVerifyRequestBody(token), nil, "")
	if err != nil {
		return nil, err
	}
	return auth.authenticationInfoFromResponse(httpResponse, options...)
}

func (auth *authenticationService) OAuthStart(provider OAuthProvider, w http.ResponseWriter) (string, error) {
	return auth.OAuthStartWithOptions(provider, WithResponseOption(w))
}

func (auth *authenticationService) OAuthStartWithOptions(provider OAuthProvider, options ...Option) (url string, err error) {
	httpResponse, err := auth.client.DoGetRequest(composeOAuthURL(), &api.HTTPRequest{QueryParams: map[string]string{"provider": string(provider)}}, "")
	if err != nil {
		return
	}

	if httpResponse.Res != nil {
		urlObj, err := httpResponse.Res.Location()
		if err != nil {
			logger.LogError("failed to parse location from response for [%s]", err, provider)
			return "", err
		}
		url = urlObj.String()
		Options(options).CopyResponse(httpResponse.Res, httpResponse.BodyStr)
	}

	return
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

func (auth *authenticationService) ValidateSession(request *http.Request, w http.ResponseWriter) (bool, *AuthenticationInfo, error) {
	return auth.ValidateSessionWithOptions(request, WithResponseOption(w))
}

func (auth *authenticationService) ValidateSessionWithOptions(request *http.Request, options ...Option) (bool, *AuthenticationInfo, error) {
	if request == nil {
		return false, nil, errors.MissingProviderError
	}

	sessionToken, refreshToken := provideTokens(request)
	if refreshToken == "" {
		logger.LogDebug("unable to find tokens from cookies")
		return false, nil, errors.RefreshTokenError
	}

	return auth.validateSession(sessionToken, refreshToken, options...)
}

// AuthenticationMiddleware - middleware used to validate session and invoke if provided a failure and
// success callbacks after calling ValidateSession().
// onFailure will be called when the authentication failed, if empty, will write unauthorized (401) on the response writer.
func AuthenticationMiddleware(auth Authentication, onFailure func(http.ResponseWriter, *http.Request, error)) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ok, _, err := auth.ValidateSession(r, w); ok {
				next.ServeHTTP(w, r)
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

func (auth *authenticationService) validateSession(sessionToken string, refreshToken string, options ...Option) (bool, *AuthenticationInfo, error) {
	if sessionToken == "" {
		return false, nil, errors.NewValidationError("empty sessionToken")
	}

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
		tokens, err := auth.extractTokens(httpResponse.BodyStr)
		if err != nil {
			logger.LogError("unable to extract tokens after refresh", err)
			return false, nil, err
		}
		cookies := httpResponse.Res.Cookies()
		var token *Token
		sessionJWT := ""
		for i := range tokens {
			ck := createCookie(tokens[i])
			if ck != nil {
				cookies = append(cookies, ck)
			}
			if tokens[i].Claims["cookieName"] == SessionCookieName {
				token = tokens[i]
				sessionJWT = token.JWT
			}
		}
		Options(options).SetCookies(cookies)
		token, err = auth.validateJWT(sessionJWT)
		if err != nil {
			logger.LogError("unable to validate refreshed token", err)
			return false, nil, err
		}
		return true, NewAuthenticationInfo(token), err
	}

	return true, NewAuthenticationInfo(token), nil
}

func (auth *authenticationService) extractTokens(bodyStr string) ([]*Token, error) {
	if bodyStr == "" {
		return nil, nil
	}
	t := JWTResponse{}
	err := utils.Unmarshal([]byte(bodyStr), &t)
	if err != nil {
		logger.LogError("unable to parse token from response", err)
		return nil, err
	}

	if len(t.JWTS) == 0 {
		return nil, nil
	}
	var tokens []*Token
	for i := range t.JWTS {
		token, err := auth.validateJWT(t.JWTS[i])
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

func (*authenticationService) verifyDeliveryMethod(method DeliveryMethod, identifier string) *errors.WebError {
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

func createCookie(token *Token) *http.Cookie {
	if token != nil {
		path, _ := token.Claims["path"].(string)
		domain, _ := token.Claims["domain"].(string)
		name, _ := token.Claims["cookieName"].(string)
		return &http.Cookie{Path: path, Domain: domain, Name: name, Value: token.JWT, HttpOnly: true}
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

func composeVerifyCodeURL(method DeliveryMethod) string {
	return composeURLMethod(api.Routes.VerifyCode(), method)
}

func composeMagicLinkSignInURL(method DeliveryMethod) string {
	return composeURLMethod(api.Routes.SignInMagicLink(), method)
}

func composeMagicLinkSignUpURL(method DeliveryMethod) string {
	return composeURLMethod(api.Routes.SignUpMagicLink(), method)
}

func composeVerifyMagicLinkURL() string {
	return api.Routes.VerifyMagicLink()
}

func composeOAuthURL() string {
	return api.Routes.OAuthStart()
}

func composeGetMagicLinkSession() string {
	return api.Routes.GetMagicLinkSession()
}
