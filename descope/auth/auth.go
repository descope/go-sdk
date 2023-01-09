package auth

import (
	"context"
	goErrors "errors"
	"fmt"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/errors"
	"github.com/descope/go-sdk/descope/logger"
	"github.com/descope/go-sdk/descope/utils"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"golang.org/x/exp/slices"
)

const SKEW = time.Second * 5

type AuthParams struct {
	ProjectID           string
	PublicKey           string
	SessionJWTViaCookie bool
}

type authenticationsBase struct {
	client             *api.Client
	conf               *AuthParams
	publicKeysProvider *provider
}

type authenticationService struct {
	authenticationsBase

	otp           OTP
	magicLink     MagicLink
	enchantedLink EnchantedLink
	totp          TOTP
	webAuthn      WebAuthn
	oauth         OAuth
	saml          SAML
}

func NewAuth(conf AuthParams, c *api.Client) (*authenticationService, error) {
	base := authenticationsBase{conf: &conf, client: c}
	base.publicKeysProvider = newProvider(c, base.conf)
	authenticationService := &authenticationService{authenticationsBase: base}
	authenticationService.otp = &otp{authenticationsBase: base}
	authenticationService.magicLink = &magicLink{authenticationsBase: base}
	authenticationService.enchantedLink = &enchantedLink{authenticationsBase: base}
	authenticationService.oauth = &oauth{authenticationsBase: base}
	authenticationService.saml = &saml{authenticationsBase: base}
	authenticationService.webAuthn = &webAuthn{authenticationsBase: base}
	authenticationService.totp = &totp{authenticationsBase: base}
	return authenticationService, nil
}

func (auth *authenticationService) MagicLink() MagicLink {
	return auth.magicLink
}

func (auth *authenticationService) EnchantedLink() EnchantedLink {
	return auth.enchantedLink
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
	if request == nil {
		return errors.MissingRequestError
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

	httpResponse, err := auth.client.DoPostRequest(api.Routes.Logout(), nil, &api.HTTPRequest{}, refreshToken)
	if err != nil {
		return err
	}
	if w == nil {
		return nil
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

	setCookies(cookies, w)
	return nil
}

func (auth *authenticationService) LogoutAll(request *http.Request, w http.ResponseWriter) error {
	if request == nil {
		return errors.MissingRequestError
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

	httpResponse, err := auth.client.DoPostRequest(api.Routes.LogoutAll(), nil, &api.HTTPRequest{}, refreshToken)
	if err != nil {
		return err
	}
	if w == nil {
		return nil
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

	setCookies(cookies, w)
	return nil
}

func (auth *authenticationService) Me(request *http.Request) (*UserResponse, error) {
	if request == nil {
		return nil, errors.MissingRequestError
	}

	_, refreshToken := provideTokens(request)
	if refreshToken == "" {
		logger.LogDebug("unable to find tokens from cookies")
		return nil, errors.RefreshTokenError
	}

	_, err := auth.validateJWT(refreshToken)
	if err != nil {
		logger.LogDebug("invalid refresh token")
		return nil, errors.RefreshTokenError
	}

	httpResponse, err := auth.client.DoGetRequest(api.Routes.Me(), &api.HTTPRequest{}, refreshToken)
	if err != nil {
		return nil, err
	}
	return auth.extractUserResponse(httpResponse.BodyStr)
}

func (auth *authenticationService) ValidateSession(request *http.Request, w http.ResponseWriter) (bool, *Token, error) {
	if request == nil {
		return false, nil, errors.MissingProviderError
	}

	// Allow either empty session or refresh tokens if all we want is to validate the session token
	sessionToken, refreshToken := provideTokens(request)
	if sessionToken == "" && refreshToken == "" {
		logger.LogDebug("unable to find token from cookies")
		return false, nil, nil
	}
	return auth.validateSession(sessionToken, refreshToken, false, w)
}

func (auth *authenticationService) ValidateSessionTokens(sessionToken, refreshToken string) (bool, *Token, error) {
	return auth.validateSession(sessionToken, refreshToken, false, nil)
}

func (auth *authenticationService) RefreshSession(request *http.Request, w http.ResponseWriter) (bool, *Token, error) {
	if request == nil {
		return false, nil, errors.MissingProviderError
	}

	// Allow either empty session or refresh tokens if all we want is to validate the session token
	sessionToken, refreshToken := provideTokens(request)
	if sessionToken == "" && refreshToken == "" {
		logger.LogDebug("unable to find token from cookies")
		return false, nil, nil
	}

	return auth.validateSession(sessionToken, refreshToken, true, w)
}

func (auth *authenticationService) ExchangeAccessKey(accessKey string) (success bool, SessionToken *Token, err error) {
	httpResponse, err := auth.client.DoPostRequest(api.Routes.ExchangeAccessKey(), nil, &api.HTTPRequest{}, accessKey)
	if err != nil {
		logger.LogError("failed to exchange access key", err)
		return false, nil, errors.UnauthorizedError
	}

	jwtResponse, err := auth.extractJWTResponse(httpResponse.BodyStr)
	if err != nil || jwtResponse == nil {
		return false, nil, errors.InvalidAccessKeyResponse
	}

	tokens, err := auth.extractTokens(jwtResponse)
	if err != nil || len(tokens) == 0 {
		return false, nil, errors.InvalidAccessKeyResponse
	}

	return true, tokens[0], nil
}

func (auth *authenticationService) ValidatePermissions(token *Token, permissions []string) bool {
	return auth.ValidateTenantPermissions(token, "", permissions)
}

func (auth *authenticationService) ValidateTenantPermissions(token *Token, tenant string, permissions []string) bool {
	granted := getAuthorizationClaimItems(token, tenant, claimPermissions)
	for i := range permissions {
		if !slices.Contains(granted, permissions[i]) {
			return false
		}
	}
	return true
}

func (auth *authenticationService) ValidateRoles(token *Token, roles []string) bool {
	return auth.ValidateTenantRoles(token, "", roles)
}

func (auth *authenticationService) ValidateTenantRoles(token *Token, tenant string, roles []string) bool {
	membership := getAuthorizationClaimItems(token, tenant, claimRoles)
	for i := range roles {
		if !slices.Contains(membership, roles[i]) {
			return false
		}
	}
	return true
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

func (auth *authenticationService) validateSession(sessionToken string, refreshToken string, forceRefresh bool, w http.ResponseWriter) (bool, *Token, error) {
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
		httpResponse, err := auth.client.DoPostRequest(api.Routes.RefreshToken(), nil, &api.HTTPRequest{}, refreshToken)
		if err != nil {
			return false, nil, errors.FailedToRefreshTokenError
		}
		info, err := auth.generateAuthenticationInfoWithRefreshToken(httpResponse, tToken, w)
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

func (auth *authenticationsBase) extractUserResponse(bodyStr string) (*UserResponse, error) {
	if bodyStr == "" {
		return nil, nil
	}
	res := UserResponse{}
	err := utils.Unmarshal([]byte(bodyStr), &res)
	if err != nil {
		logger.LogError("unable to parse user response", err)
		return nil, err
	}
	return &res, nil
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
	token, err := jwt.Parse([]byte(JWT), jwt.WithKeyProvider(auth.publicKeysProvider), jwt.WithVerify(true), jwt.WithValidate(true), jwt.WithAcceptableSkew(SKEW))
	if err != nil {
		var parseErr error
		token, parseErr = jwt.Parse([]byte(JWT), jwt.WithKeyProvider(auth.publicKeysProvider), jwt.WithVerify(false), jwt.WithValidate(false), jwt.WithAcceptableSkew(SKEW))
		if parseErr != nil {
			err = parseErr
		}
	}
	return NewToken(JWT, token), err
}

func (*authenticationsBase) verifyDeliveryMethod(method DeliveryMethod, loginID string, user *User) *errors.WebError {
	varName := "loginID"
	if loginID == "" {
		return errors.NewInvalidArgumentError(varName)
	}

	switch method {
	case MethodEmail:
		if len(user.Email) == 0 {
			user.Email = loginID
		} else {
			varName = "user.Email"
		}
		if !emailRegex.MatchString(user.Email) {
			return errors.NewInvalidArgumentError(varName)
		}
	case MethodSMS:
		if len(user.Phone) == 0 {
			user.Phone = loginID
		} else {
			varName = "user.Phone"
		}
		if !phoneRegex.MatchString(user.Phone) {
			return errors.NewInvalidArgumentError(varName)
		}
	case MethodWhatsApp:
		if len(user.Phone) == 0 {
			user.Phone = loginID
		} else {
			varName = "user.Phone"
		}
		if !phoneRegex.MatchString(user.Phone) {
			return errors.NewInvalidArgumentError(varName)
		}
	}
	return nil
}

func (auth *authenticationsBase) exchangeToken(code string, url string, w http.ResponseWriter) (*AuthenticationInfo, error) {
	if code == "" {
		return nil, errors.NewInvalidArgumentError("code")
	}

	httpResponse, err := auth.client.DoPostRequest(url, newExchangeTokenBody(code), nil, "")
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(httpResponse, w)
}

func (auth *authenticationsBase) generateAuthenticationInfo(httpResponse *api.HTTPResponse, w http.ResponseWriter) (*AuthenticationInfo, error) {
	return auth.generateAuthenticationInfoWithRefreshToken(httpResponse, nil, w)
}

func (auth *authenticationsBase) generateAuthenticationInfoWithRefreshToken(httpResponse *api.HTTPResponse, refreshToken *Token, w http.ResponseWriter) (*AuthenticationInfo, error) {
	jwtResponse, err := auth.extractJWTResponse(httpResponse.BodyStr)
	if err != nil {
		return nil, err
	}
	tokens, err := auth.extractTokens(jwtResponse)
	if err != nil {
		logger.LogError("unable to extract tokens from request [%s]", err, httpResponse.Req.URL)
		return nil, err
	}

	logger.LogInfo("generateAuthenticationInfoWithRefreshToken body: %s", httpResponse.BodyStr)
	logger.LogInfo("generateAuthenticationInfoWithRefreshToken jwtResponse: %s", fmt.Sprintf("%+v", jwtResponse))
	logger.LogInfo("generateAuthenticationInfoWithRefreshToken tokens: %s", fmt.Sprintf("%+v", tokens))

	cookies := httpResponse.Res.Cookies()
	var sToken *Token
	for i := range tokens {
		addToCookie := true
		if tokens[i].Claims[claimAttributeName] == SessionCookieName {
			sToken = tokens[i]
			if !auth.conf.SessionJWTViaCookie {
				addToCookie = false
			}
		}
		if tokens[i].Claims[claimAttributeName] == RefreshCookieName {
			refreshToken = tokens[i]
		}
		if addToCookie {
			ck := createCookie(tokens[i], jwtResponse)
			if ck != nil {
				cookies = append(cookies, ck)
			}
		}
	}

	if refreshToken == nil || refreshToken.JWT == "" {
		if refreshToken == nil {
			logger.LogInfo("generateAuthenticationInfoWithRefreshToken empty refreshToken going to take it from cookies..")
		} else {
			logger.LogInfo("generateAuthenticationInfoWithRefreshToken empty refreshToken.JWT going to take it from cookies..")
		}

		for i := range cookies {
			logger.LogInfo("generateAuthenticationInfoWithRefreshToken handling cookie %s", cookies[i].Name)
			if cookies[i].Name == RefreshCookieName {
				logger.LogInfo("generateAuthenticationInfoWithRefreshToken found DSR, value %s", cookies[i].Value)
				refreshToken, err = auth.validateJWT(cookies[i].Value)
				if err != nil {
					logger.LogInfo("generateAuthenticationInfoWithRefreshToken failed to validate DSR jwt [%s]", err.Error())
					return nil, err
				}
			}
		}
	}

	if refreshToken == nil {
		logger.LogInfo("generateAuthenticationInfoWithRefreshToken RefreshToken is nil")
	} else {
		logger.LogInfo("generateAuthenticationInfoWithRefreshToken RefreshToken is NOT nil [%s]", refreshToken.JWT)
	}

	setCookies(cookies, w)
	logger.LogInfo("generateAuthenticationInfoWithRefreshToken cookies: %s", fmt.Sprintf("%+v", cookies))
	return NewAuthenticationInfo(jwtResponse, sToken, refreshToken), err
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
	if r == nil {
		return "", ""
	}
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

func getAuthorizationClaimItems(token *Token, tenant string, claim string) []string {
	items := []string{}

	// in case ValidateSession failed or there's no Claims map for some reason
	if token == nil || token.Claims == nil {
		return items
	}

	// look for the granted claim list in the appropriate place
	if tenant == "" {
		if v, ok := token.Claims[claim].([]interface{}); ok {
			for i := range v {
				if item, ok := v[i].(string); ok {
					items = append(items, item)
				}
			}
		}
	} else {
		if v, ok := token.GetTenantValue(tenant, claim).([]interface{}); ok {
			for i := range v {
				if item, ok := v[i].(string); ok {
					items = append(items, item)
				}
			}
		}
	}

	// warn if it seems like programmer forgot the tenant ID
	if len(items) == 0 && tenant == "" && len(token.GetTenants()) != 0 {
		logger.LogDebug("no authorization items found but tenant might need to be specified")
	}

	return items
}

func getPendingRefFromResponse(httpResponse *api.HTTPResponse) (*EnchantedLinkResponse, error) {
	var response *EnchantedLinkResponse
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

func composeEnchantedLinkSignInURL() string {
	return composeURLMethod(api.Routes.SignInEnchantedLink(), MethodEmail)
}

func composeEnchantedLinkSignUpURL() string {
	return composeURLMethod(api.Routes.SignUpEnchantedLink(), MethodEmail)
}

func composeEnchantedLinkSignUpOrInURL() string {
	return composeURLMethod(api.Routes.SignUpOrInEnchantedLink(), MethodEmail)
}

func composeVerifyEnchantedLinkURL() string {
	return api.Routes.VerifyEnchantedLink()
}

func composeGetSession() string {
	return api.Routes.GetEnchantedLinkSession()
}

func composeUpdateUserEmailEnchantedLink() string {
	return api.Routes.UpdateUserEmailEnchantedlink()
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

func composeUpdateUserEmailOTP() string {
	return api.Routes.UpdateUserEmailOTP()
}

func composeUpdateUserEmailMagicLink() string {
	return api.Routes.UpdateUserEmailMagiclink()
}

func composeUpdateUserPhoneMagiclink(method DeliveryMethod) string {
	return composeURLMethod(api.Routes.UpdateUserPhoneMagicLink(), method)
}

func composeUpdateUserPhoneOTP(method DeliveryMethod) string {
	return composeURLMethod(api.Routes.UpdateUserPhoneOTP(), method)
}

func redirectToURL(url string, w http.ResponseWriter) {
	if w == nil {
		return
	}
	w.Header().Set(RedirectLocationCookieName, url)
	w.WriteHeader(http.StatusTemporaryRedirect)
}

func setCookies(cookies []*http.Cookie, w http.ResponseWriter) {
	if w == nil {
		return
	}
	for i := range cookies {
		http.SetCookie(w, cookies[i])
	}
}
