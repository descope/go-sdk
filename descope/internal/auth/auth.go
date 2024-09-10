package auth

import (
	"context"
	goErrors "errors"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/logger"
	"github.com/descope/go-sdk/descope/sdk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"golang.org/x/exp/slices"
)

const SKEW = time.Second * 5

type AuthParams struct {
	ProjectID           string
	PublicKey           string
	SessionJWTViaCookie bool
	CookieDomain        string
	CookieSameSite      http.SameSite
}

type authenticationsBase struct {
	client             *api.Client
	conf               *AuthParams
	publicKeysProvider *provider
}

type authenticationService struct {
	authenticationsBase

	otp           sdk.OTP
	magicLink     sdk.MagicLink
	enchantedLink sdk.EnchantedLink
	totp          sdk.TOTP
	notp          sdk.NOTP
	password      sdk.Password
	webAuthn      sdk.WebAuthn
	oauth         sdk.OAuth
	saml          sdk.SAML
	sso           sdk.SSOServiceProvider
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
	authenticationService.sso = &sso{authenticationsBase: base}
	authenticationService.webAuthn = &webAuthn{authenticationsBase: base}
	authenticationService.totp = &totp{authenticationsBase: base}
	authenticationService.notp = &notp{authenticationsBase: base}
	authenticationService.password = &password{authenticationsBase: base}
	return authenticationService, nil
}

func (auth *authenticationService) MagicLink() sdk.MagicLink {
	return auth.magicLink
}

func (auth *authenticationService) EnchantedLink() sdk.EnchantedLink {
	return auth.enchantedLink
}

func (auth *authenticationService) OTP() sdk.OTP {
	return auth.otp
}

func (auth *authenticationService) TOTP() sdk.TOTP {
	return auth.totp
}

func (auth *authenticationService) NOTP() sdk.NOTP {
	return auth.notp
}

func (auth *authenticationService) Password() sdk.Password {
	return auth.password
}

func (auth *authenticationService) OAuth() sdk.OAuth {
	return auth.oauth
}

func (auth *authenticationService) SAML() sdk.SAML {
	return auth.saml
}

func (auth *authenticationService) SSO() sdk.SSOServiceProvider {
	return auth.sso
}

func (auth *authenticationService) WebAuthn() sdk.WebAuthn {
	return auth.webAuthn
}

func (auth *authenticationService) Logout(request *http.Request, w http.ResponseWriter) error {
	return auth.logout(request, w)
}

func (auth *authenticationService) LogoutWithToken(refreshToken string, w http.ResponseWriter) error {
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: refreshToken})
	return auth.logout(request, w)
}

func (auth *authenticationService) logout(request *http.Request, w http.ResponseWriter) error {
	if request == nil {
		return utils.NewInvalidArgumentError("request")
	}

	_, refreshToken := provideTokens(request)
	if refreshToken == "" {
		logger.LogDebug("Unable to find tokens from cookies")
		return descope.ErrRefreshToken.WithMessage("Unable to find tokens from cookies")
	}

	_, err := auth.validateJWT(refreshToken)
	if err != nil {
		logger.LogDebug("Invalid refresh token")
		return descope.ErrRefreshToken.WithMessage("Invalid refresh token")
	}

	httpResponse, err := auth.client.DoPostRequest(request.Context(), api.Routes.Logout(), nil, &api.HTTPRequest{}, refreshToken)
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
		jwtResponse = &descope.JWTResponse{}
	}
	if len(jwtResponse.CookiePath) == 0 {
		jwtResponse.CookiePath = "/"
	}
	jwtResponse.CookieMaxAge = 0
	jwtResponse.CookieExpiration = 0

	// delete cookies by not specifying max-age (e.i. max-age=0)
	cookies = append(cookies, auth.createCookie(&descope.Token{
		JWT:    "",
		Claims: map[string]interface{}{claimAttributeName: descope.SessionCookieName},
	}, jwtResponse))
	cookies = append(cookies, auth.createCookie(&descope.Token{JWT: "",
		Claims: map[string]interface{}{claimAttributeName: descope.RefreshCookieName},
	}, jwtResponse))

	setCookies(cookies, w)
	return nil
}

func (auth *authenticationService) LogoutAll(request *http.Request, w http.ResponseWriter) error {
	return auth.logoutAll(request, w)
}

func (auth *authenticationService) LogoutAllWithToken(refreshToken string, w http.ResponseWriter) error {
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: refreshToken})
	return auth.logoutAll(request, w)
}

func (auth *authenticationService) logoutAll(request *http.Request, w http.ResponseWriter) error {
	if request == nil {
		return utils.NewInvalidArgumentError("request")
	}

	_, refreshToken := provideTokens(request)
	if refreshToken == "" {
		logger.LogDebug("Unable to find tokens from cookies")
		return descope.ErrRefreshToken.WithMessage("Unable to find tokens from cookies")
	}

	_, err := auth.validateJWT(refreshToken)
	if err != nil {
		logger.LogDebug("Invalid refresh token")
		return descope.ErrRefreshToken.WithMessage("Invalid refresh token")
	}

	httpResponse, err := auth.client.DoPostRequest(request.Context(), api.Routes.LogoutAll(), nil, &api.HTTPRequest{}, refreshToken)
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
		jwtResponse = &descope.JWTResponse{}
	}
	if len(jwtResponse.CookiePath) == 0 {
		jwtResponse.CookiePath = "/"
	}
	jwtResponse.CookieMaxAge = 0
	jwtResponse.CookieExpiration = 0

	// delete cookies by not specifying max-age (e.i. max-age=0)
	cookies = append(cookies, auth.createCookie(&descope.Token{
		JWT:    "",
		Claims: map[string]interface{}{claimAttributeName: descope.SessionCookieName},
	}, jwtResponse))
	cookies = append(cookies, auth.createCookie(&descope.Token{JWT: "",
		Claims: map[string]interface{}{claimAttributeName: descope.RefreshCookieName},
	}, jwtResponse))

	setCookies(cookies, w)
	return nil
}

func (auth *authenticationService) Me(request *http.Request) (*descope.UserResponse, error) {
	if request == nil {
		return nil, utils.NewInvalidArgumentError("request")
	}

	_, refreshToken := provideTokens(request)
	if refreshToken == "" {
		logger.LogDebug("Unable to find tokens from cookies")
		return nil, descope.ErrRefreshToken.WithMessage("Unable to find tokens from cookies")
	}

	_, err := auth.validateJWT(refreshToken)
	if err != nil {
		logger.LogDebug("Invalid refresh token")
		return nil, descope.ErrRefreshToken.WithMessage("Invalid refresh token")
	}

	httpResponse, err := auth.client.DoGetRequest(request.Context(), api.Routes.Me(), &api.HTTPRequest{}, refreshToken)
	if err != nil {
		return nil, err
	}
	return auth.extractUserResponse(httpResponse.BodyStr)
}

func (auth *authenticationService) MyTenants(ctx context.Context, request *http.Request, dct bool, tenantIDs []string) (*descope.TenantsResponse, error) {
	if request == nil {
		return nil, utils.NewInvalidArgumentError("request")
	}

	if dct && len(tenantIDs) > 0 {
		return nil, utils.NewInvalidArgumentError("Only one of dct or tenant ids should be provided")
	}

	_, refreshToken := provideTokens(request)
	if refreshToken == "" {
		logger.LogDebug("Unable to find tokens from cookies")
		return nil, descope.ErrRefreshToken.WithMessage("Unable to find tokens from cookies")
	}

	_, err := auth.validateJWT(refreshToken)
	if err != nil {
		logger.LogDebug("Invalid refresh token")
		return nil, descope.ErrRefreshToken.WithMessage("Invalid refresh token")
	}

	httpResponse, err := auth.client.DoPostRequest(ctx, api.Routes.MeTenants(), map[string]any{"dct": dct, "ids": tenantIDs}, &api.HTTPRequest{}, refreshToken)
	if err != nil {
		return nil, err
	}
	res := descope.TenantsResponse{}
	err = utils.Unmarshal([]byte(httpResponse.BodyStr), &res)
	if err != nil {
		logger.LogError("Unable to parse tenant response", err)
		return nil, err
	}
	return &res, nil
}

func (auth *authenticationService) History(request *http.Request) ([]*descope.UserHistoryResponse, error) {
	if request == nil {
		return nil, utils.NewInvalidArgumentError("request")
	}

	_, refreshToken := provideTokens(request)
	if refreshToken == "" {
		logger.LogDebug("Unable to find tokens from cookies")
		return nil, descope.ErrRefreshToken.WithMessage("Unable to find tokens from cookies")
	}

	_, err := auth.validateJWT(refreshToken)
	if err != nil {
		logger.LogDebug("Invalid refresh token")
		return nil, descope.ErrRefreshToken.WithMessage("Invalid refresh token")
	}

	httpResponse, err := auth.client.DoGetRequest(request.Context(), api.Routes.History(), &api.HTTPRequest{}, refreshToken)
	if err != nil {
		return nil, err
	}
	return auth.extractUserHistoryResponse(httpResponse.BodyStr)
}

// Validate Session

func (auth *authenticationService) ValidateSessionWithRequest(request *http.Request) (bool, *descope.Token, error) {
	if request == nil {
		return false, nil, utils.NewInvalidArgumentError("request")
	}
	sessionToken, _ := provideTokens(request)
	if sessionToken == "" {
		return false, nil, descope.ErrMissingArguments.WithMessage("Request doesn't contain session token")
	}
	return auth.validateSession(request.Context(), sessionToken)
}

func (auth *authenticationService) ValidateSessionWithToken(ctx context.Context, sessionToken string) (bool, *descope.Token, error) {
	if sessionToken == "" {
		return false, nil, utils.NewInvalidArgumentError("sessionToken")
	}
	return auth.validateSession(ctx, sessionToken)
}

func (auth *authenticationService) validateSession(_ context.Context, sessionToken string) (valid bool, token *descope.Token, err error) {
	token, err = auth.validateJWT(sessionToken)
	if err != nil {
		return false, nil, err
	}
	return true, token, nil
}

// Refresh Session

func (auth *authenticationService) RefreshSessionWithRequest(request *http.Request, w http.ResponseWriter) (bool, *descope.Token, error) {
	if request == nil {
		return false, nil, utils.NewInvalidArgumentError("request")
	}
	_, refreshToken := provideTokens(request)
	if refreshToken == "" {
		return false, nil, descope.ErrMissingArguments.WithMessage("Request doesn't contain refresh token")
	}
	return auth.refreshSession(request.Context(), refreshToken, w)
}

func (auth *authenticationService) RefreshSessionWithToken(ctx context.Context, refreshToken string) (bool, *descope.Token, error) {
	if refreshToken == "" {
		return false, nil, utils.NewInvalidArgumentError("refreshToken")
	}
	return auth.refreshSession(ctx, refreshToken, nil)
}

func (auth *authenticationService) refreshSession(ctx context.Context, refreshToken string, w http.ResponseWriter) (bool, *descope.Token, error) {
	token, err := auth.validateJWT(refreshToken)
	if err != nil {
		return false, nil, err
	}

	// refresh session token
	httpResponse, err := auth.client.DoPostRequest(ctx, api.Routes.RefreshToken(), nil, &api.HTTPRequest{}, refreshToken)
	if err != nil {
		return false, nil, err
	}
	info, err := auth.generateAuthenticationInfoWithRefreshToken(httpResponse, token, w)
	if err != nil {
		return false, nil, err
	}
	// No need to check for error again because validateTokenError will return false for any non-nil error
	info.SessionToken.RefreshExpiration = token.Expiration
	return true, info.SessionToken, nil
}

// Validate & Refresh Session

func (auth *authenticationService) ValidateAndRefreshSessionWithRequest(request *http.Request, w http.ResponseWriter) (bool, *descope.Token, error) {
	if request == nil {
		return false, nil, utils.NewInvalidArgumentError("request")
	}
	sessionToken, refreshToken := provideTokens(request)
	return auth.validateAndRefreshSessionWithTokens(request.Context(), sessionToken, refreshToken, w)
}

func (auth *authenticationService) ValidateAndRefreshSessionWithTokens(ctx context.Context, sessionToken, refreshToken string) (bool, *descope.Token, error) {
	return auth.validateAndRefreshSessionWithTokens(ctx, sessionToken, refreshToken, nil)
}

func (auth *authenticationService) validateAndRefreshSessionWithTokens(ctx context.Context, sessionToken, refreshToken string, w http.ResponseWriter) (valid bool, token *descope.Token, err error) {
	if sessionToken == "" && refreshToken == "" {
		return false, nil, descope.ErrMissingArguments.WithMessage("Both sessionToken and refreshToken are empty")
	}
	if sessionToken != "" {
		if valid, token, err = auth.validateSession(ctx, sessionToken); valid {
			return
		}
	}
	if refreshToken != "" {
		if valid, token, err = auth.refreshSession(ctx, refreshToken, w); valid {
			return
		}
	}
	return false, nil, err
}

func (auth *authenticationService) ExchangeAccessKey(ctx context.Context, accessKey string, loginOptions *descope.AccessKeyLoginOptions) (success bool, SessionToken *descope.Token, err error) {
	httpResponse, err := auth.client.DoPostRequest(ctx, api.Routes.ExchangeAccessKey(), newExchangeAccessKeyBody(loginOptions), &api.HTTPRequest{}, accessKey)
	if err != nil {
		logger.LogError("Failed to exchange access key", err)
		return false, nil, err
	}

	jwtResponse, err := auth.extractJWTResponse(httpResponse.BodyStr)
	if err != nil || jwtResponse == nil {
		return false, nil, descope.ErrUnexpectedResponse.WithMessage("Invalid data in access key response")
	}

	tokens, err := auth.extractTokens(jwtResponse)
	if err != nil { // notest
		errMsg := err.Error()
		if len(errMsg) == 0 {
			errMsg = "Missing token in JWT response"
		}
		return false, nil, descope.ErrUnexpectedResponse.WithMessage(errMsg)
	}

	if len(tokens) == 0 {
		return false, nil, descope.ErrUnexpectedResponse.WithMessage("Missing token in JWT response")
	}

	return true, tokens[0], nil
}

func (auth *authenticationService) ValidatePermissions(ctx context.Context, token *descope.Token, permissions []string) bool {
	return auth.ValidateTenantPermissions(ctx, token, "", permissions)
}

func (auth *authenticationService) GetMatchedPermissions(ctx context.Context, token *descope.Token, permissions []string) []string {
	return auth.GetMatchedTenantPermissions(ctx, token, "", permissions)
}

func (auth *authenticationService) ValidateTenantPermissions(_ context.Context, token *descope.Token, tenant string, permissions []string) bool {
	if tenant != "" && !isAssociatedWithTenant(token, tenant) {
		return false
	}
	granted := getAuthorizationClaimItems(token, tenant, claimPermissions)
	for i := range permissions {
		if !slices.Contains(granted, permissions[i]) {
			return false
		}
	}
	return true
}

func (auth *authenticationService) GetMatchedTenantPermissions(_ context.Context, token *descope.Token, tenant string, permissions []string) []string {
	if tenant != "" && !isAssociatedWithTenant(token, tenant) {
		return []string{}
	}
	granted := getAuthorizationClaimItems(token, tenant, claimPermissions)
	matched := []string{}
	for i := range permissions {
		if slices.Contains(granted, permissions[i]) {
			matched = append(matched, permissions[i])
		}
	}
	return matched
}

func (auth *authenticationService) ValidateRoles(ctx context.Context, token *descope.Token, roles []string) bool {
	return auth.ValidateTenantRoles(ctx, token, "", roles)
}

func (auth *authenticationService) GetMatchedRoles(ctx context.Context, token *descope.Token, roles []string) []string {
	return auth.GetMatchedTenantRoles(ctx, token, "", roles)
}

func (auth *authenticationService) ValidateTenantRoles(_ context.Context, token *descope.Token, tenant string, roles []string) bool {
	if tenant != "" && !isAssociatedWithTenant(token, tenant) {
		return false
	}
	membership := getAuthorizationClaimItems(token, tenant, claimRoles)
	for i := range roles {
		if !slices.Contains(membership, roles[i]) {
			return false
		}
	}
	return true
}

func (auth *authenticationService) GetMatchedTenantRoles(_ context.Context, token *descope.Token, tenant string, roles []string) []string {
	if tenant != "" && !isAssociatedWithTenant(token, tenant) {
		return []string{}
	}
	membership := getAuthorizationClaimItems(token, tenant, claimRoles)
	matched := []string{}
	for i := range roles {
		if slices.Contains(membership, roles[i]) {
			matched = append(matched, roles[i])
		}
	}
	return matched
}

// Select Tenant

func (auth *authenticationService) SelectTenantWithRequest(ctx context.Context, tenantID string, request *http.Request, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	if request == nil {
		return nil, utils.NewInvalidArgumentError("request")
	}
	_, refreshToken := provideTokens(request)
	if refreshToken == "" {
		return nil, descope.ErrMissingArguments.WithMessage("Request doesn't contain refresh token")
	}
	return auth.selectTenant(ctx, tenantID, refreshToken, w)
}

func (auth *authenticationService) SelectTenantWithToken(ctx context.Context, tenantID string, refreshToken string) (*descope.AuthenticationInfo, error) {
	if refreshToken == "" {
		return nil, utils.NewInvalidArgumentError("refreshToken")
	}
	return auth.selectTenant(ctx, tenantID, refreshToken, nil)
}

func (auth *authenticationService) selectTenant(ctx context.Context, tenantID string, refreshToken string, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	token, err := auth.validateJWT(refreshToken)
	if err != nil {
		return nil, err
	}

	httpResponse, err := auth.client.DoPostRequest(ctx, api.Routes.SelectTenant(), map[string]any{"tenant": tenantID}, &api.HTTPRequest{}, refreshToken)
	if err != nil {
		return nil, err
	}
	info, err := auth.generateAuthenticationInfoWithRefreshToken(httpResponse, token, w)
	if err != nil {
		return nil, err
	}
	// No need to check for error again because validateTokenError will return false for any non-nil error
	info.SessionToken.RefreshExpiration = token.Expiration
	return info, nil
}

func (auth *authenticationsBase) extractJWTResponse(bodyStr string) (*descope.JWTResponse, error) {
	if bodyStr == "" {
		return nil, nil
	}
	jRes := descope.JWTResponse{}
	err := utils.Unmarshal([]byte(bodyStr), &jRes)
	if err != nil {
		logger.LogError("Unable to parse jwt response", err)
		return nil, err
	}
	return &jRes, nil
}

func (auth *authenticationsBase) extractUserResponse(bodyStr string) (*descope.UserResponse, error) {
	res := descope.UserResponse{}
	err := utils.Unmarshal([]byte(bodyStr), &res)
	if err != nil {
		logger.LogError("Unable to parse user response", err)
		return nil, err
	}
	return &res, nil
}

func (auth *authenticationsBase) extractUserHistoryResponse(bodyStr string) ([]*descope.UserHistoryResponse, error) {
	res := []*descope.UserHistoryResponse{}
	err := utils.Unmarshal([]byte(bodyStr), &res)
	if err != nil {
		logger.LogError("Unable to parse user history response", err)
		return nil, err
	}
	return res, nil
}

func (auth *authenticationsBase) collectJwts(jwt, rJwt string, tokens []*descope.Token) ([]*descope.Token, error) {
	var err error
	var token *descope.Token
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

func (auth *authenticationsBase) extractTokens(jRes *descope.JWTResponse) ([]*descope.Token, error) {
	if jRes == nil {
		return nil, nil
	}
	var tokens []*descope.Token

	tokens, err := auth.collectJwts(jRes.SessionJwt, jRes.RefreshJwt, tokens)
	if err != nil {
		return nil, err
	}
	return tokens, nil
}

func (auth *authenticationsBase) validateJWT(JWT string) (*descope.Token, error) {
	token, err := jwt.Parse([]byte(JWT), jwt.WithKeyProvider(auth.publicKeysProvider), jwt.WithVerify(true), jwt.WithValidate(true), jwt.WithAcceptableSkew(SKEW))
	if err != nil {
		var parseErr error
		token, parseErr = jwt.Parse([]byte(JWT), jwt.WithKeyProvider(auth.publicKeysProvider), jwt.WithVerify(false), jwt.WithValidate(false), jwt.WithAcceptableSkew(SKEW))
		if parseErr != nil {
			err = parseErr
		}
		err = convertTokenError(err)
	}

	// if the validation failed and we got an error from `convertTokenError` that's not
	// just about the token being invalid that would usually just mean that fetching
	// the public key failed because of something important, and we should include
	// the reason in the returned error
	if !auth.publicKeysProvider.publicKeyExists() {
		logger.LogInfo("Cannot validate or refresh session, no public key available")
		if descope.ErrInvalidToken.Is(err) {
			err = descope.ErrPublicKey
		} else if !descope.ErrPublicKey.Is(err) {
			err = descope.ErrPublicKey.WithMessage("%s", err.Error())
		}
	}

	return descope.NewToken(JWT, token), err
}

func (*authenticationsBase) verifyDeliveryMethod(method descope.DeliveryMethod, loginID string, user *descope.User) *descope.Error {
	varName := "loginID"
	if loginID == "" {
		return utils.NewInvalidArgumentError(varName)
	}

	switch method {
	case descope.MethodEmail:
		if len(user.Email) == 0 {
			user.Email = loginID
		} else {
			varName = "user.Email"
		}
		if !emailRegex.MatchString(user.Email) {
			return utils.NewInvalidArgumentError(varName)
		}
	case descope.MethodSMS:
		if len(user.Phone) == 0 {
			user.Phone = loginID
		} else {
			varName = "user.Phone"
		}
		if !phoneRegex.MatchString(user.Phone) {
			return utils.NewInvalidArgumentError(varName)
		}
	case descope.MethodVoice:
		if len(user.Phone) == 0 {
			user.Phone = loginID
		} else {
			varName = "user.Phone"
		}
		if !phoneRegex.MatchString(user.Phone) {
			return utils.NewInvalidArgumentError(varName)
		}
	case descope.MethodWhatsApp:
		if len(user.Phone) == 0 {
			user.Phone = loginID
		} else {
			varName = "user.Phone"
		}
		if !phoneRegex.MatchString(user.Phone) {
			return utils.NewInvalidArgumentError(varName)
		}
	}
	return nil
}

func (auth *authenticationsBase) exchangeToken(ctx context.Context, code string, url string, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	if code == "" {
		return nil, utils.NewInvalidArgumentError("code")
	}

	httpResponse, err := auth.client.DoPostRequest(ctx, url, newExchangeTokenBody(code), nil, "")
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(httpResponse, w)
}

func (auth *authenticationsBase) generateAuthenticationInfo(httpResponse *api.HTTPResponse, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	return auth.generateAuthenticationInfoWithRefreshToken(httpResponse, nil, w)
}

func (auth *authenticationsBase) generateAuthenticationInfoWithRefreshToken(httpResponse *api.HTTPResponse, refreshToken *descope.Token, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	jwtResponse, err := auth.extractJWTResponse(httpResponse.BodyStr)
	if err != nil {
		return nil, err
	}
	tokens, err := auth.extractTokens(jwtResponse)
	if err != nil {
		logger.LogError("Unable to extract tokens from request [%s]", err, httpResponse.Req.URL)
		return nil, err
	}

	cookies := httpResponse.Res.Cookies()
	var sToken *descope.Token
	for i := range tokens {
		addToCookie := true
		if tokens[i].Claims[claimAttributeName] == descope.SessionCookieName {
			sToken = tokens[i]
			if !auth.conf.SessionJWTViaCookie {
				addToCookie = false
			}
		}
		if tokens[i].Claims[claimAttributeName] == descope.RefreshCookieName {
			refreshToken = tokens[i]
		}
		if addToCookie {
			ck := auth.createCookie(tokens[i], jwtResponse)
			if ck != nil {
				cookies = append(cookies, ck)
			}
		}
	}

	if refreshToken == nil || refreshToken.JWT == "" {
		for i := range cookies {
			if cookies[i].Name == descope.RefreshCookieName {
				refreshToken, err = auth.validateJWT(cookies[i].Value)
				if err != nil {
					logger.LogDebug("Validation of refresh token failed: %s", err.Error())
					return nil, err
				}
			}
		}
	}

	setCookies(cookies, w)
	return descope.NewAuthenticationInfo(jwtResponse, sToken, refreshToken), err
}

func getValidRefreshToken(r *http.Request) (string, error) {
	_, refreshToken := provideTokens(r)
	if refreshToken == "" {
		logger.LogDebug("Unable to find tokens from cookies")
		return "", descope.ErrRefreshToken.WithMessage("Unable to find tokens from cookies")
	}
	return refreshToken, nil
}

func (auth *authenticationsBase) createCookie(token *descope.Token, jwtRes *descope.JWTResponse) *http.Cookie {
	// Take cookie domain for conf, fallback to JWTResponse
	cookieDomain := auth.conf.CookieDomain
	if cookieDomain == "" {
		cookieDomain = jwtRes.CookieDomain
	}

	cookieSameSite := auth.conf.CookieSameSite
	if cookieSameSite <= http.SameSiteDefaultMode || cookieSameSite > http.SameSiteNoneMode {
		cookieSameSite = http.SameSiteStrictMode
	}

	if token == nil {
		return nil // notest
	}
	name, ok := token.Claims[claimAttributeName].(string)
	if !ok {
		logger.LogDebug("Unable to find attribute name claim")
		return nil // notest
	}
	return &http.Cookie{
		Path:     jwtRes.CookiePath,
		Domain:   cookieDomain,
		Name:     name,
		Value:    token.JWT,
		HttpOnly: true,
		MaxAge:   int(jwtRes.CookieMaxAge),
		Expires:  time.Unix(int64(jwtRes.CookieExpiration), 0),
		SameSite: cookieSameSite,
		Secure:   true,
	}
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
		if sessionCookie, _ := r.Cookie(descope.SessionCookieName); sessionCookie != nil {
			sessionToken = sessionCookie.Value
		}
	}

	refreshCookie, err := r.Cookie(descope.RefreshCookieName)
	if err != nil {
		return sessionToken, ""
	}
	return sessionToken, refreshCookie.Value
}

func convertTokenError(err error) error {
	if goErrors.Is(err, jwt.ErrTokenExpired()) {
		return descope.ErrInvalidToken.WithMessage("Token has expired")
	}
	if goErrors.Is(err, jwt.ErrTokenNotYetValid()) {
		return descope.ErrInvalidToken.WithMessage("Token is not yet valid")
	}
	var validationErr jwt.ValidationError
	if goErrors.As(err, &validationErr) {
		return descope.ErrInvalidToken
	}
	if err != nil {
		if unwrapped := goErrors.Unwrap(err); unwrapped != nil {
			if de, ok := unwrapped.(*descope.Error); ok {
				return de
			}
		}
		return descope.ErrInvalidToken.WithMessage("Failed to verify token: %s", err.Error())
	}
	return nil
}

func getAuthorizationClaimItems(token *descope.Token, tenant string, claim string) []string {
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
		var claimValue []interface{}
		if v, ok := token.GetTenantValue(tenant, claim).([]interface{}); ok {
			claimValue = v
		} else if token.Claims[descope.ClaimDescopeCurrentTenant] == tenant && token.Claims[descope.ClaimAuthorizedTenants] == nil {
			// The token may have the current tenant in the "dct" claim and without the "tenants" claim
			// Note: We also must ensure that the tenants claim is not present because in the if "tenants" claim exists,
			// the top level claim represents for the project level roles/permissions
			if v, ok := token.Claims[claim].([]interface{}); ok {
				claimValue = v
			}
		}

		for i := range claimValue {
			if item, ok := claimValue[i].(string); ok {
				items = append(items, item)
			}
		}
	}

	// warn if it seems like programmer forgot the tenant ID
	if len(items) == 0 && tenant == "" && len(token.GetTenants()) != 0 {
		logger.LogDebug("No authorization items found but tenant might need to be specified")
	}

	return items
}

func isAssociatedWithTenant(token *descope.Token, tenant string) bool {
	return slices.Contains(token.GetTenants(), tenant) || (token.Claims != nil && token.Claims[descope.ClaimDescopeCurrentTenant] == tenant)
}

func getPendingRefFromResponse(httpResponse *api.HTTPResponse) (*descope.EnchantedLinkResponse, error) {
	var response *descope.EnchantedLinkResponse
	if err := utils.Unmarshal([]byte(httpResponse.BodyStr), &response); err != nil {
		logger.LogError("Failed to load pending reference from response", err)
		return response, descope.ErrUnexpectedResponse.WithMessage("Failed to load pending reference")
	}
	return response, nil
}

func getNOTPResponse(httpResponse *api.HTTPResponse) (*descope.NOTPResponse, error) {
	var response *descope.NOTPResponse
	if err := utils.Unmarshal([]byte(httpResponse.BodyStr), &response); err != nil {
		logger.LogError("Failed to load NOTP response from http response", err)
		return response, descope.ErrUnexpectedResponse.WithMessage("Failed to load NOTP response")
	}
	return response, nil
}

func composeURLMethod(base string, method descope.DeliveryMethod) string {
	return path.Join(base, string(method))
}

func composeSignInURL(method descope.DeliveryMethod) string {
	return composeURLMethod(api.Routes.SignInOTP(), method)
}

func composeSignUpURL(method descope.DeliveryMethod) string {
	return composeURLMethod(api.Routes.SignUpOTP(), method)
}

func composeSignUpOrInURL(method descope.DeliveryMethod) string {
	return composeURLMethod(api.Routes.SignUpOrInOTP(), method)
}

func composeSignUpTOTPURL() string {
	return api.Routes.SignUpTOTP()
}

func composeUpdateTOTPURL() string {
	return api.Routes.UpdateTOTP()
}

func composeNOTPSignInURL() string {
	return api.Routes.SignInNOTP()
}

func composeNOTPSignUpURL() string {
	return api.Routes.SignUpNOTP()
}

func composeNOTPSignUpOrInURL() string {
	return api.Routes.SignUpOrInNOTP()
}

func composeNOTPGetSession() string {
	return api.Routes.GetNOTPSession()
}

func composeVerifyCodeURL(method descope.DeliveryMethod) string {
	return composeURLMethod(api.Routes.VerifyCode(), method)
}

func composeVerifyTOTPCodeURL() string {
	return api.Routes.VerifyTOTPCode()
}

func composeMagicLinkSignInURL(method descope.DeliveryMethod) string {
	return composeURLMethod(api.Routes.SignInMagicLink(), method)
}

func composeMagicLinkSignUpURL(method descope.DeliveryMethod) string {
	return composeURLMethod(api.Routes.SignUpMagicLink(), method)
}

func composeMagicLinkSignUpOrInURL(method descope.DeliveryMethod) string {
	return composeURLMethod(api.Routes.SignUpOrInMagicLink(), method)
}

func composeVerifyMagicLinkURL() string {
	return api.Routes.VerifyMagicLink()
}

func composeEnchantedLinkSignInURL() string {
	return composeURLMethod(api.Routes.SignInEnchantedLink(), descope.MethodEmail)
}

func composeEnchantedLinkSignUpURL() string {
	return composeURLMethod(api.Routes.SignUpEnchantedLink(), descope.MethodEmail)
}

func composeEnchantedLinkSignUpOrInURL() string {
	return composeURLMethod(api.Routes.SignUpOrInEnchantedLink(), descope.MethodEmail)
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

func composeOAuthSignUpOrInURL() string {
	return api.Routes.OAuthSignUpOrIn()
}

func composeOAuthSignInURL() string {
	return api.Routes.OAuthSignIn()
}

func composeOAuthSignUpURL() string {
	return api.Routes.OAuthSignUp()
}

func composeOAuthUpdateUserURL() string {
	return api.Routes.OAuthUpdateUser()
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

func composeSSOStartURL() string {
	return api.Routes.SSOStart()
}
func composeSSOExchangeTokenURL() string {
	return api.Routes.ExchangeTokenSSO()
}

func composeUpdateUserEmailOTP() string {
	return api.Routes.UpdateUserEmailOTP()
}

func composeUpdateUserEmailMagicLink() string {
	return api.Routes.UpdateUserEmailMagiclink()
}

func composeUpdateUserPhoneMagiclink(method descope.DeliveryMethod) string {
	return composeURLMethod(api.Routes.UpdateUserPhoneMagicLink(), method)
}

func composeUpdateUserPhoneOTP(method descope.DeliveryMethod) string {
	return composeURLMethod(api.Routes.UpdateUserPhoneOTP(), method)
}

func redirectToURL(url string, w http.ResponseWriter) {
	if w == nil {
		return // notest
	}
	w.Header().Set(descope.RedirectLocationCookieName, url)
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

type Masked interface {
	GetMasked() string
}

type MaskedEmailRes struct {
	MaskedEmail string `json:"maskedEmail,omitempty"` // Masked email to which the message was sent
}

func (mer *MaskedEmailRes) GetMasked() string {
	return mer.MaskedEmail
}

type MaskedPhoneRes struct {
	MaskedPhone string `json:"maskedPhone,omitempty"` // Masked phone to which the message was sent
}

func (mer *MaskedPhoneRes) GetMasked() string {
	return mer.MaskedPhone
}

func getMaskedValue(method descope.DeliveryMethod) Masked {
	var m Masked
	switch method {
	case descope.MethodSMS:
		fallthrough
	case descope.MethodVoice:
		fallthrough
	case descope.MethodWhatsApp:
		m = &MaskedPhoneRes{}
	case descope.MethodEmail:
		m = &MaskedEmailRes{}
	}
	return m
}
