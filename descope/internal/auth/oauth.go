package auth

import (
	"context"
	"net/http"
	"strconv"

	"github.com/descope/go-sdk/v2/descope"
	"github.com/descope/go-sdk/v2/descope/api"
	"github.com/descope/go-sdk/v2/descope/internal/utils"
	"github.com/descope/go-sdk/v2/descope/logger"
)

type oauth struct {
	authenticationsBase
}

type oauthStartResponse struct {
	URL string `json:"url"`
}

func (auth *oauth) startAuth(ctx context.Context, provider descope.OAuthProvider, redirectURL string, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter, authorizeURL string) (url string, err error) {
	m := generateOAuthRequestParams(ctx, provider, redirectURL)
	var pswd string
	if loginOptions.IsJWTRequired() {
		pswd, err = getValidRefreshToken(r)
		if err != nil {
			return "", descope.ErrInvalidStepUpJWT
		}
	}

	return auth.doStart(ctx, provider, m, pswd, loginOptions, w, authorizeURL)
}

func (auth *oauth) startUpdate(ctx context.Context, provider descope.OAuthProvider, redirectURL string, allowAllMerge bool, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter, authorizeURL string) (url string, err error) {
	m := generateOAuthRequestParams(ctx, provider, redirectURL)
	if allowAllMerge {
		m["allowAllMerge"] = strconv.FormatBool(allowAllMerge)
	}
	pswd, err := getValidRefreshToken(r)
	if err != nil {
		return "", descope.ErrRefreshToken
	}

	return auth.doStart(ctx, provider, m, pswd, loginOptions, w, authorizeURL)
}

func (auth *oauth) doStart(ctx context.Context, provider descope.OAuthProvider, params map[string]string, pswd string, loginOptions *descope.LoginOptions, w http.ResponseWriter, authorizeURL string) (url string, err error) {
	httpResponse, err := auth.client.DoPostRequest(ctx, authorizeURL, loginOptions, &api.HTTPRequest{QueryParams: params}, pswd)
	if err != nil {
		return
	}

	if httpResponse.Res != nil {
		res := &oauthStartResponse{}
		err = utils.Unmarshal([]byte(httpResponse.BodyStr), res)
		if err != nil {
			logger.LogError("Failed to parse location from response for [%s]", err, provider)
			return "", err
		}
		url = res.URL
		redirectToURL(url, w)
	}
	return
}

func (auth *oauth) SignUpOrIn(ctx context.Context, provider descope.OAuthProvider, redirectURL string, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter) (url string, err error) {
	return auth.startAuth(ctx, provider, redirectURL, r, loginOptions, w, composeOAuthSignUpOrInURL())
}

func (auth *oauth) SignUp(ctx context.Context, provider descope.OAuthProvider, redirectURL string, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter) (url string, err error) {
	return auth.startAuth(ctx, provider, redirectURL, r, loginOptions, w, composeOAuthSignUpURL())
}

func (auth *oauth) SignIn(ctx context.Context, provider descope.OAuthProvider, redirectURL string, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter) (url string, err error) {
	return auth.startAuth(ctx, provider, redirectURL, r, loginOptions, w, composeOAuthSignInURL())
}

func (auth *oauth) UpdateUser(ctx context.Context, provider descope.OAuthProvider, redirectURL string, allowAllMerge bool, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter) (url string, err error) {
	return auth.startUpdate(ctx, provider, redirectURL, allowAllMerge, r, loginOptions, w, composeOAuthUpdateUserURL())
}

func (auth *oauth) Start(ctx context.Context, provider descope.OAuthProvider, redirectURL string, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter) (url string, err error) {
	return auth.SignUpOrIn(ctx, provider, redirectURL, r, loginOptions, w)
}

func (auth *oauth) ExchangeToken(ctx context.Context, code string, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	return auth.exchangeToken(ctx, code, composeOAuthExchangeTokenURL(), w)
}

func generateOAuthRequestParams(_ context.Context, provider descope.OAuthProvider, redirectURL string) map[string]string {
	params := map[string]string{
		"provider": string(provider),
	}
	if len(redirectURL) > 0 {
		params["redirectURL"] = redirectURL
	}

	return params
}
