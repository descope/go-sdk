package auth

import (
	"context"
	"net/http"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/logger"
)

type oauth struct {
	authenticationsBase
}

type oauthStartResponse struct {
	URL string `json:"url"`
}

func (auth *oauth) start(ctx context.Context, provider descope.OAuthProvider, redirectURL string, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter, authorizeURL string) (url string, err error) {
	m := map[string]string{
		"provider": string(provider),
	}
	if len(redirectURL) > 0 {
		m["redirectURL"] = redirectURL
	}
	var pswd string
	if loginOptions.IsJWTRequired() {
		pswd, err = getValidRefreshToken(r)
		if err != nil {
			return "", descope.ErrInvalidStepUpJWT
		}
	}

	httpResponse, err := auth.client.DoPostRequest(ctx, authorizeURL, loginOptions, &api.HTTPRequest{QueryParams: m}, pswd)
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
	return auth.start(ctx, provider, redirectURL, r, loginOptions, w, composeOAuthSignUpOrInURL())
}

func (auth *oauth) SignUp(ctx context.Context, provider descope.OAuthProvider, redirectURL string, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter) (url string, err error) {
	return auth.start(ctx, provider, redirectURL, r, loginOptions, w, composeOAuthSignUpURL())
}

func (auth *oauth) SignIn(ctx context.Context, provider descope.OAuthProvider, redirectURL string, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter) (url string, err error) {
	return auth.start(ctx, provider, redirectURL, r, loginOptions, w, composeOAuthSignInURL())
}

func (auth *oauth) Start(ctx context.Context, provider descope.OAuthProvider, redirectURL string, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter) (url string, err error) {
	return auth.SignUpOrIn(ctx, provider, redirectURL, r, loginOptions, w)
}

func (auth *oauth) ExchangeToken(ctx context.Context, code string, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	return auth.exchangeToken(ctx, code, composeOAuthExchangeTokenURL(), w)
}
