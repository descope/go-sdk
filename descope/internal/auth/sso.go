package auth

import (
	"context"
	"net/http"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/logger"
)

type sso struct {
	authenticationsBase
}

type ssoStartResponse struct {
	URL string `json:"url"`
}

func (auth *sso) Start(ctx context.Context, tenant string, redirectURL string, prompt string, ssoID string, loginHint string, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter) (url string, err error) {
	if tenant == "" {
		return "", utils.NewInvalidArgumentError("tenant")
	}
	m := map[string]string{
		"tenant": string(tenant),
	}
	if len(redirectURL) > 0 {
		m["redirectURL"] = redirectURL
	}
	if len(prompt) > 0 {
		m["prompt"] = prompt
	}
	if len(ssoID) > 0 {
		m["ssoId"] = ssoID
	}
	if len(loginHint) > 0 {
		m["loginHint"] = loginHint
	}

	var pswd string
	if loginOptions.IsJWTRequired() {
		pswd, err = getValidRefreshToken(r)
		if err != nil {
			return "", descope.ErrInvalidStepUpJWT
		}
	}
	httpResponse, err := auth.client.DoPostRequest(ctx, composeSSOStartURL(), loginOptions, &api.HTTPRequest{QueryParams: m}, pswd)
	if err != nil {
		return
	}

	if httpResponse.Res != nil {
		res := &ssoStartResponse{}
		err = utils.Unmarshal([]byte(httpResponse.BodyStr), res)
		if err != nil {
			logger.LogError("Failed to parse sso location from response for [%s]", err, tenant)
			return "", err
		}
		url = res.URL
		redirectToURL(url, w)
	}

	return
}

func (auth *sso) ExchangeToken(ctx context.Context, code string, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	return auth.exchangeToken(ctx, code, composeSSOExchangeTokenURL(), w)
}
