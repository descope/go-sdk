package auth

import (
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

func (auth *sso) Start(tenant string, redirectURL string, prompt string, r *http.Request, loginOptions *descope.LoginOptions, w http.ResponseWriter) (url string, err error) {
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
	var pswd string
	if loginOptions.IsJWTRequired() {
		pswd, err = getValidRefreshToken(r)
		if err != nil {
			return "", descope.ErrInvalidStepUpJWT
		}
	}
	httpResponse, err := auth.client.DoPostRequest(composeSSOStartURL(), loginOptions, &api.HTTPRequest{QueryParams: m}, pswd)
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

func (auth *sso) ExchangeToken(code string, w http.ResponseWriter) (*descope.AuthenticationInfo, error) {
	return auth.exchangeToken(code, composeSSOExchangeTokenURL(), w)
}
