package auth

import (
	"net/http"

	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/errors"
	"github.com/descope/go-sdk/descope/logger"
	"github.com/descope/go-sdk/descope/utils"
)

type saml struct {
	authenticationsBase
}

type samlStartResponse struct {
	URL string `json:"url"`
}

func (auth *saml) Start(tenant string, redirectURL string, r *http.Request, loginOptions *LoginOptions, w http.ResponseWriter) (url string, err error) {
	if tenant == "" {
		return "", errors.NewInvalidArgumentError("tenant")
	}
	m := map[string]string{
		"tenant": string(tenant),
	}
	if len(redirectURL) > 0 {
		m["redirectURL"] = redirectURL
	}
	var pswd string
	if loginOptions.IsStepup() {
		pswd, err = getValidRefreshToken(r)
		if err != nil {
			return "", errors.InvalidStepupJwtError
		}
	}
	httpResponse, err := auth.client.DoPostRequest(composeSAMLStartURL(), loginOptions, &api.HTTPRequest{QueryParams: m}, pswd)
	if err != nil {
		return
	}

	if httpResponse.Res != nil {
		res := &samlStartResponse{}
		err = utils.Unmarshal([]byte(httpResponse.BodyStr), res)
		if err != nil {
			logger.LogError("failed to parse saml location from response for [%s]", err, tenant)
			return "", err
		}
		url = res.URL
		redirectToURL(url, w)
	}

	return
}

func (auth *saml) ExchangeToken(code string, w http.ResponseWriter) (*AuthenticationInfo, error) {
	return auth.exchangeToken(code, composeSAMLExchangeTokenURL(), w)
}
