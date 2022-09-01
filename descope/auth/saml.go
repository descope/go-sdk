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

func (auth *saml) Start(tenant string, returnURL string, w http.ResponseWriter) (redirectURL string, err error) {
	return auth.StartWithOptions(tenant, returnURL, WithResponseOption(w))
}

func (auth *saml) StartWithOptions(tenant string, returnURL string, options ...Option) (redirectURL string, err error) {
	if tenant == "" {
		return "", errors.NewInvalidArgumentError("tenant")
	}
	m := map[string]string{
		"tenant": string(tenant),
	}
	if len(returnURL) > 0 {
		m["redirectURL"] = returnURL
	}
	httpResponse, err := auth.client.DoGetRequest(composeSAMLStartURL(), &api.HTTPRequest{QueryParams: m}, "")
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
		redirectURL = res.URL
		Options(options).CreateRedirect(redirectURL)
	}

	return
}

func (auth *saml) ExchangeToken(code string, w http.ResponseWriter) (*AuthenticationInfo, error) {
	return auth.ExchangeTokenWithOptions(code, WithResponseOption(w))
}

func (auth *saml) ExchangeTokenWithOptions(code string, options ...Option) (*AuthenticationInfo, error) {
	return auth.exchangeTokenWithOptions(code, composeSAMLExchangeTokenURL(), options...)
}
