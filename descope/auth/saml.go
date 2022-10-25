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

func (auth *saml) Start(tenant string, returnURL string, w http.ResponseWriter) (url string, err error) {
	if tenant == "" {
		return "", errors.NewInvalidArgumentError("tenant")
	}
	httpResponse, err := auth.client.DoPostRequest(composeSAMLStartURL(), newSAMLStartBody(tenant, returnURL), &api.HTTPRequest{}, "")
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
		redirectURL(url, w)
	}

	return
}

func (auth *saml) ExchangeToken(code string, r *http.Request, loginOptions *LoginOptions, w http.ResponseWriter) (*AuthenticationInfo, error) {
	return auth.exchangeToken(code, composeSAMLExchangeTokenURL(), r, loginOptions, w)
}
