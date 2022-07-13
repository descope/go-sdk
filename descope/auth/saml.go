package auth

import (
	"net/http"

	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/errors"
	"github.com/descope/go-sdk/descope/logger"
)

func (auth *authenticationService) SAMLStart(tenant string, returnURL string, w http.ResponseWriter) (redirectURL string, err error) {
	return auth.SAMLStartWithOptions(tenant, returnURL, WithResponseOption(w))
}

func (auth *authenticationService) SAMLStartWithOptions(tenant string, returnURL string, options ...Option) (redirectURL string, err error) {
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
		urlObj, err := httpResponse.Res.Location()
		if err != nil {
			logger.LogError("failed to parse saml location from response for [%s]", err, tenant)
			return "", err
		}
		redirectURL = urlObj.String()
		Options(options).CopyResponse(httpResponse.Res, httpResponse.BodyStr)
	}

	return
}
