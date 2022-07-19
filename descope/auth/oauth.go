package auth

import (
	"net/http"

	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/logger"
	"github.com/descope/go-sdk/descope/utils"
)

type oauthService struct {
	exchangerBase
}

type oauthStartResponse struct {
	URL string `json:"url"`
}

func (auth *oauthService) Start(provider OAuthProvider, returnURL string, w http.ResponseWriter) (string, error) {
	return auth.StartWithOptions(provider, returnURL, WithResponseOption(w))
}

func (auth *oauthService) StartWithOptions(provider OAuthProvider, returnURL string, options ...Option) (url string, err error) {
	m := map[string]string{
		"provider": string(provider),
	}
	if len(returnURL) > 0 {
		m["redirectURL"] = returnURL
	}
	httpResponse, err := auth.client.DoGetRequest(composeOAuthURL(), &api.HTTPRequest{QueryParams: m}, "")
	if err != nil {
		return
	}

	if httpResponse.Res != nil {
		res := &oauthStartResponse{}
		err = utils.Unmarshal([]byte(httpResponse.BodyStr), res)
		if err != nil {
			logger.LogError("failed to parse location from response for [%s]", err, provider)
			return "", err
		}
		url = res.URL
		Options(options).CreateRedirect(url)
	}

	return
}
