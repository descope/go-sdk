package auth

import (
	"net/http"

	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/errors"
	"github.com/descope/go-sdk/descope/logger"
)

func (auth *authenticationService) OAuthStart(provider OAuthProvider, w http.ResponseWriter) (string, error) {
	return auth.OAuthStartWithOptions(provider, WithResponseOption(w))
}

func (auth *authenticationService) OAuthStartWithOptions(provider OAuthProvider, options ...Option) (url string, err error) {
	httpResponse, err := auth.client.DoGetRequest(composeOAuthURL(), &api.HTTPRequest{QueryParams: map[string]string{"provider": string(provider)}}, "")
	if err != nil {
		return
	}

	if httpResponse.Res != nil {
		urlObj, err := httpResponse.Res.Location()
		if err != nil {
			logger.LogError("failed to parse location from response for [%s]", err, provider)
			return "", err
		}
		url = urlObj.String()
		Options(options).CopyResponse(httpResponse.Res, httpResponse.BodyStr)
	}

	return
}

func (auth *authenticationService) ExchangeToken(code string, w http.ResponseWriter) (*AuthenticationInfo, error) {
	return auth.ExchangeTokenWithOptions(code, WithResponseOption(w))
}

func (auth *authenticationService) ExchangeTokenWithOptions(code string, options ...Option) (*AuthenticationInfo, error) {
	if code == "" {
		return nil, errors.NewInvalidArgumentError("code")
	}

	httpResponse, err := auth.client.DoPostRequest(composeExchangeTokenURL(), newExchangeTokenRequest(code), nil, "")
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(httpResponse, options...)
}
