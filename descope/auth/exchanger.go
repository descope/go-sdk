package auth

import (
	"net/http"

	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/errors"
)

type exchangerBase struct {
	authenticationsBase
}

func (auth *exchangerBase) ExchangeToken(code string, w http.ResponseWriter) (*AuthenticationInfo, error) {
	return auth.ExchangeTokenWithOptions(code, WithResponseOption(w))
}

func (auth *exchangerBase) ExchangeTokenWithOptions(code string, options ...Option) (*AuthenticationInfo, error) {
	if code == "" {
		return nil, errors.NewInvalidArgumentError("code")
	}

	httpResponse, err := auth.client.DoGetRequest(composeExchangeTokenURL(), &api.HTTPRequest{QueryParams: map[string]string{"code": string(code)}}, "")
	if err != nil {
		return nil, err
	}
	return auth.generateAuthenticationInfo(httpResponse, options...)
}
