package sdk

import "net/http"

type RequestTokensProvider interface {
	ProvideTokens(r *http.Request) (sessionToken string, refreshToken string)
}
