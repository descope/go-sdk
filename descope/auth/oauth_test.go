package auth

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/descope/go-sdk/descope/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOAuthStartForwardResponse(t *testing.T) {
	uri := "http://test.me"
	landingURL := "https://test.com"
	provider := OAuthGithub
	a, err := newTestAuth(nil, DoRedirect(uri, func(r *http.Request) {
		assert.EqualValues(t, fmt.Sprintf("%s?provider=%s&redirectURL=%s", composeOAuthURL(), provider, url.QueryEscape(landingURL)), r.URL.RequestURI())
	}))
	require.NoError(t, err)
	w := httptest.NewRecorder()
	urlStr, err := a.OAuth().Start(provider, landingURL, w)
	require.NoError(t, err)
	assert.EqualValues(t, uri, urlStr)
	assert.EqualValues(t, urlStr, w.Result().Header.Get(RedirectLocationCookieName))
	assert.EqualValues(t, http.StatusTemporaryRedirect, w.Result().StatusCode)
}

func TestOAuthStartInvalidForwardResponse(t *testing.T) {
	provider := OAuthGithub
	a, err := newTestAuth(nil, DoBadRequest(func(r *http.Request) {
		assert.EqualValues(t, fmt.Sprintf("%s?provider=%s", composeOAuthURL(), provider), r.URL.RequestURI())
	}))
	require.NoError(t, err)
	w := httptest.NewRecorder()
	urlStr, err := a.OAuth().Start(provider, "", w)
	require.Error(t, err)
	assert.Empty(t, urlStr)
}

func TestExchangeToken(t *testing.T) {
	code := "code"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeExchangeTokenURL()+"?code="+code, r.URL.RequestURI())
		resp := &JWTResponse{
			JWTS: []string{jwtTokenValid},
			User: &UserResponse{
				User: User{
					Name: "name",
				},
			},
			FirstSeen: true,
		}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	w := httptest.NewRecorder()
	authInfo, err := a.OAuth().ExchangeToken(code, w)
	require.NoError(t, err)
	require.NotNil(t, authInfo)
	assert.EqualValues(t, "name", authInfo.User.Name)
	assert.True(t, authInfo.FirstSeen)
}

func TestExchangeTokenError(t *testing.T) {
	code := ""
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	w := httptest.NewRecorder()
	_, err = a.OAuth().ExchangeToken(code, w)
	require.Error(t, err)
}
