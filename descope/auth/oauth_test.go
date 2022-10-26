package auth

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOAuthStartForwardResponse(t *testing.T) {
	uri := "http://test.me"
	landingURL := "https://test.com"
	provider := OAuthGithub
	a, err := newTestAuth(nil, DoRedirect(uri, func(r *http.Request) {
		req := oauthStartBody{}
		err := readBody(r, &req)
		require.NoError(t, err)
		assert.EqualValues(t, provider, req.Provider)
		assert.EqualValues(t, landingURL, req.RedirectURL)
		assert.EqualValues(t, composeOAuthURL(), r.URL.RequestURI())
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

func TestExchangeTokenOAuth(t *testing.T) {
	code := "code"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		req := exchangeTokenBody{}
		err := readBody(r, &req)
		require.NoError(t, err)
		assert.EqualValues(t, code, req.Code)

		resp := &JWTResponse{
			RefreshJwt: jwtTokenValid,
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
	authInfo, err := a.OAuth().ExchangeToken(code, nil, nil, w)
	require.NoError(t, err)
	require.NotNil(t, authInfo)
	assert.EqualValues(t, "name", authInfo.User.Name)
	assert.True(t, authInfo.FirstSeen)
}

func TestExchangeTokenOAuthLoginOptions(t *testing.T) {
	code := "code"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		req := exchangeTokenBody{}
		err := readBody(r, &req)
		require.NoError(t, err)
		assert.EqualValues(t, code, req.Code)
		assert.EqualValues(t, map[string]interface{}{"k1": "v1"}, req.LoginOptions.CustomClaims)
		reqToken := r.Header.Get(api.AuthorizationHeaderName)
		splitToken := strings.Split(reqToken, api.BearerAuthorizationPrefix)
		require.Len(t, splitToken, 2)
		bearer := splitToken[1]
		bearers := strings.Split(bearer, ":")
		require.Len(t, bearers, 2)
		assert.EqualValues(t, "test", bearers[1])

		resp := &JWTResponse{
			RefreshJwt: jwtTokenValid,
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
	authInfo, err := a.OAuth().ExchangeToken(code, &http.Request{Header: http.Header{"Cookie": []string{"DSR=test"}}}, &LoginOptions{Stepup: true, CustomClaims: map[string]interface{}{"k1": "v1"}}, w)
	require.NoError(t, err)
	require.NotNil(t, authInfo)
	assert.EqualValues(t, "name", authInfo.User.Name)
	assert.True(t, authInfo.FirstSeen)
}

func TestExchangeTokenSAML(t *testing.T) {
	code := "code"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		req := exchangeTokenBody{}
		err := readBody(r, &req)
		require.NoError(t, err)
		assert.EqualValues(t, code, req.Code)
		resp := &JWTResponse{
			RefreshJwt: jwtTokenValid,
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
	authInfo, err := a.SAML().ExchangeToken(code, nil, nil, w)
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
	_, err = a.OAuth().ExchangeToken(code, nil, nil, w)
	require.Error(t, err)
}
