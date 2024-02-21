package auth

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOAuthStartForwardResponse(t *testing.T) {
	uri := "http://test.me"
	landingURL := "https://test.com"
	provider := descope.OAuthGithub
	a, err := newTestAuth(nil, DoRedirect(uri, func(r *http.Request) {
		assert.EqualValues(t, fmt.Sprintf("%s?provider=%s&redirectURL=%s", composeOAuthSignUpOrInURL(), provider, url.QueryEscape(landingURL)), r.URL.RequestURI())
	}))
	require.NoError(t, err)
	w := httptest.NewRecorder()
	urlStr, err := a.OAuth().Start(context.Background(), provider, landingURL, nil, nil, w)
	require.NoError(t, err)
	assert.EqualValues(t, uri, urlStr)
	assert.EqualValues(t, urlStr, w.Result().Header.Get(descope.RedirectLocationCookieName))
	assert.EqualValues(t, http.StatusTemporaryRedirect, w.Result().StatusCode)
}

func TestOAuthSignInForwardResponse(t *testing.T) {
	uri := "http://test.me"
	landingURL := "https://test.com"
	provider := descope.OAuthGithub
	a, err := newTestAuth(nil, DoRedirect(uri, func(r *http.Request) {
		assert.EqualValues(t, fmt.Sprintf("%s?provider=%s&redirectURL=%s", composeOAuthSignInURL(), provider, url.QueryEscape(landingURL)), r.URL.RequestURI())
	}))
	require.NoError(t, err)
	w := httptest.NewRecorder()
	urlStr, err := a.OAuth().SignIn(context.Background(), provider, landingURL, nil, nil, w)
	require.NoError(t, err)
	assert.EqualValues(t, uri, urlStr)
	assert.EqualValues(t, urlStr, w.Result().Header.Get(descope.RedirectLocationCookieName))
	assert.EqualValues(t, http.StatusTemporaryRedirect, w.Result().StatusCode)
}

func TestOAuthSignUpForwardResponse(t *testing.T) {
	uri := "http://test.me"
	landingURL := "https://test.com"
	provider := descope.OAuthGithub
	a, err := newTestAuth(nil, DoRedirect(uri, func(r *http.Request) {
		assert.EqualValues(t, fmt.Sprintf("%s?provider=%s&redirectURL=%s", composeOAuthSignUpURL(), provider, url.QueryEscape(landingURL)), r.URL.RequestURI())
	}))
	require.NoError(t, err)
	w := httptest.NewRecorder()
	urlStr, err := a.OAuth().SignUp(context.Background(), provider, landingURL, nil, nil, w)
	require.NoError(t, err)
	assert.EqualValues(t, uri, urlStr)
	assert.EqualValues(t, urlStr, w.Result().Header.Get(descope.RedirectLocationCookieName))
	assert.EqualValues(t, http.StatusTemporaryRedirect, w.Result().StatusCode)
}

func TestOAuthStartForwardResponseStepup(t *testing.T) {
	uri := "http://test.me"
	landingURL := "https://test.com"
	provider := descope.OAuthGithub
	a, err := newTestAuth(nil, DoRedirect(uri, func(r *http.Request) {
		assert.EqualValues(t, fmt.Sprintf("%s?provider=%s&redirectURL=%s", composeOAuthSignUpOrInURL(), provider, url.QueryEscape(landingURL)), r.URL.RequestURI())
		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, map[string]interface{}{"stepup": true, "customClaims": map[string]interface{}{"k1": "v1"}}, body)
		reqToken := r.Header.Get(api.AuthorizationHeaderName)
		splitToken := strings.Split(reqToken, api.BearerAuthorizationPrefix)
		require.Len(t, splitToken, 2)
		bearer := splitToken[1]
		bearers := strings.Split(bearer, ":")
		require.Len(t, bearers, 2)
		assert.EqualValues(t, "test", bearers[1])
	}))
	require.NoError(t, err)
	w := httptest.NewRecorder()
	urlStr, err := a.OAuth().Start(context.Background(), provider, landingURL, &http.Request{Header: http.Header{"Cookie": []string{"DSR=test"}}}, &descope.LoginOptions{Stepup: true, CustomClaims: map[string]interface{}{"k1": "v1"}}, w)
	require.NoError(t, err)
	assert.EqualValues(t, uri, urlStr)
	assert.EqualValues(t, urlStr, w.Result().Header.Get(descope.RedirectLocationCookieName))
	assert.EqualValues(t, http.StatusTemporaryRedirect, w.Result().StatusCode)
}

func TestOAuthStartForwardResponseStepupNoJWT(t *testing.T) {
	uri := "http://test.me"
	landingURL := "https://test.com"
	provider := descope.OAuthGithub
	a, err := newTestAuth(nil, DoRedirect(uri, func(r *http.Request) {}))
	require.NoError(t, err)
	w := httptest.NewRecorder()
	_, err = a.OAuth().Start(context.Background(), provider, landingURL, nil, &descope.LoginOptions{Stepup: true, CustomClaims: map[string]interface{}{"k1": "v1"}}, w)
	assert.ErrorIs(t, err, descope.ErrInvalidStepUpJWT)
}

func TestOAuthStartInvalidForwardResponse(t *testing.T) {
	provider := descope.OAuthGithub
	a, err := newTestAuth(nil, DoBadRequest(func(r *http.Request) {
		assert.EqualValues(t, fmt.Sprintf("%s?provider=%s", composeOAuthSignUpOrInURL(), provider), r.URL.RequestURI())
	}))
	require.NoError(t, err)
	w := httptest.NewRecorder()
	urlStr, err := a.OAuth().Start(context.Background(), provider, "", nil, nil, w)
	require.Error(t, err)
	assert.Empty(t, urlStr)
}

func TestExchangeTokenOAuth(t *testing.T) {
	code := "code"
	firstSeen := true
	name := "name"
	phone := "+11111111111"
	picture := "@(^_^)@"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		req := exchangeTokenBody{}
		err := readBody(r, &req)
		require.NoError(t, err)
		assert.EqualValues(t, code, req.Code)

		resp := &descope.JWTResponse{
			RefreshJwt: jwtTokenValid,
			User: &descope.UserResponse{
				User: descope.User{
					Name:  name,
					Phone: phone,
				},
				Picture: picture,
			},
			FirstSeen: firstSeen,
		}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	w := httptest.NewRecorder()
	authInfo, err := a.OAuth().ExchangeToken(context.Background(), code, w)
	require.NoError(t, err)
	require.NotNil(t, authInfo)
	assert.Equal(t, firstSeen, authInfo.FirstSeen)
	assert.Equal(t, name, authInfo.User.Name)
	assert.Equal(t, phone, authInfo.User.Phone)
	assert.Equal(t, picture, authInfo.User.Picture)
}

func TestExchangeTokenSAML(t *testing.T) {
	code := "code"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		req := exchangeTokenBody{}
		err := readBody(r, &req)
		require.NoError(t, err)
		assert.EqualValues(t, code, req.Code)
		resp := &descope.JWTResponse{
			RefreshJwt: jwtTokenValid,
			User: &descope.UserResponse{
				User: descope.User{
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
	authInfo, err := a.SAML().ExchangeToken(context.Background(), code, w)
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
	_, err = a.OAuth().ExchangeToken(context.Background(), code, w)
	require.Error(t, err)
}
