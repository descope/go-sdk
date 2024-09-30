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

func TestSSOStart(t *testing.T) {
	uri := "http://test.me"
	tenant := "tenantID"
	prompt := "none"
	landingURL := "https://test.com"
	a, err := newTestAuth(nil, DoRedirect(uri, func(r *http.Request) {
		assert.EqualValues(t, fmt.Sprintf("%s?prompt=%s&redirectURL=%s&tenant=%s", composeSSOStartURL(), prompt, url.QueryEscape(landingURL), tenant), r.URL.RequestURI())
		assert.Nil(t, r.Body)
	}))
	require.NoError(t, err)
	w := httptest.NewRecorder()
	urlStr, err := a.SSO().Start(context.Background(), tenant, landingURL, prompt, nil, nil, w)
	require.NoError(t, err)
	assert.EqualValues(t, uri, urlStr)
	assert.EqualValues(t, urlStr, w.Result().Header.Get(descope.RedirectLocationCookieName))
	assert.EqualValues(t, http.StatusTemporaryRedirect, w.Result().StatusCode)
}

func TestSSOStartFailureNoTenant(t *testing.T) {
	uri := "http://test.me"
	a, err := newTestAuth(nil, DoRedirect(uri, func(_ *http.Request) {}))
	require.NoError(t, err)
	w := httptest.NewRecorder()
	landingURL := "https://test.com"
	prompt := "none"
	tenant := ""
	_, err = a.SSO().Start(context.Background(), tenant, landingURL, prompt, nil, nil, w)
	require.ErrorIs(t, err, utils.NewInvalidArgumentError("tenant"))
}

func TestSSOStartStepup(t *testing.T) {
	uri := "http://test.me"
	tenant := "tenantID"
	prompt := "none"
	landingURL := "https://test.com"
	a, err := newTestAuth(nil, DoRedirect(uri, func(r *http.Request) {
		assert.EqualValues(t, fmt.Sprintf("%s?prompt=%s&redirectURL=%s&tenant=%s", composeSSOStartURL(), prompt, url.QueryEscape(landingURL), tenant), r.URL.RequestURI())
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
	urlStr, err := a.SSO().Start(context.Background(), tenant, landingURL, prompt, &http.Request{Header: http.Header{"Cookie": []string{"DSR=test"}}}, &descope.LoginOptions{Stepup: true, CustomClaims: map[string]interface{}{"k1": "v1"}}, w)
	require.NoError(t, err)
	assert.EqualValues(t, uri, urlStr)
	assert.EqualValues(t, urlStr, w.Result().Header.Get(descope.RedirectLocationCookieName))
	assert.EqualValues(t, http.StatusTemporaryRedirect, w.Result().StatusCode)
}

func TestSSOStartInvalidForwardResponse(t *testing.T) {
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	w := httptest.NewRecorder()
	_, err = a.SAML().Start(context.Background(), "", "", nil, nil, w)
	require.Error(t, err)

	_, err = a.SSO().Start(context.Background(), "test", "", "", nil, &descope.LoginOptions{Stepup: true}, w)
	assert.ErrorIs(t, err, descope.ErrInvalidStepUpJWT)
}

func TestExchangeTokenSSO(t *testing.T) {
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
	authInfo, err := a.SSO().ExchangeToken(context.Background(), code, w)
	require.NoError(t, err)
	require.NotNil(t, authInfo)
	assert.EqualValues(t, "name", authInfo.User.Name)
	assert.True(t, authInfo.FirstSeen)
}
