package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
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
	urlStr, err := a.SSO().Start(tenant, landingURL, prompt, nil, nil, w)
	require.NoError(t, err)
	assert.EqualValues(t, uri, urlStr)
	assert.EqualValues(t, urlStr, w.Result().Header.Get(descope.RedirectLocationCookieName))
	assert.EqualValues(t, http.StatusTemporaryRedirect, w.Result().StatusCode)
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
	urlStr, err := a.SSO().Start(tenant, landingURL, prompt, &http.Request{Header: http.Header{"Cookie": []string{"DSR=test"}}}, &descope.LoginOptions{Stepup: true, CustomClaims: map[string]interface{}{"k1": "v1"}}, w)
	require.NoError(t, err)
	assert.EqualValues(t, uri, urlStr)
	assert.EqualValues(t, urlStr, w.Result().Header.Get(descope.RedirectLocationCookieName))
	assert.EqualValues(t, http.StatusTemporaryRedirect, w.Result().StatusCode)
}

func TestSSOStartInvalidForwardResponse(t *testing.T) {
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	w := httptest.NewRecorder()
	_, err = a.SAML().Start("", "", nil, nil, w)
	require.Error(t, err)

	_, err = a.SSO().Start("test", "", "", nil, &descope.LoginOptions{Stepup: true}, w)
	assert.ErrorIs(t, err, descope.ErrInvalidStepUpJWT)
}
