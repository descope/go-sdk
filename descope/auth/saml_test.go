package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSAMLStart(t *testing.T) {
	uri := "http://test.me"
	tenant := "tenantID"
	landingURL := "https://test.com"
	a, err := newTestAuth(nil, DoRedirect(uri, func(r *http.Request) {
		req := samlStartBody{}
		err := readBody(r, &req)
		require.NoError(t, err)
		assert.EqualValues(t, tenant, req.Tenant)
		assert.EqualValues(t, landingURL, req.RedirectURL)
		assert.EqualValues(t, composeSAMLStartURL(), r.URL.RequestURI())
	}))
	require.NoError(t, err)
	w := httptest.NewRecorder()
	urlStr, err := a.SAML().Start(tenant, landingURL, w)
	require.NoError(t, err)
	assert.EqualValues(t, uri, urlStr)
	assert.EqualValues(t, urlStr, w.Result().Header.Get(RedirectLocationCookieName))
	assert.EqualValues(t, http.StatusTemporaryRedirect, w.Result().StatusCode)
}

func TestSAMLStartInvalidForwardResponse(t *testing.T) {
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	w := httptest.NewRecorder()
	_, err = a.SAML().Start("", "", w)
	require.Error(t, err)
}
