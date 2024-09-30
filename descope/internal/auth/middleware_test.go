package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/sdk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthenticationMiddlewareFailure(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	handlerToTest := sdk.AuthenticationMiddleware(a, func(w http.ResponseWriter, _ *http.Request, err error) {
		require.ErrorIs(t, err, descope.ErrPublicKey)
		w.WriteHeader(http.StatusBadGateway)
	}, nil)(nil)

	req := httptest.NewRequest("GET", "http://testing", nil)
	req.AddCookie(mockAuthInvalidSessionCookie)
	req.AddCookie(mockAuthInvalidRefreshCookie)

	res := httptest.NewRecorder()
	handlerToTest.ServeHTTP(res, req)
	require.EqualValues(t, http.StatusBadGateway, res.Result().StatusCode)
}

func TestAuthenticationMiddlewareFailureDefault(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	handlerToTest := sdk.AuthenticationMiddleware(a, nil, nil)(nil)

	req := httptest.NewRequest("GET", "http://testing", nil)

	res := httptest.NewRecorder()
	handlerToTest.ServeHTTP(res, req)

	assert.EqualValues(t, http.StatusUnauthorized, res.Result().StatusCode)
}

func TestAuthenticationMiddlewareSuccessDefault(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	handlerToTest := sdk.AuthenticationMiddleware(a, nil, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, ok := r.Context().Value(descope.ContextUserIDPropertyKey).(string)
		require.True(t, ok)
		assert.EqualValues(t, "someuser", s)
		w.WriteHeader(http.StatusTeapot)
	}))

	req := httptest.NewRequest("GET", "http://testing", nil)
	req.AddCookie(mockAuthSessionCookie)
	req.AddCookie(mockAuthRefreshCookie)

	res := httptest.NewRecorder()
	handlerToTest.ServeHTTP(res, req)
	assert.EqualValues(t, http.StatusTeapot, res.Result().StatusCode)
}

func TestAuthenticationMiddlewareSuccess(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	handlerToTest := sdk.AuthenticationMiddleware(a, nil, func(w http.ResponseWriter, r *http.Request, next http.Handler, token *descope.Token) {
		assert.EqualValues(t, "someuser", token.ID)
		next.ServeHTTP(w, r)
	})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))

	req := httptest.NewRequest("GET", "http://testing", nil)
	req.AddCookie(mockAuthSessionCookie)
	req.AddCookie(mockAuthRefreshCookie)

	res := httptest.NewRecorder()
	handlerToTest.ServeHTTP(res, req)
	assert.EqualValues(t, http.StatusTeapot, res.Result().StatusCode)
}
