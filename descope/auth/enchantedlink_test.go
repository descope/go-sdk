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
	"github.com/descope/go-sdk/descope/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignInEnchantedLinkEmptyExternalID(t *testing.T) {
	email := ""
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	_, err = a.EnchantedLink().SignIn(email, "", nil, nil)
	require.Error(t, err)
	assert.EqualValues(t, errors.BadRequestErrorCode, err.(*errors.WebError).Code)
}

func TestSignInEnchantedLinkStepupNoJwt(t *testing.T) {
	email := "test@test.com"
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	_, err = a.EnchantedLink().SignIn(email, "", nil, &LoginOptions{Stepup: true})
	require.Error(t, err)
	assert.ErrorIs(t, err, errors.InvalidStepupJwtError)
}

func TestSignInEnchantedLink(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	pendingRefResponse := "pending_ref"
	identifier := "identifier"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeEnchantedLinkSignInURL(), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["externalId"])
		assert.EqualValues(t, uri, m["URI"])
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(fmt.Sprintf(`{"pendingRef": "%s","linkId": "%s"}`, pendingRefResponse, identifier))),
		}, nil
	})
	require.NoError(t, err)
	response, err := a.EnchantedLink().SignIn(email, uri, nil, nil)
	require.NoError(t, err)
	require.Equal(t, pendingRefResponse, response.PendingRef)
	require.Equal(t, identifier, response.LinkID)
}

func TestSignInEnchantedLinkStepup(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	pendingRefResponse := "pending_ref"
	identifier := "identifier"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeEnchantedLinkSignInURL(), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["externalId"])
		assert.EqualValues(t, uri, m["URI"])
		assert.EqualValues(t, map[string]interface{}{"stepup": true, "customClaims": map[string]interface{}{"k1": "v1"}}, m["loginOptions"])
		reqToken := r.Header.Get(api.AuthorizationHeaderName)
		splitToken := strings.Split(reqToken, api.BearerAuthorizationPrefix)
		require.Len(t, splitToken, 2)
		bearer := splitToken[1]
		bearers := strings.Split(bearer, ":")
		require.Len(t, bearers, 2)
		assert.EqualValues(t, "test", bearers[1])
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(fmt.Sprintf(`{"pendingRef": "%s","linkId": "%s"}`, pendingRefResponse, identifier))),
		}, nil
	})
	require.NoError(t, err)
	response, err := a.EnchantedLink().SignIn(email, uri, &http.Request{Header: http.Header{"Cookie": []string{"DSR=test"}}}, &LoginOptions{Stepup: true, CustomClaims: map[string]interface{}{"k1": "v1"}})
	require.NoError(t, err)
	require.Equal(t, pendingRefResponse, response.PendingRef)
	require.Equal(t, identifier, response.LinkID)
}

func TestSignInEnchantedLinkInvalidResponse(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(`{"pendingRef"`)),
		}, nil
	})
	require.NoError(t, err)
	res, err := a.EnchantedLink().SignIn(email, uri, nil, nil)
	require.Error(t, err)
	require.Empty(t, res)
}

func TestSignUpEnchantedLink(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	pendingRefResponse := "pending_ref"
	identifier := "identifier"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeEnchantedLinkSignUpURL(), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["email"])
		assert.EqualValues(t, uri, m["URI"])
		assert.EqualValues(t, email, m["externalId"])
		assert.EqualValues(t, "test", m["user"].(map[string]interface{})["name"])
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(fmt.Sprintf(`{"pendingRef": "%s","linkId": "%s"}`, pendingRefResponse, identifier))),
		}, nil
	})
	require.NoError(t, err)
	response, err := a.EnchantedLink().SignUp(email, uri, &User{Name: "test"})
	require.NoError(t, err)
	require.Equal(t, pendingRefResponse, response.PendingRef)
	require.Equal(t, identifier, response.LinkID)
}

func TestSignUpOrInEnchantedLink(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	pendingRefResponse := "pending_ref"
	identifier := "ident"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeEnchantedLinkSignUpOrInURL(), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["externalId"])
		assert.EqualValues(t, uri, m["URI"])
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(fmt.Sprintf(`{"pendingRef": "%s", "linkId": "%s"}`, pendingRefResponse, identifier))),
		}, nil
	})
	require.NoError(t, err)
	response, err := a.EnchantedLink().SignUpOrIn(email, uri)
	require.NoError(t, err)
	require.Equal(t, pendingRefResponse, response.PendingRef)
	require.Equal(t, identifier, response.LinkID)
}

func TestSignUpEnchantedLinkEmptyIdentifier(t *testing.T) {
	uri := "http://test.me"
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	response, err := a.EnchantedLink().SignUp("", uri, &User{Name: "test"})
	require.Error(t, err)
	require.Empty(t, response)
}

func TestGetSession(t *testing.T) {
	pendingRef := "pending_ref"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeGetSession(), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, pendingRef, body["pendingRef"])
	}))
	require.NoError(t, err)
	w := httptest.NewRecorder()
	info, err := a.EnchantedLink().GetSession(pendingRef, w)
	require.NoError(t, err)
	assert.NotEmpty(t, info.SessionToken.JWT)
	require.Len(t, w.Result().Cookies(), 1)
	sessionCookie := w.Result().Cookies()[0]
	require.NoError(t, err)
	assert.EqualValues(t, mockAuthSessionCookie.Value, sessionCookie.Value)
}

func TestGetEnchantedLinkSessionError(t *testing.T) {
	pendingRef := "pending_ref"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadGateway}, nil
	})
	require.NoError(t, err)
	w := httptest.NewRecorder()
	_, err = a.EnchantedLink().GetSession(pendingRef, w)
	require.Error(t, err)
}

func TestGetEnchantedLinkSessionStillPending(t *testing.T) {
	pendingRef := "pending_ref"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusUnauthorized}, nil
	})
	require.NoError(t, err)
	w := httptest.NewRecorder()
	_, err = a.EnchantedLink().GetSession(pendingRef, w)
	require.Error(t, err)
	require.ErrorIs(t, err, errors.EnchantedLinkUnauthorized)
}

func TestUpdateUserEmailEnchantedLink(t *testing.T) {
	externalID := "943248329844"
	email := "test@test.com"
	uri := "https://some.url.com"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeUpdateUserEmailEnchantedLink(), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, externalID, body["externalId"])
		assert.EqualValues(t, email, body["email"])
		assert.EqualValues(t, uri, body["URI"])
		assert.True(t, body["crossDevice"].(bool))
		u, p := getProjectAndJwt(r)
		assert.NotEmpty(t, u)
		assert.NotEmpty(t, p)
	}))
	require.NoError(t, err)
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtTokenValid})
	_, err = a.EnchantedLink().UpdateUserEmail(externalID, email, uri, r)
	require.NoError(t, err)
}

func TestUpdateUserEmailEnchantedLinkMissingArgs(t *testing.T) {
	externalID := "943248329844"
	email := "test@test.com"
	uri := "https://some.url.com"
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtTokenValid})
	_, err = a.EnchantedLink().UpdateUserEmail("", email, uri, r)
	require.Error(t, err)
	_, err = a.EnchantedLink().UpdateUserEmail(externalID, "", uri, r)
	require.Error(t, err)
	_, err = a.EnchantedLink().UpdateUserEmail(externalID, "not_a_valid_email", uri, r)
	require.Error(t, err)
}

func TestSignUpEnchantedLinkEmailNoUser(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeEnchantedLinkSignUpURL(), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["email"])
		assert.EqualValues(t, uri, m["URI"])
		assert.EqualValues(t, email, m["externalId"])
		assert.EqualValues(t, email, m["user"].(map[string]interface{})["email"])
	}))
	require.NoError(t, err)
	_, err = a.EnchantedLink().SignUp(email, uri, nil)
	require.NoError(t, err)
}
func TestSignUpOrInEnchantedLinkNoIdentifier(t *testing.T) {
	uri := "http://test.me"
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	_, err = a.EnchantedLink().SignUpOrIn("", uri)
	require.Error(t, err)
}

func TestVerifyEnchantedLink(t *testing.T) {
	token := "4444"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeVerifyEnchantedLinkURL(), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, token, body["token"])
		return &http.Response{StatusCode: http.StatusOK}, nil
	})
	require.NoError(t, err)
	err = a.EnchantedLink().Verify(token)
	require.NoError(t, err)
}

func TestVerifyEnchantedLinkError(t *testing.T) {
	token := "4444"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeVerifyEnchantedLinkURL(), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, token, body["token"])
		return &http.Response{StatusCode: http.StatusBadRequest}, nil
	})
	require.NoError(t, err)
	err = a.EnchantedLink().Verify(token)
	require.Error(t, err)
}
