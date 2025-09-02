package auth

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignInEnchantedLinkEmptyLoginID(t *testing.T) {
	email := ""
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	_, err = a.EnchantedLink().SignIn(context.Background(), email, "", nil, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidArguments)
}

func TestSignInEnchantedLinkStepupNoJwt(t *testing.T) {
	email := "test@test.com"
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	_, err = a.EnchantedLink().SignIn(context.Background(), email, "", nil, &descope.LoginOptions{Stepup: true})
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidStepUpJWT)
}

func TestSignInEnchantedLink(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	pendingRefResponse := "pending_ref"
	loginID := "loginID"
	maskedEmail := "t**@email.com"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeEnchantedLinkSignInURL(), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["loginId"])
		assert.EqualValues(t, uri, m["URI"])
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(fmt.Sprintf(`{"pendingRef": "%s","linkId": "%s", "maskedEmail":"%s"}`, pendingRefResponse, loginID, maskedEmail))),
		}, nil
	})
	require.NoError(t, err)
	response, err := a.EnchantedLink().SignIn(context.Background(), email, uri, nil, nil)
	require.NoError(t, err)
	require.EqualValues(t, pendingRefResponse, response.PendingRef)
	require.EqualValues(t, loginID, response.LinkID)
	require.EqualValues(t, maskedEmail, response.MaskedEmail)
}

func TestSignInEnchantedLinkStepup(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	pendingRefResponse := "pending_ref"
	loginID := "loginID"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeEnchantedLinkSignInURL(), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["loginId"])
		assert.EqualValues(t, uri, m["URI"])
		assert.EqualValues(t, map[string]any{"stepup": true, "customClaims": map[string]any{"k1": "v1"}}, m["loginOptions"])
		reqToken := r.Header.Get(api.AuthorizationHeaderName)
		splitToken := strings.Split(reqToken, api.BearerAuthorizationPrefix)
		require.Len(t, splitToken, 2)
		bearer := splitToken[1]
		bearers := strings.Split(bearer, ":")
		require.Len(t, bearers, 2)
		assert.EqualValues(t, "test", bearers[1])
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(fmt.Sprintf(`{"pendingRef": "%s","linkId": "%s"}`, pendingRefResponse, loginID))),
		}, nil
	})
	require.NoError(t, err)
	response, err := a.EnchantedLink().SignIn(context.Background(), email, uri, &http.Request{Header: http.Header{"Cookie": []string{"DSR=test"}}}, &descope.LoginOptions{Stepup: true, CustomClaims: map[string]any{"k1": "v1"}})
	require.NoError(t, err)
	require.EqualValues(t, pendingRefResponse, response.PendingRef)
	require.EqualValues(t, loginID, response.LinkID)
}

func TestSignInEnchantedLinkInvalidResponse(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	a, err := newTestAuth(nil, func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(`{"pendingRef"`)),
		}, nil
	})
	require.NoError(t, err)
	res, err := a.EnchantedLink().SignIn(context.Background(), email, uri, nil, nil)
	require.Error(t, err)
	require.Empty(t, res)
}

func TestSignUpEnchantedLink(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	pendingRefResponse := "pending_ref"
	loginID := "loginID"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeEnchantedLinkSignUpURL(), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["email"])
		assert.EqualValues(t, uri, m["URI"])
		assert.EqualValues(t, email, m["loginId"])
		assert.EqualValues(t, "test", m["user"].(map[string]any)["name"])
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(fmt.Sprintf(`{"pendingRef": "%s","linkId": "%s"}`, pendingRefResponse, loginID))),
		}, nil
	})
	require.NoError(t, err)
	response, err := a.EnchantedLink().SignUp(context.Background(), email, uri, &descope.User{Name: "test"}, nil)
	require.NoError(t, err)
	require.EqualValues(t, pendingRefResponse, response.PendingRef)
	require.EqualValues(t, loginID, response.LinkID)
}

func TestSignUpEnchantedLinkWithSignUpOptions(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	pendingRefResponse := "pending_ref"
	loginID := "loginID"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeEnchantedLinkSignUpURL(), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["email"])
		assert.EqualValues(t, uri, m["URI"])
		assert.EqualValues(t, email, m["loginId"])
		assert.EqualValues(t, "test", m["user"].(map[string]any)["name"])
		assert.EqualValues(t, map[string]any{"customClaims": map[string]any{"aa": "bb"}, "templateOptions": map[string]any{"cc": "dd"}, "templateId": "foo"}, m["loginOptions"])
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(fmt.Sprintf(`{"pendingRef": "%s","linkId": "%s"}`, pendingRefResponse, loginID))),
		}, nil
	})
	require.NoError(t, err)
	response, err := a.EnchantedLink().SignUp(context.Background(), email, uri, &descope.User{Name: "test"}, &descope.SignUpOptions{
		CustomClaims:    map[string]any{"aa": "bb"},
		TemplateOptions: map[string]string{"cc": "dd"},
		TemplateID:      "foo",
	})
	require.NoError(t, err)
	require.EqualValues(t, pendingRefResponse, response.PendingRef)
	require.EqualValues(t, loginID, response.LinkID)
}

func TestSignUpOrInEnchantedLink(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	pendingRefResponse := "pending_ref"
	loginID := "ident"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeEnchantedLinkSignUpOrInURL(), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["loginId"])
		assert.EqualValues(t, uri, m["URI"])
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(fmt.Sprintf(`{"pendingRef": "%s", "linkId": "%s"}`, pendingRefResponse, loginID))),
		}, nil
	})
	require.NoError(t, err)
	response, err := a.EnchantedLink().SignUpOrIn(context.Background(), email, uri, nil)
	require.NoError(t, err)
	require.EqualValues(t, pendingRefResponse, response.PendingRef)
	require.EqualValues(t, loginID, response.LinkID)
}

func TestSignUpOrInEnchantedLinkWithLoginOptions(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	pendingRefResponse := "pending_ref"
	loginID := "ident"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeEnchantedLinkSignUpOrInURL(), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["loginId"])
		assert.EqualValues(t, uri, m["URI"])
		assert.EqualValues(t, map[string]any{"customClaims": map[string]any{"aa": "bb"}, "templateOptions": map[string]any{"cc": "dd"}}, m["loginOptions"])
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(fmt.Sprintf(`{"pendingRef": "%s", "linkId": "%s"}`, pendingRefResponse, loginID))),
		}, nil
	})
	require.NoError(t, err)
	response, err := a.EnchantedLink().SignUpOrIn(context.Background(), email, uri, &descope.SignUpOptions{
		CustomClaims:    map[string]any{"aa": "bb"},
		TemplateOptions: map[string]string{"cc": "dd"},
	})
	require.NoError(t, err)
	require.EqualValues(t, pendingRefResponse, response.PendingRef)
	require.EqualValues(t, loginID, response.LinkID)
}

func TestSignUpEnchantedLinkEmptyLoginID(t *testing.T) {
	uri := "http://test.me"
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	response, err := a.EnchantedLink().SignUp(context.Background(), "", uri, &descope.User{Name: "test"}, nil)
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
	info, err := a.EnchantedLink().GetSession(context.Background(), pendingRef, w)
	require.NoError(t, err)
	assert.NotEmpty(t, info.SessionToken.JWT)
	require.Len(t, w.Result().Cookies(), 1) // Just the refresh token
}

func TestGetSessionGenerateAuthenticationInfoValidDSRCookie(t *testing.T) {
	pendingRef := "pending_ref"
	a, err := newTestAuth(nil, func(_ *http.Request) (*http.Response, error) {
		cookie := &http.Cookie{Name: descope.RefreshCookieName, Value: jwtRTokenValid} // valid token
		return &http.Response{StatusCode: http.StatusOK,
			Body:   io.NopCloser(bytes.NewBufferString(mockAuthSessionBodyNoRefreshJwt)),
			Header: http.Header{"Set-Cookie": []string{cookie.String()}},
		}, nil
	})
	a.conf.SessionJWTViaCookie = true
	require.NoError(t, err)

	w := httptest.NewRecorder()
	info, err := a.EnchantedLink().GetSession(context.Background(), pendingRef, w)
	require.NoError(t, err)
	assert.NotEmpty(t, info.SessionToken.JWT)
	assert.NotEmpty(t, info.RefreshToken.JWT) // make sure refresh token exist
}

func TestGetSessionGenerateAuthenticationInfoInValidDSRCookie(t *testing.T) {
	pendingRef := "pending_ref"
	a, err := newTestAuth(nil, func(_ *http.Request) (*http.Response, error) {
		cookie := &http.Cookie{Name: descope.RefreshCookieName, Value: jwtTokenExpired} // invalid token
		return &http.Response{StatusCode: http.StatusOK,
			Body:   io.NopCloser(bytes.NewBufferString(mockAuthSessionBodyNoRefreshJwt)),
			Header: http.Header{"Set-Cookie": []string{cookie.String()}},
		}, nil
	})
	a.conf.SessionJWTViaCookie = true
	require.NoError(t, err)

	w := httptest.NewRecorder()
	_, err = a.EnchantedLink().GetSession(context.Background(), pendingRef, w)
	require.Error(t, err) // should get error as Refresh cookie is invalid
}

func TestGetSessionGenerateAuthenticationInfoNoDSRCookie(t *testing.T) {
	pendingRef := "pending_ref"
	a, err := newTestAuth(nil, func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK,
			Body: io.NopCloser(bytes.NewBufferString(mockAuthSessionBodyNoRefreshJwt)),
		}, nil
	})
	a.conf.SessionJWTViaCookie = true
	require.NoError(t, err)

	w := httptest.NewRecorder()
	info, err := a.EnchantedLink().GetSession(context.Background(), pendingRef, w)
	require.NoError(t, err)
	assert.NotEmpty(t, info.SessionToken.JWT)
	assert.Nil(t, info.RefreshToken) // there is no DSR cookie so refresh token is not exist (not on body and not on cookie)
}

func TestGetEnchantedLinkSessionError(t *testing.T) {
	pendingRef := "pending_ref"
	a, err := newTestAuth(nil, func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadGateway}, nil
	})
	require.NoError(t, err)
	w := httptest.NewRecorder()
	_, err = a.EnchantedLink().GetSession(context.Background(), pendingRef, w)
	require.Error(t, err)
}

func TestGetEnchantedLinkSessionStillPending(t *testing.T) {
	pendingRef := "pending_ref"
	expectedResponse := map[string]string{"errorCode": "E062503"}
	a, err := newTestAuth(nil, DoWithBody(http.StatusUnauthorized, nil, expectedResponse))
	require.NoError(t, err)
	w := httptest.NewRecorder()
	_, err = a.EnchantedLink().GetSession(context.Background(), pendingRef, w)
	require.Error(t, err)
	require.ErrorIs(t, err, descope.ErrEnchantedLinkUnauthorized)
}

func TestUpdateUserEmailEnchantedLink(t *testing.T) {
	loginID := "943248329844"
	email := "test@test.com"
	uri := "https://some.url.com"
	checkOptions := true
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeUpdateUserEmailEnchantedLink(), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, loginID, body["loginId"])
		assert.EqualValues(t, email, body["email"])
		assert.EqualValues(t, uri, body["URI"])
		if checkOptions {
			assert.EqualValues(t, true, body["addToLoginIDs"])
			assert.EqualValues(t, true, body["onMergeUseExisting"])
		} else {
			assert.EqualValues(t, nil, body["addToLoginIDs"])
			assert.EqualValues(t, nil, body["onMergeUseExisting"])
		}
		assert.True(t, body["crossDevice"].(bool))
		u, p := getProjectAndJwt(r)
		assert.NotEmpty(t, u)
		assert.NotEmpty(t, p)
	}))
	require.NoError(t, err)
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtTokenValid})
	_, err = a.EnchantedLink().UpdateUserEmail(context.Background(), loginID, email, uri, &descope.UpdateOptions{AddToLoginIDs: true, OnMergeUseExisting: true}, r)
	require.NoError(t, err)
	checkOptions = false
	_, err = a.EnchantedLink().UpdateUserEmail(context.Background(), loginID, email, uri, nil, r)
	require.NoError(t, err)
}

func TestUpdateUserEmailEnchantedLinkWithTemplateOptions(t *testing.T) {
	loginID := "943248329844"
	email := "test@test.com"
	uri := "https://some.url.com"
	checkOptions := true
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeUpdateUserEmailEnchantedLink(), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, loginID, body["loginId"])
		assert.EqualValues(t, email, body["email"])
		assert.EqualValues(t, uri, body["URI"])
		if checkOptions {
			assert.EqualValues(t, true, body["addToLoginIDs"])
			assert.EqualValues(t, true, body["onMergeUseExisting"])
			assert.EqualValues(t, map[string]any{"cc": "dd"}, body["templateOptions"])
		} else {
			assert.EqualValues(t, nil, body["addToLoginIDs"])
			assert.EqualValues(t, nil, body["onMergeUseExisting"])
			assert.EqualValues(t, nil, body["templateOptions"])
		}
		assert.True(t, body["crossDevice"].(bool))
		u, p := getProjectAndJwt(r)
		assert.NotEmpty(t, u)
		assert.NotEmpty(t, p)
	}))
	require.NoError(t, err)
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtTokenValid})
	_, err = a.EnchantedLink().UpdateUserEmail(context.Background(), loginID, email, uri, &descope.UpdateOptions{AddToLoginIDs: true, OnMergeUseExisting: true, TemplateOptions: map[string]string{"cc": "dd"}}, r)
	require.NoError(t, err)
	checkOptions = false
	_, err = a.EnchantedLink().UpdateUserEmail(context.Background(), loginID, email, uri, nil, r)
	require.NoError(t, err)
}

func TestUpdateUserEmailEnchantedLinkMissingArgs(t *testing.T) {
	loginID := "943248329844"
	email := "test@test.com"
	uri := "https://some.url.com"
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtTokenValid})
	_, err = a.EnchantedLink().UpdateUserEmail(context.Background(), "", email, uri, nil, r)
	require.Error(t, err)
	_, err = a.EnchantedLink().UpdateUserEmail(context.Background(), loginID, "", uri, nil, r)
	require.Error(t, err)
	_, err = a.EnchantedLink().UpdateUserEmail(context.Background(), loginID, "not_a_valid_email", uri, nil, r)
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
		assert.EqualValues(t, email, m["loginId"])
		assert.EqualValues(t, email, m["user"].(map[string]any)["email"])
	}))
	require.NoError(t, err)
	_, err = a.EnchantedLink().SignUp(context.Background(), email, uri, nil, nil)
	require.NoError(t, err)
}
func TestSignUpOrInEnchantedLinkNoLoginID(t *testing.T) {
	uri := "http://test.me"
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	_, err = a.EnchantedLink().SignUpOrIn(context.Background(), "", uri, nil)
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
	err = a.EnchantedLink().Verify(context.Background(), token)
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
	err = a.EnchantedLink().Verify(context.Background(), token)
	require.Error(t, err)
}
