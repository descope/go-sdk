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

const (
	image       = "image-1"
	redirectURL = "url-1"
)

func TestSignInNOTPEmptyLoginID(t *testing.T) {
	phone := ""
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(`{"pendingRef": "pr1","image": "image1", "redirectUrl":"redirect-1"}`)),
		}, nil
	})
	require.NoError(t, err)
	_, err = a.NOTP().SignIn(context.Background(), phone, nil, nil)
	require.NoError(t, err)
}

func TestSignInNOTPStepupNoJwt(t *testing.T) {
	phone := "+111111111111"
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	_, err = a.NOTP().SignIn(context.Background(), phone, nil, &descope.LoginOptions{Stepup: true})
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidStepUpJWT)
}

func TestSignInNOTP(t *testing.T) {
	phone := "+111111111111"
	pendingRefResponse := "pending_ref"

	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeNOTPSignInURL(), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, m["loginId"])
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(fmt.Sprintf(`{"pendingRef": "%s","image": "%s", "redirectUrl":"%s"}`, pendingRefResponse, image, redirectURL))),
		}, nil
	})
	require.NoError(t, err)
	response, err := a.NOTP().SignIn(context.Background(), phone, nil, nil)
	require.NoError(t, err)
	require.EqualValues(t, pendingRefResponse, response.PendingRef)
	require.EqualValues(t, image, response.Image)
	require.EqualValues(t, redirectURL, response.RedirectURL)
}

func TestSignInNOTPStepup(t *testing.T) {
	phone := "+111111111111"
	pendingRefResponse := "pending_ref"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeNOTPSignInURL(), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, m["loginId"])
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
			Body:       io.NopCloser(bytes.NewBufferString(fmt.Sprintf(`{"pendingRef": "%s","image": "%s"}`, pendingRefResponse, image))),
		}, nil
	})
	require.NoError(t, err)
	response, err := a.NOTP().SignIn(context.Background(), phone, &http.Request{Header: http.Header{"Cookie": []string{"DSR=test"}}}, &descope.LoginOptions{Stepup: true, CustomClaims: map[string]interface{}{"k1": "v1"}})
	require.NoError(t, err)
	require.EqualValues(t, pendingRefResponse, response.PendingRef)
	require.EqualValues(t, image, response.Image)
}

func TestSignInNOTPInvalidResponse(t *testing.T) {
	phone := "+111111111111"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(`{"pendingRef"`)),
		}, nil
	})
	require.NoError(t, err)
	res, err := a.NOTP().SignIn(context.Background(), phone, nil, nil)
	require.Error(t, err)
	require.Empty(t, res)
}

func TestSignUpNOTP(t *testing.T) {
	phone := "+111111111111"
	pendingRefResponse := "pending_ref"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeNOTPSignUpURL(), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, m["phone"])
		assert.EqualValues(t, phone, m["loginId"])
		assert.EqualValues(t, "test", m["user"].(map[string]interface{})["name"])
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(fmt.Sprintf(`{"pendingRef": "%s","image": "%s"}`, pendingRefResponse, image))),
		}, nil
	})
	require.NoError(t, err)
	response, err := a.NOTP().SignUp(context.Background(), phone, &descope.User{Name: "test"}, nil)
	require.NoError(t, err)
	require.EqualValues(t, pendingRefResponse, response.PendingRef)
	require.EqualValues(t, image, response.Image)
}

func TestSignUpNOTPWithSignUpOptions(t *testing.T) {
	phone := "+111111111111"
	pendingRefResponse := "pending_ref"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeNOTPSignUpURL(), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, m["phone"])
		assert.EqualValues(t, phone, m["loginId"])
		assert.EqualValues(t, "test", m["user"].(map[string]interface{})["name"])
		assert.EqualValues(t, map[string]interface{}{"customClaims": map[string]interface{}{"aa": "bb"}, "templateOptions": map[string]interface{}{"cc": "dd"}}, m["loginOptions"])
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(fmt.Sprintf(`{"pendingRef": "%s","image": "%s"}`, pendingRefResponse, image))),
		}, nil
	})
	require.NoError(t, err)
	response, err := a.NOTP().SignUp(context.Background(), phone, &descope.User{Name: "test"}, &descope.SignUpOptions{
		CustomClaims:    map[string]interface{}{"aa": "bb"},
		TemplateOptions: map[string]string{"cc": "dd"},
	})
	require.NoError(t, err)
	require.EqualValues(t, pendingRefResponse, response.PendingRef)
	require.EqualValues(t, image, response.Image)
}

func TestSignUpOrInNOTP(t *testing.T) {
	phone := "+111111111111"
	pendingRefResponse := "pending_ref"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeNOTPSignUpOrInURL(), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, m["loginId"])
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(fmt.Sprintf(`{"pendingRef": "%s", "image": "%s"}`, pendingRefResponse, image))),
		}, nil
	})
	require.NoError(t, err)
	response, err := a.NOTP().SignUpOrIn(context.Background(), phone, nil)
	require.NoError(t, err)
	require.EqualValues(t, pendingRefResponse, response.PendingRef)
	require.EqualValues(t, image, response.Image)
}

func TestSignUpOrInNOTPWithLoginOptions(t *testing.T) {
	phone := "+111111111111"
	pendingRefResponse := "pending_ref"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeNOTPSignUpOrInURL(), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, m["loginId"])
		assert.EqualValues(t, map[string]interface{}{"customClaims": map[string]interface{}{"aa": "bb"}, "templateOptions": map[string]interface{}{"cc": "dd"}}, m["loginOptions"])
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(fmt.Sprintf(`{"pendingRef": "%s", "image": "%s"}`, pendingRefResponse, image))),
		}, nil
	})
	require.NoError(t, err)
	response, err := a.NOTP().SignUpOrIn(context.Background(), phone, &descope.SignUpOptions{
		CustomClaims:    map[string]interface{}{"aa": "bb"},
		TemplateOptions: map[string]string{"cc": "dd"},
	})
	require.NoError(t, err)
	require.EqualValues(t, pendingRefResponse, response.PendingRef)
	require.EqualValues(t, image, response.Image)
}

func TestSignUpNOTPEmptyLoginID(t *testing.T) {
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(`{"pendingRef": "pr1","image": "image1", "redirectUrl":"redirect-1"}`)),
		}, nil
	})
	require.NoError(t, err)
	_, err = a.NOTP().SignUp(context.Background(), "", &descope.User{Name: "test"}, nil)
	require.NoError(t, err)
}

func TestNOTPGetSession(t *testing.T) {
	pendingRef := "pending_ref"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeNOTPGetSession(), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, pendingRef, body["pendingRef"])
	}))
	require.NoError(t, err)
	w := httptest.NewRecorder()
	info, err := a.NOTP().GetSession(context.Background(), pendingRef, w)
	require.NoError(t, err)
	assert.NotEmpty(t, info.SessionToken.JWT)
	require.Len(t, w.Result().Cookies(), 1) // Just the refresh token
}

func TestNOTPGetSessionGenerateAuthenticationInfoValidDSRCookie(t *testing.T) {
	pendingRef := "pending_ref"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		cookie := &http.Cookie{Name: descope.RefreshCookieName, Value: jwtRTokenValid} // valid token
		return &http.Response{StatusCode: http.StatusOK,
			Body:   io.NopCloser(bytes.NewBufferString(mockAuthSessionBodyNoRefreshJwt)),
			Header: http.Header{"Set-Cookie": []string{cookie.String()}},
		}, nil
	})
	a.conf.SessionJWTViaCookie = true
	require.NoError(t, err)

	w := httptest.NewRecorder()
	info, err := a.NOTP().GetSession(context.Background(), pendingRef, w)
	require.NoError(t, err)
	assert.NotEmpty(t, info.SessionToken.JWT)
	assert.NotEmpty(t, info.RefreshToken.JWT) // make sure refresh token exist
}

func TestNOTPGetSessionGenerateAuthenticationInfoInValidDSRCookie(t *testing.T) {
	pendingRef := "pending_ref"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		cookie := &http.Cookie{Name: descope.RefreshCookieName, Value: jwtTokenExpired} // invalid token
		return &http.Response{StatusCode: http.StatusOK,
			Body:   io.NopCloser(bytes.NewBufferString(mockAuthSessionBodyNoRefreshJwt)),
			Header: http.Header{"Set-Cookie": []string{cookie.String()}},
		}, nil
	})
	a.conf.SessionJWTViaCookie = true
	require.NoError(t, err)

	w := httptest.NewRecorder()
	_, err = a.NOTP().GetSession(context.Background(), pendingRef, w)
	require.Error(t, err) // should get error as Refresh cookie is invalid
}

func TesNOTPtGetSessionGenerateAuthenticationInfoNoDSRCookie(t *testing.T) {
	pendingRef := "pending_ref"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK,
			Body: io.NopCloser(bytes.NewBufferString(mockAuthSessionBodyNoRefreshJwt)),
		}, nil
	})
	a.conf.SessionJWTViaCookie = true
	require.NoError(t, err)

	w := httptest.NewRecorder()
	info, err := a.NOTP().GetSession(context.Background(), pendingRef, w)
	require.NoError(t, err)
	assert.NotEmpty(t, info.SessionToken.JWT)
	assert.Nil(t, info.RefreshToken) // there is no DSR cookie so refresh token is not exist (not on body and not on cookie)
}

func TestGetNOTPSessionError(t *testing.T) {
	pendingRef := "pending_ref"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadGateway}, nil
	})
	require.NoError(t, err)
	w := httptest.NewRecorder()
	_, err = a.NOTP().GetSession(context.Background(), pendingRef, w)
	require.Error(t, err)
}

func TestSignUpNOTPNoUser(t *testing.T) {
	phone := "+111111111111"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeNOTPSignUpURL(), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, m["phone"])
		assert.EqualValues(t, phone, m["loginId"])
		assert.EqualValues(t, phone, m["user"].(map[string]interface{})["phone"])
	}))
	require.NoError(t, err)
	_, err = a.NOTP().SignUp(context.Background(), phone, nil, nil)
	require.NoError(t, err)
}
func TestSignUpOrInNOTPNoLoginID(t *testing.T) {
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(bytes.NewBufferString(`{"pendingRef": "pr1","image": "image1", "redirectUrl":"redirect-1"}`)),
		}, nil
	})
	require.NoError(t, err)
	_, err = a.NOTP().SignUpOrIn(context.Background(), "", nil)
	require.NoError(t, err)
}
