package auth

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getProjectAndJwt(r *http.Request) (string, string) {
	var projectID, jwt string
	reqToken := r.Header.Get(api.AuthorizationHeaderName)
	if splitToken := strings.Split(reqToken, api.BearerAuthorizationPrefix); len(splitToken) == 2 {
		bearer := splitToken[1]
		bearers := strings.Split(bearer, ":")
		projectID = bearers[0]
		if len(bearers) > 1 {
			jwt = bearers[1]
		}
	}
	return projectID, jwt
}

func TestSignInMagicLinkEmptyLoginID(t *testing.T) {
	email := ""
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	_, err = a.MagicLink().SignIn(context.Background(), descope.MethodEmail, email, "", nil, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidArguments)

	_, err = a.MagicLink().SignIn(context.Background(), descope.MethodEmail, email, "http://test.me", nil, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidArguments)
}

func TestSignInMagicLinkStepupNoJWT(t *testing.T) {
	email := "e@e.com"
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	_, err = a.MagicLink().SignIn(context.Background(), descope.MethodEmail, email, "", nil, &descope.LoginOptions{Stepup: true})
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidStepUpJWT)
}

func TestSignInMagicLinkEmail(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	maskedEmail := "t***@email.com"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeMagicLinkSignInURL(descope.MethodEmail), r.URL.RequestURI())
		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, body["loginId"])
		assert.EqualValues(t, uri, body["URI"])
		resp := MaskedEmailRes{MaskedEmail: maskedEmail}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	me, err := a.MagicLink().SignIn(context.Background(), descope.MethodEmail, email, uri, nil, nil)
	require.NoError(t, err)
	require.EqualValues(t, maskedEmail, me)
}

func TestSignInMagicLinkEmailLoginOptions(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	maskedEmail := "t***@email.com"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeMagicLinkSignInURL(descope.MethodEmail), r.URL.RequestURI())
		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, body["loginId"])
		assert.EqualValues(t, uri, body["URI"])
		assert.EqualValues(t, map[string]interface{}{"stepup": true, "customClaims": map[string]interface{}{"k1": "v1"}}, body["loginOptions"])
		reqToken := r.Header.Get(api.AuthorizationHeaderName)
		splitToken := strings.Split(reqToken, api.BearerAuthorizationPrefix)
		require.Len(t, splitToken, 2)
		bearer := splitToken[1]
		bearers := strings.Split(bearer, ":")
		require.Len(t, bearers, 2)
		assert.EqualValues(t, "test", bearers[1])
		resp := MaskedEmailRes{MaskedEmail: maskedEmail}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	me, err := a.MagicLink().SignIn(context.Background(), descope.MethodEmail, email, uri, &http.Request{Header: http.Header{"Cookie": []string{"DSR=test"}}}, &descope.LoginOptions{Stepup: true, CustomClaims: map[string]interface{}{"k1": "v1"}})
	require.NoError(t, err)
	require.EqualValues(t, maskedEmail, me)
}

func TestSignInMagicLinkEmailLoginOptionsMFA(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"

	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeMagicLinkSignInURL(descope.MethodEmail), r.URL.RequestURI())
		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, body["loginId"])
		assert.EqualValues(t, uri, body["URI"])
		assert.EqualValues(t, map[string]interface{}{"mfa": true, "customClaims": map[string]interface{}{"k1": "v1"}}, body["loginOptions"])
		reqToken := r.Header.Get(api.AuthorizationHeaderName)
		splitToken := strings.Split(reqToken, api.BearerAuthorizationPrefix)
		require.Len(t, splitToken, 2)
		bearer := splitToken[1]
		bearers := strings.Split(bearer, ":")
		require.Len(t, bearers, 2)
		assert.EqualValues(t, "test", bearers[1])
		resp := MaskedEmailRes{MaskedEmail: "a"}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	_, err = a.MagicLink().SignIn(context.Background(), descope.MethodEmail, email, uri, &http.Request{Header: http.Header{"Cookie": []string{"DSR=test"}}}, &descope.LoginOptions{MFA: true, CustomClaims: map[string]interface{}{"k1": "v1"}})
	require.NoError(t, err)
}

func TestInvalidPhoneSignUpSMS(t *testing.T) {
	phone := "thisisemail@af.com"
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	_, err = a.MagicLink().SignUp(context.Background(), descope.MethodSMS, phone, "", &descope.User{Name: "test"}, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidArguments)

	_, err = a.MagicLink().SignUp(context.Background(), descope.MethodSMS, phone, "http://test.me", &descope.User{Name: "test"}, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidArguments)
}

func TestInvalidPhoneSignUpWhatsApp(t *testing.T) {
	phone := "thisisemail@af.com"
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	_, err = a.MagicLink().SignUp(context.Background(), descope.MethodSMS, phone, "", &descope.User{Name: "test"}, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidArguments)

	_, err = a.MagicLink().SignUp(context.Background(), descope.MethodSMS, phone, "http://test.me", &descope.User{Name: "test"}, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidArguments)
}

func TestInvalidEmailSignUpEmail(t *testing.T) {
	email := "943248329844"
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	_, err = a.MagicLink().SignUp(context.Background(), descope.MethodEmail, email, "", &descope.User{Name: "test"}, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidArguments)

	_, err = a.MagicLink().SignUp(context.Background(), descope.MethodEmail, email, "http://test.me", &descope.User{Name: "test"}, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidArguments)
}

func TestSignUpMagicLinkEmail(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	maskedEmail := "t***@email.com"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeMagicLinkSignUpURL(descope.MethodEmail), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["email"])
		assert.EqualValues(t, uri, m["URI"])
		assert.EqualValues(t, email, m["loginId"])
		assert.EqualValues(t, "test", m["user"].(map[string]interface{})["name"])
		resp := MaskedEmailRes{MaskedEmail: maskedEmail}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	me, err := a.MagicLink().SignUp(context.Background(), descope.MethodEmail, email, uri, &descope.User{Name: "test"}, nil)
	require.NoError(t, err)
	require.EqualValues(t, maskedEmail, me)
}

func TestSignUpMagicLinkEmailWithSignUpOptions(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	maskedEmail := "t***@email.com"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeMagicLinkSignUpURL(descope.MethodEmail), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["email"])
		assert.EqualValues(t, uri, m["URI"])
		assert.EqualValues(t, email, m["loginId"])
		assert.EqualValues(t, "test", m["user"].(map[string]interface{})["name"])
		resp := MaskedEmailRes{MaskedEmail: maskedEmail}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		assert.EqualValues(t, map[string]interface{}{"customClaims": map[string]interface{}{"aa": "bb"}, "templateOptions": map[string]interface{}{"cc": "dd"}}, m["loginOptions"])
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	me, err := a.MagicLink().SignUp(context.Background(), descope.MethodEmail, email, uri, &descope.User{Name: "test"}, &descope.SignUpOptions{
		CustomClaims:    map[string]interface{}{"aa": "bb"},
		TemplateOptions: map[string]interface{}{"cc": "dd"},
	})
	require.NoError(t, err)
	require.EqualValues(t, maskedEmail, me)
}

func TestSignUpMagicLinkEmailNoUser(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeMagicLinkSignUpURL(descope.MethodEmail), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["email"])
		assert.EqualValues(t, uri, m["URI"])
		assert.EqualValues(t, email, m["loginId"])
		assert.EqualValues(t, email, m["user"].(map[string]interface{})["email"])
		resp := MaskedEmailRes{MaskedEmail: "t"}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	_, err = a.MagicLink().SignUp(context.Background(), descope.MethodEmail, email, uri, nil, nil)
	require.NoError(t, err)
}

func TestSignUpOrInMagicLinkEmail(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	maskedEmail := "t***@email.com"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeMagicLinkSignUpOrInURL(descope.MethodEmail), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["loginId"])
		assert.EqualValues(t, uri, m["URI"])
		assert.Nil(t, m["user"])
		resp := MaskedEmailRes{MaskedEmail: maskedEmail}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	me, err := a.MagicLink().SignUpOrIn(context.Background(), descope.MethodEmail, email, uri, nil)
	require.NoError(t, err)
	require.EqualValues(t, maskedEmail, me)
}

func TestSignUpOrInMagicLinkEmailWithLoginOptions(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	maskedEmail := "t***@email.com"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeMagicLinkSignUpOrInURL(descope.MethodEmail), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["loginId"])
		assert.EqualValues(t, uri, m["URI"])
		assert.Nil(t, m["user"])
		resp := MaskedEmailRes{MaskedEmail: maskedEmail}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		assert.EqualValues(t, map[string]interface{}{"customClaims": map[string]interface{}{"aa": "bb"}, "templateOptions": map[string]interface{}{"cc": "dd"}}, m["loginOptions"])
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	me, err := a.MagicLink().SignUpOrIn(context.Background(), descope.MethodEmail, email, uri, &descope.SignUpOptions{
		CustomClaims:    map[string]interface{}{"aa": "bb"},
		TemplateOptions: map[string]interface{}{"cc": "dd"},
	})
	require.NoError(t, err)
	require.EqualValues(t, maskedEmail, me)
}

func TestSignUpOrInMagicLinkNoLoginID(t *testing.T) {
	uri := "http://test.me"
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	_, err = a.MagicLink().SignUpOrIn(context.Background(), descope.MethodSMS, "", uri, nil)
	require.Error(t, err)
}

func TestSignUpOrInMagicLinkSMS(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	phone := "*****1111"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeMagicLinkSignUpOrInURL(descope.MethodSMS), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["loginId"])
		assert.EqualValues(t, uri, m["URI"])
		assert.Nil(t, m["user"])
		resp := MaskedPhoneRes{MaskedPhone: phone}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	mp, err := a.MagicLink().SignUpOrIn(context.Background(), descope.MethodSMS, email, uri, nil)
	require.NoError(t, err)
	require.EqualValues(t, phone, mp)
}

func TestSignUpOrInMagicLinkWhatsapp(t *testing.T) {
	email := "test@email.com"
	uri := "http://test.me"
	phone := "*****1111"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeMagicLinkSignUpOrInURL(descope.MethodWhatsApp), r.URL.RequestURI())

		m, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, email, m["loginId"])
		assert.EqualValues(t, uri, m["URI"])
		assert.Nil(t, m["user"])
		resp := MaskedPhoneRes{MaskedPhone: phone}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	mp, err := a.MagicLink().SignUpOrIn(context.Background(), descope.MethodWhatsApp, email, uri, nil)
	require.NoError(t, err)
	require.EqualValues(t, phone, mp)
}

func TestSignUpMagicLinkSMS(t *testing.T) {
	phone := "943248329844"
	uri := "http://test.me"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeMagicLinkSignUpURL(descope.MethodSMS), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, body["phone"])
		assert.EqualValues(t, uri, body["URI"])
		assert.EqualValues(t, phone, body["loginId"])
		assert.EqualValues(t, "test", body["user"].(map[string]interface{})["name"])
	}))
	require.NoError(t, err)
	_, err = a.MagicLink().SignUp(context.Background(), descope.MethodSMS, phone, uri, &descope.User{Name: "test"}, nil)
	require.NoError(t, err)
}

func TestSignUpMagicLinkWhatsApp(t *testing.T) {
	phone := "943248329844"
	uri := "http://test.me"
	a, err := newTestAuth(nil, DoOk(func(r *http.Request) {
		assert.EqualValues(t, composeMagicLinkSignUpURL(descope.MethodWhatsApp), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, phone, body["whatsapp"])
		assert.EqualValues(t, uri, body["URI"])
		assert.EqualValues(t, phone, body["loginId"])
		assert.EqualValues(t, "test", body["user"].(map[string]interface{})["name"])
	}))
	require.NoError(t, err)
	_, err = a.MagicLink().SignUp(context.Background(), descope.MethodWhatsApp, phone, uri, &descope.User{Name: "test"}, nil)
	require.NoError(t, err)
}

func TestVerifyMagicLinkCodeWithSession(t *testing.T) {
	token := "4444"
	firstSeen := true
	name := "name"
	phone := "+11111111111"
	picture := "@(^_^)@"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeVerifyMagicLinkURL(), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, token, body["token"])
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
	info, err := a.MagicLink().Verify(context.Background(), token, w)
	require.NoError(t, err)
	assert.NotEmpty(t, info.SessionToken.JWT)
	assert.Equal(t, firstSeen, info.FirstSeen)
	assert.Equal(t, name, info.User.Name)
	assert.Equal(t, phone, info.User.Phone)
	assert.Equal(t, picture, info.User.Picture)
	require.Len(t, w.Result().Cookies(), 0)
}

func TestVerifyMagicLinkCodeNoSession(t *testing.T) {
	token := "4444"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeVerifyMagicLinkURL(), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, token, body["token"])
		return &http.Response{StatusCode: http.StatusOK}, nil
	})
	require.NoError(t, err)
	w := httptest.NewRecorder()
	info, err := a.MagicLink().Verify(context.Background(), token, w)
	require.NoError(t, err)
	assert.Empty(t, info)
}

func TestUpdateUserEmail(t *testing.T) {
	loginID := "943248329844"
	email := "test@test.com"
	maskedEmail := "t***@test.com"
	uri := "https://some.url.com"
	checkOptions := true
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeUpdateUserEmailMagicLink(), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, loginID, body["loginId"])
		assert.EqualValues(t, email, body["email"])
		assert.EqualValues(t, uri, body["URI"])
		assert.Nil(t, body["crossDevice"])
		if checkOptions {
			assert.EqualValues(t, true, body["addToLoginIDs"])
			assert.EqualValues(t, true, body["onMergeUseExisting"])
		} else {
			assert.EqualValues(t, nil, body["addToLoginIDs"])
			assert.EqualValues(t, nil, body["onMergeUseExisting"])
		}

		u, p := getProjectAndJwt(r)
		assert.NotEmpty(t, u)
		assert.NotEmpty(t, p)
		resp := MaskedEmailRes{MaskedEmail: maskedEmail}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})

	require.NoError(t, err)
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtTokenValid})
	me, err := a.MagicLink().UpdateUserEmail(context.Background(), loginID, email, uri, &descope.UpdateOptions{AddToLoginIDs: true, OnMergeUseExisting: true}, r)
	require.NoError(t, err)
	require.EqualValues(t, maskedEmail, me)
	checkOptions = false
	me, err = a.MagicLink().UpdateUserEmail(context.Background(), loginID, email, uri, nil, r)
	require.NoError(t, err)
	require.EqualValues(t, maskedEmail, me)
}

func TestUpdateUserEmailWithTemplateOptions(t *testing.T) {
	loginID := "943248329844"
	email := "test@test.com"
	maskedEmail := "t***@test.com"
	uri := "https://some.url.com"
	checkOptions := true
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeUpdateUserEmailMagicLink(), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, loginID, body["loginId"])
		assert.EqualValues(t, email, body["email"])
		assert.EqualValues(t, uri, body["URI"])
		assert.Nil(t, body["crossDevice"])
		if checkOptions {
			assert.EqualValues(t, true, body["addToLoginIDs"])
			assert.EqualValues(t, true, body["onMergeUseExisting"])
			assert.EqualValues(t, map[string]interface{}{"cc": "dd"}, body["templateOptions"])
		} else {
			assert.EqualValues(t, nil, body["addToLoginIDs"])
			assert.EqualValues(t, nil, body["onMergeUseExisting"])
			assert.EqualValues(t, nil, body["templateOptions"])
		}

		u, p := getProjectAndJwt(r)
		assert.NotEmpty(t, u)
		assert.NotEmpty(t, p)
		resp := MaskedEmailRes{MaskedEmail: maskedEmail}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})

	require.NoError(t, err)
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtTokenValid})
	me, err := a.MagicLink().UpdateUserEmail(context.Background(), loginID, email, uri, &descope.UpdateOptions{AddToLoginIDs: true, OnMergeUseExisting: true, TemplateOptions: map[string]interface{}{"cc": "dd"}}, r)
	require.NoError(t, err)
	require.EqualValues(t, maskedEmail, me)
	checkOptions = false
	me, err = a.MagicLink().UpdateUserEmail(context.Background(), loginID, email, uri, nil, r)
	require.NoError(t, err)
	require.EqualValues(t, maskedEmail, me)
}

func TestUpdateEmailMagicLinkFailures(t *testing.T) {
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtTokenValid})
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	_, err = a.MagicLink().UpdateUserEmail(context.Background(), "", "email@email.com", "", nil, r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "loginID"))
	_, err = a.MagicLink().UpdateUserEmail(context.Background(), "id", "", "", nil, r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "email"))
	_, err = a.MagicLink().UpdateUserEmail(context.Background(), "id", "email", "", nil, r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "email"))
}

func TestUpdateUserPhone(t *testing.T) {
	loginID := "943248329844"
	phone := "+111111111111"
	maskedPhone := "*****1111"
	uri := "https://some.url.com"
	checkOptions := true
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeUpdateUserPhoneMagiclink(descope.MethodSMS), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, loginID, body["loginId"])
		assert.EqualValues(t, phone, body["phone"])
		assert.EqualValues(t, uri, body["URI"])
		if checkOptions {
			assert.EqualValues(t, true, body["addToLoginIDs"])
			assert.EqualValues(t, true, body["onMergeUseExisting"])
		} else {
			assert.EqualValues(t, nil, body["addToLoginIDs"])
			assert.EqualValues(t, nil, body["onMergeUseExisting"])
		}
		assert.Nil(t, body["crossDevice"])
		u, p := getProjectAndJwt(r)
		assert.NotEmpty(t, u)
		assert.NotEmpty(t, p)
		resp := MaskedPhoneRes{MaskedPhone: maskedPhone}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtTokenValid})
	mp, err := a.MagicLink().UpdateUserPhone(context.Background(), descope.MethodSMS, loginID, phone, uri, &descope.UpdateOptions{AddToLoginIDs: true, OnMergeUseExisting: true}, r)
	require.NoError(t, err)
	require.EqualValues(t, maskedPhone, mp)
	checkOptions = false
	mp, err = a.MagicLink().UpdateUserPhone(context.Background(), descope.MethodSMS, loginID, phone, uri, nil, r)
	require.NoError(t, err)
	require.EqualValues(t, maskedPhone, mp)
}

func TestUpdateUserPhoneWithTemplateOptions(t *testing.T) {
	loginID := "943248329844"
	phone := "+111111111111"
	maskedPhone := "*****1111"
	uri := "https://some.url.com"
	checkOptions := true
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeUpdateUserPhoneMagiclink(descope.MethodSMS), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, loginID, body["loginId"])
		assert.EqualValues(t, phone, body["phone"])
		assert.EqualValues(t, uri, body["URI"])
		if checkOptions {
			assert.EqualValues(t, true, body["addToLoginIDs"])
			assert.EqualValues(t, true, body["onMergeUseExisting"])
			assert.EqualValues(t, map[string]interface{}{"cc": "dd"}, body["templateOptions"])
		} else {
			assert.EqualValues(t, nil, body["addToLoginIDs"])
			assert.EqualValues(t, nil, body["onMergeUseExisting"])
			assert.EqualValues(t, nil, body["templateOptions"])
		}
		assert.Nil(t, body["crossDevice"])
		u, p := getProjectAndJwt(r)
		assert.NotEmpty(t, u)
		assert.NotEmpty(t, p)
		resp := MaskedPhoneRes{MaskedPhone: maskedPhone}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtTokenValid})
	mp, err := a.MagicLink().UpdateUserPhone(context.Background(), descope.MethodSMS, loginID, phone, uri, &descope.UpdateOptions{AddToLoginIDs: true, OnMergeUseExisting: true, TemplateOptions: map[string]interface{}{"cc": "dd"}}, r)
	require.NoError(t, err)
	require.EqualValues(t, maskedPhone, mp)
	checkOptions = false
	mp, err = a.MagicLink().UpdateUserPhone(context.Background(), descope.MethodSMS, loginID, phone, uri, nil, r)
	require.NoError(t, err)
	require.EqualValues(t, maskedPhone, mp)
}

func TestUpdatePhoneMagicLinkFailures(t *testing.T) {
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: jwtTokenValid})
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	_, err = a.MagicLink().UpdateUserPhone(context.Background(), descope.MethodSMS, "", "+1111111111", "", nil, r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "loginID"))
	_, err = a.MagicLink().UpdateUserPhone(context.Background(), descope.MethodSMS, "id", "", "", nil, r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "phone"))
	_, err = a.MagicLink().UpdateUserPhone(context.Background(), descope.MethodSMS, "id", "phone", "", nil, r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "phone"))
	_, err = a.MagicLink().UpdateUserPhone(context.Background(), descope.MethodEmail, "id", "+1111111111", "", nil, r)
	assert.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "method"))
	r = &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: "somename", Value: jwtTokenValid})
	_, err = a.MagicLink().UpdateUserPhone(context.Background(), descope.MethodSMS, "id", "+111111111111", "", nil, r)
	assert.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrRefreshToken)
}
