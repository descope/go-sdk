package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/errors"
	"github.com/descope/go-sdk/descope/tests/mocks"
	"github.com/descope/go-sdk/descope/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	jwtTokenValid    = `eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCIsImtpZCI6ImU0YTU3Y2M5ZGZiNDAyYTNlNTNjNDJhNjQyMmY3M2FmIiwiZXhwIjoyNjU2MjU4NjkxfQ.eyJjb29raWVOYW1lIjoiRFMifQ.TyOg1RVbYzY2u5PPyZ-ogzLS15lBROtwQEzNCbOojEdAoQct-yr5RQLBhAejbgUnLjDqWNUj_Dj4t37N6Dl4II-P5ZHeqV0rVppntjGiKNehvE8x6KR_JV5xi59_OFg7xBbUEW7iWPGPxTYumb91GKddnYgyEppaeQDgIjNJAgHp6-bcZ5kKYTABbXqeDzXLKCx7NqVrSB86ZkUmJ09uTIkRcifyz4EZfJzxUhm1jJULmlDpI_q3JZxfrVViBlKuPH18qm9i68GXMiwcBRsunok0bP1zMjhoolu748pLUTYVGpzr67Styg5FcLYLV2dNEFahJYQfWvWg1CyU5cHXktxyPdr9ANlhPmkzcKGYvdL6cVYB5ynmfAE8RgrwiyCWgIl6Bt_OFn3ArraEo6YSCVSdNhRf0N3_aHkXwQUjACtpyGx35VuiUgrU-9UT43YPllIUmTLeASXNEQpWZ9FvlU1KeYyMNx9UkkXzc_c3tcyW9XZ1Ib8QOW1BEAREA1y_`
	jwtTokenExpired  = `eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCIsImtpZCI6ImU0YTU3Y2M5ZGZiNDAyYTNlNTNjNDJhNjQyMmY3M2FmIn0.eyJjb29raWVOYW1lIjoiRFMiLCJleHAiOjEyNTYyNTg2OTF9.AvU50pkQt8F000JqpVy7vCbcV-pwGqyi_GENqmmqrRMVswk5Y5VfSjP7axBnZ55xJ85sP6ozawbs_g1FdGtzvgrHEIJVRJSe73EwWTV9yZwiUD8kU-QAtUqP_Vk-rf-3zzE1lmI3DubXZYGTE4tMUsIQ-2NI3-Q9R89yzjLMv9z7_0TaDB28LMCJPlmjTA-7x_FoWqxmCs0z00dZ6sthtppbo25DiO3EW7D35gE1CPOgITjktWSRt035TR0iV91YoPyPAkmEo3mxI4XXu-1fLcZdFFTZOOU4TmA-_wbXevf0kIaQ9Kl4jPEK9lSUHEhLG59nu_0aPVxUXqE-Y8Qo7Ed-Gri5fPhZarDtMRRpVc1pc7D8zYMyKEHvCqkdjV9MDfIK3eCVuCGUxytgEe4Px-sgPSS_7Ne8hZ1T7K3TbcoMlRl--fI6rbmcOj-2srCcofr9NX2pxeUdWU8g6ZfFFxADSfJNb0MbZz55QGN8yz-54jZR3nT7i7kXX0ylrDQw`
	jwtTokenNotYet   = `eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzM4NCIsImtpZCI6ImU0YTU3Y2M5ZGZiNDAyYTNlNTNjNDJhNjQyMmY3M2FmIn0.eyJjb29raWVOYW1lIjoiRFMiLCJuYmYiOjI2NTYyNTg2OTF9.dvkNfmyUgbhlwv2eW_qC8VfcKYaMKaS8aDM2XdgYxnLuOhQUNnlY87H8bQGw7RChvqyJtciFo74KFhTZkAWqKDpdisIPDnydJ7SzY-NOv6Mtg0DAl99nDuItsYDoSIHVV_3h6feZC353ziQIEoktPf9dnyYpN0IumGMg-g5ww7foDglpwbIP9c6SxxDIOIMh5fGlT7tG79-i_QJ3zsDuYo0v8aNFd7QcP5tA8Kj9Tthp2pHTacu0WDSq39p6XEvDaKiLRhhVOfyd_jTTC2xzmkXRzt2KOy1ObRvhOiItQCoISn66QO4dm8febSagA2_GtDd1VYxwT0zW7usK4CwKfoSej_UMp-BZZ8Q1fDqMWfG9qWjeinfty7ePQwV2Y_kiNCjyTvKlbPnTINL_VXemb0pIaAITfROlzWtXGGnP3soFczgWe4WXC_Q7wx3uCkyN5BIKLajxCF3EAfPzDi7YbYnQXEk-imGoqWpYXw0SXMkYo2wkd9Qul4uXH_mGh50l`
	unknownPublicKey = `{
		"crv": "P-384",
		"key_ops": [
		  "verify"
		],
		"kty": "EC",
		"x": "Zd7Unk3ijm3MKXt9vbHR02Y1zX-cpXu6H1_wXRtMl3e39TqeOJ3XnJCxSfE5vjMX",
		"y": "Cv8AgXWpMkMFWvLGhJ_Gsb8LmapAtEurnBsFI4CAG42yUGDfkZ_xjFXPbYssJl7U",
		"alg": "ES384",
		"use": "sig",
		"kid": "32b3da5277b142c7e24fdf0ef09e0919"
	  }`
	publicKey = `{
		"alg": "RS384",
		"d": "BN_n915sHKB_-wleE2n19Pb2v3-CbumqaoD3X6VbVA809YWdEvBLAODqQC9pqC1GXKjg-BttZxSI-8zR-OHIbnHqVWHWBTH4ci4_0ABl2RUR99bY2sOyuknSS8y1xvxGv4m0mHo_diYF5Q0vy5nDjqpMoTMRVX5gLVRbKHDOZZ_phBc26hHoic62x5mmbHqcKBVvFlPFMjbZIaZLPz-uQzEwcQbEfEbrPWwSzLT9sdrvuO1tOQ-Xmi08jJeHm1JIXFRGv_Jo4IY0Vj45laERUi7BbgJZz9liR24o3KtNOUZSBR0BLMDaYeVIVVhIfippv4RChFk2-v2qwWbxS_sjWTJV30Ogb_0v-78Zjc-KR3JGuFNcKaMUrG6pxhMrhlKp65rKmWRI51rm_qTvzPetM7zVAJ6svycEr8vrjepmOUVOZqEdspSnQzwEiSj-TRq7OaLNzTCKblK8IPrZP5V2q8sUa-_vfeeRlqIG3e_WVO7SOAfs-Gbz5NtZFDTd_yEB",
		"dp": "t952F1QA-bLy0eNwOdbU3rQpS4Qwk6QzAitFr8egskNAIC44J8sMbdWR1zdRB4ja11XBqFklRZmyAhVgOzY8ySExbTZOYdEnxQBivUMTadZD89ML34tPXKU128hJxPSt8r01WMbaTg9-YMwhzFhOm-izYM0QoIxtbN4um9ZfZIYBBjLB8JJAVY4B-5Vr6JP7rE_e-fezezh0hOA6IuPu3Z7z4DRhxhQh4g8NvejwBOzMe-FDJkTIJIcYvIF5LrJh",
		"dq": "gWm9G7nv2ZR4wuPo-OQOsKUQVEooPkMqi-qgW3j3zWbNrG7kJpkFty1ZKcq6704IPR_ie3lvzYZp8F9ePH-elleWme5EEAGD8Vh6eT60kvCqDxVldDAkDTMXKw68kTlucjnKLf4KGOrDPvQvqzFlGJevJuxJDo5VPegkYkW6tnq1lFOErUOWm7KBWXhAc5kNywu3j7z3BWjE4EPlP7aNgsxy28ZEXIcH3i12_FHdLO_6QnRwLGdAdHIZRQvmQ59B",
		"e": "AQAB",
		"key_ops": [
		  "sign"
		],
		"kty": "RSA",
		"n": "zOtIoACSUTgYOgXEBzss-w-NdXNtRH2sSCZnjSypCcaxyuQEsEFYXzommvT43yWxK2PxDgXUu4PejoALchWQDDVUx7RdxI4lIsMT6QuiUPDmsnasBqi45VMFW0zxqfbCuFDP6sqfWMB1a7vUHyCKAUpFNqGrCFOxIcAJ-7mHNrtiXGedr6xamJcq6OrSNQtvSFkxYyh7J0DBMKzk1KMkbuoZpt6V7dbeZLX6i4rSUzFbcP_cSGKiMwrK7sVpEY1WdsoVQSX28FkwPF1W1gcArZdVog7kULQUta2GgfyBP8o9JDzb7c3FisuBc7-mxdDRpvkJsPGz0nEUSUPNs6cJzFla1MFG9VsyDa9HKuXTzLtR8fy-uakuNqu-9T2EkORGuC4yrJE7xGzB-c2UfaBuSynQ9rcfiwIvFdS78vvz6SlcBcLVvCgTrsywEMz-zIKw9sPgVgKQf9rQNl9mtGgUvgAvOt6ljCtwDsNLAJ4d_s-1lczljyDWjRuB4ZXGcd6Z",
		"p": "-nDpMgCY9kuIQE389qb4jzuRauK3cvgN_qvfMxVkDmhWKtpapnvs-oqLH7zLBfKa5AR5d44r9jRvwAX4o7wcWBiodYRp8SSMqd962RBTqfzLw5i9FQsf5r3OKb7He1zpNDinIyikv4EOSB3O-BKzg5UTcDjJp5RNg_z_GHq6h633bKoLCq89cJf-LaAO-MjsfG7PotIfub-DsxHkkBxbWaYn4LeLr6vEGmUAuozVJe2_ZEokF3PJT_6fl0Mh0V55",
		"q": "0XezqH1pUWYF1odAR7RHTCjs-kmZC9g_ubnYw0ycsA-__FYkYHBdxv1vaRe9TB3w0g-m8vzYx-7ZkFogHiHiEZ2gigOak0zRkpjnQ7JYZk6B0B9JkQlllie1OwBdRR47evmd5eBpwcqjgxAWp_V7KcWNgKKQtAMCHP3Gu6QtcqMFXjm-bW6uhesq4R4_H5WWcHmcmyie8EfjoYVNMiL1cyvZ3SHGolv1KHxCEbvaNXiD7dVaIH6IQvwNjNX52fkh",
		"qi": "mGjbY9ouQnDOaoO1bVMkPz56t6ONyJ6OGiWHHHly0beq49oDFhhtLPb2HnmpVvLsp27JoNSxVaS-j_g84BGHC7gOb9hhGRccA1E9662EvY7QcG1_eYoL6dh2mTFWe29oGIWj1ib1Iprje2_IdJcA3725GR4cM_IgU7R-23b2MNJ2IDvIwrTYQ_eTXch9nEwJUI6_eG2OCKneN_2rthbKHDsaKbhkofj1SvhM9jLRByMXxmnygPx3u1l1MEpQRg8M",
		"use": "sig",
		"kid": "e4a57cc9dfb402a3e53c42a6422f73af"
	  }`
)

var (
	mockAuthSessionCookie = &http.Cookie{Value: jwtTokenValid, Name: SessionCookieName}
	mockAuthRefreshCookie = &http.Cookie{Value: jwtTokenValid, Name: RefreshCookieName}

	mockAuthSessionBody = fmt.Sprintf(`{"jwts": ["%s"]}`, jwtTokenValid)
)

func readBodyMap(r *http.Request) (m map[string]interface{}, err error) {
	m = map[string]interface{}{}
	err = readBody(r, &m)
	return m, err
}

func readBody(r *http.Request, m interface{}) (err error) {
	reader, err := r.GetBody()
	if err != nil {
		return err
	}
	res, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	err = json.Unmarshal(res, &m)
	return
}

func DoOk(checks func(*http.Request)) mocks.Do {
	return func(r *http.Request) (*http.Response, error) {
		if checks != nil {
			checks(r)
		}
		res := &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(mockAuthSessionBody))}
		return res, nil
	}
}

func DoOkWithBody(checks func(*http.Request), body interface{}) mocks.Do {
	return func(r *http.Request) (*http.Response, error) {
		if checks != nil {
			checks(r)
		}

		b, err := utils.Marshal(body)
		if err != nil {
			return nil, err
		}
		res := &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(b))}
		return res, nil
	}
}

func DoRedirect(url string, checks func(*http.Request)) mocks.Do {
	return func(r *http.Request) (*http.Response, error) {
		if checks != nil {
			checks(r)
		}
		res := &http.Response{StatusCode: http.StatusTemporaryRedirect, Header: http.Header{RedirectLocationCookieName: []string{url}}}
		return res, nil
	}
}

func newTestAuth(clientParams *api.ClientParams, callback mocks.Do) (*authenticationService, error) {
	return newTestAuthConf(nil, clientParams, callback)
}

func newTestAuthConf(authParams *AuthParams, clientParams *api.ClientParams, callback mocks.Do) (*authenticationService, error) {
	if clientParams == nil {
		clientParams = &api.ClientParams{}
	}
	if authParams == nil {
		authParams = &AuthParams{ProjectID: "a", PublicKey: publicKey}
	}
	clientParams.DefaultClient = mocks.NewTestClient(callback)
	return NewAuth(*authParams, api.NewClient(*clientParams))
}

func TestVerifyDeliveryMethodEmptyIdentifier(t *testing.T) {
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	err = a.verifyDeliveryMethod(MethodEmail, "")
	assert.EqualValues(t, errors.BadRequestErrorCode, err.(*errors.WebError).Code)
}

func TestAuthDefaultURL(t *testing.T) {
	url := "http://test.com"
	a, err := newTestAuthConf(nil, &api.ClientParams{BaseURL: url}, DoOk(func(r *http.Request) {
		assert.Contains(t, r.URL.String(), url)
	}))
	require.NoError(t, err)
	_, err = a.VerifyCodeWithOptions(MethodWhatsApp, "4444", "444")
	require.NoError(t, err)
}

func TestEmptyPublicKey(t *testing.T) {
	a, err := newTestAuthConf(&AuthParams{ProjectID: "a"}, nil, mocks.Do(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader("[]"))}, nil
	}))
	require.NoError(t, err)
	ok, _, err := a.validateSession(jwtTokenExpired, "")
	require.False(t, ok)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no public key was found")
}

func TestErrorFetchPublicKey(t *testing.T) {
	a, err := newTestAuthConf(&AuthParams{ProjectID: "a"}, nil, mocks.Do(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusInternalServerError, Body: io.NopCloser(strings.NewReader("what"))}, nil
	}))
	require.NoError(t, err)
	ok, _, err := a.validateSession(jwtTokenExpired, "")
	require.False(t, ok)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no public key was found")
}

func TestValidateSession(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	ok, _, err := a.validateSession(jwtTokenValid, "")
	require.NoError(t, err)
	require.True(t, ok)
	ok, _, err = a.validateSession(jwtTokenValid, "")
	require.NoError(t, err)
	require.True(t, ok)
}

func TestValidateSessionFetchKeyCalledOnce(t *testing.T) {
	count := 0
	a, err := newTestAuthConf(&AuthParams{ProjectID: "a"}, nil, mocks.Do(func(r *http.Request) (*http.Response, error) {
		count++
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(fmt.Sprintf("[%s]", publicKey)))}, nil
	}))
	require.NoError(t, err)
	ok, _, err := a.validateSession(jwtTokenValid, "")
	require.NoError(t, err)
	require.True(t, ok)
	require.EqualValues(t, 1, count)
	ok, _, err = a.validateSession(jwtTokenValid, "")
	require.NoError(t, err)
	require.True(t, ok)
	require.EqualValues(t, 1, count)
}

func TestValidateSessionFetchKeyMalformed(t *testing.T) {
	a, err := newTestAuthConf(&AuthParams{ProjectID: "a"}, nil, mocks.Do(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(fmt.Sprintf("[%s]", unknownPublicKey)))}, nil
	}))
	require.NoError(t, err)
	ok, _, err := a.validateSession(jwtTokenValid, jwtTokenValid)
	require.Error(t, err)
	assert.EqualValues(t, errors.BadRequestErrorCode, err.(*errors.WebError).Code)
	require.False(t, ok)
}

func TestValidateSessionFailWithInvalidKey(t *testing.T) {
	count := 0
	a, err := newTestAuthConf(&AuthParams{PublicKey: unknownPublicKey}, nil, mocks.Do(func(r *http.Request) (*http.Response, error) {
		count++
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(fmt.Sprintf("[%s]", publicKey)))}, nil
	}))
	require.NoError(t, err)
	ok, _, err := a.validateSession(jwtTokenValid, "")
	require.Error(t, err)
	assert.EqualValues(t, errors.BadRequestErrorCode, err.(*errors.WebError).Code)
	require.False(t, ok)
	require.Zero(t, count)
}

func TestValidateSessionRequest(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: jwtTokenValid})
	request.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtTokenValid})
	ok, info, err := a.ValidateSessionWithOptions(request)
	require.NoError(t, err)
	require.True(t, ok)
	require.EqualValues(t, jwtTokenValid, info.SessionToken.JWT)
}

func TestValidateSessionRequestMissingCookie(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: jwtTokenValid})
	ok, cookies, err := a.ValidateSessionWithOptions(request)
	require.NoError(t, err)
	require.False(t, ok)
	require.Empty(t, cookies)

	request = &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtTokenValid})
	ok, cookies, err = a.ValidateSessionWithOptions(request)
	require.NoError(t, err)
	require.False(t, ok)
	require.Empty(t, cookies)
}

func TestValidateSessionRequestRefreshSession(t *testing.T) {
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(mockAuthSessionBody))}, nil
	})
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtTokenValid})
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: jwtTokenExpired})

	b := httptest.NewRecorder()
	ok, userToken, err := a.ValidateSession(request, b)
	require.NoError(t, err)
	require.True(t, ok)
	assert.EqualValues(t, mockAuthSessionCookie.Value, userToken.SessionToken.JWT)
	require.Len(t, b.Result().Cookies(), 1)
	sessionCookie := b.Result().Cookies()[0]
	require.NoError(t, err)
	assert.EqualValues(t, mockAuthSessionCookie.Value, sessionCookie.Value)
}

func TestValidateSessionRequestMissingSessionToken(t *testing.T) {
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Set-Cookie": []string{mockAuthSessionCookie.String()}}}, nil
	})
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtTokenValid})

	b := httptest.NewRecorder()
	ok, info, err := a.ValidateSession(request, b)
	require.NoError(t, err)
	require.False(t, ok)
	require.Empty(t, info)
}

func TestValidateSessionRequestFailRefreshSession(t *testing.T) {
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusInternalServerError}, nil
	})
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtTokenValid})
	request.AddCookie(&http.Cookie{Name: SessionCookieName, Value: jwtTokenExpired})
	ok, cookies, err := a.ValidateSessionWithOptions(request)
	require.Error(t, err)
	assert.ErrorIs(t, err, errors.FailedToRefreshTokenError)
	require.False(t, ok)
	require.Empty(t, cookies)
}

func TestValidateSessionRequestNoCookie(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	ok, cookies, err := a.ValidateSessionWithOptions(request)
	require.NoError(t, err)
	require.False(t, ok)
	require.Empty(t, cookies)
}

func TestValidateSessionExpired(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	ok, _, err := a.validateSession(jwtTokenExpired, jwtTokenExpired)
	require.Error(t, err)
	require.False(t, ok)
	assert.EqualValues(t, errors.BadRequestErrorCode, err.(*errors.WebError).Code)
}

func TestValidateSessionNoProvider(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	ok, _, err := a.ValidateSessionWithOptions(nil)
	require.Error(t, err)
	require.ErrorIs(t, err, errors.MissingProviderError)
	require.False(t, ok)
}

func TestValidateSessionNotYet(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	ok, _, err := a.validateSession(jwtTokenNotYet, jwtTokenNotYet)
	require.Error(t, err)
	require.False(t, ok)
	assert.EqualValues(t, errors.BadRequestErrorCode, err.(*errors.WebError).Code)
}

func TestLogout(t *testing.T) {
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK}, nil
	})
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtTokenValid})

	w := httptest.NewRecorder()
	err = a.Logout(request, w)
	require.NoError(t, err)
	require.Len(t, w.Result().Cookies(), 2)
	c1 := w.Result().Cookies()[0]
	assert.Empty(t, c1.Value)
	assert.EqualValues(t, SessionCookieName, c1.Name)
	c2 := w.Result().Cookies()[1]
	assert.Empty(t, c2.Value)
	assert.EqualValues(t, RefreshCookieName, c2.Name)
}

func TestLogoutFailure(t *testing.T) {
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadGateway}, nil
	})
	require.NoError(t, err)
	request := &http.Request{Header: http.Header{}}
	request.AddCookie(&http.Cookie{Name: RefreshCookieName, Value: jwtTokenValid})

	err = a.Logout(request, nil)
	require.Error(t, err)
}

func TestLogoutEmptyRequest(t *testing.T) {
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadGateway}, nil
	})
	require.NoError(t, err)

	err = a.LogoutWithOptions(nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, errors.MissingProviderError)
}

func TestLogoutMissingToken(t *testing.T) {
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadGateway}, nil
	})
	require.NoError(t, err)

	request := &http.Request{Header: http.Header{}}
	err = a.LogoutWithOptions(request)
	require.Error(t, err)
	assert.ErrorIs(t, err, errors.RefreshTokenError)
}

func TestAuthenticationMiddlewareFailure(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	handlerToTest := AuthenticationMiddleware(a, func(w http.ResponseWriter, r *http.Request, err error) {
		assert.NoError(t, err)
		w.WriteHeader(http.StatusBadGateway)
	})(nil)

	req := httptest.NewRequest("GET", "http://testing", nil)

	res := httptest.NewRecorder()
	handlerToTest.ServeHTTP(res, req)
	assert.EqualValues(t, http.StatusBadGateway, res.Result().StatusCode)
}

func TestAuthenticationMiddlewareFailureDefault(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	handlerToTest := AuthenticationMiddleware(a, nil)(nil)

	req := httptest.NewRequest("GET", "http://testing", nil)

	res := httptest.NewRecorder()
	handlerToTest.ServeHTTP(res, req)
	assert.EqualValues(t, http.StatusUnauthorized, res.Result().StatusCode)
}

func TestAuthenticationMiddlewareSuccess(t *testing.T) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(t, err)
	handlerToTest := AuthenticationMiddleware(a, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))

	req := httptest.NewRequest("GET", "http://testing", nil)
	req.AddCookie(mockAuthSessionCookie)
	req.AddCookie(mockAuthRefreshCookie)

	res := httptest.NewRecorder()
	handlerToTest.ServeHTTP(res, req)
	assert.EqualValues(t, http.StatusTeapot, res.Result().StatusCode)
}

func TestExtractTokensEmpty(t *testing.T) {
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	tokens, err := a.extractTokens(`{ "jwts": [] }`)
	require.NoError(t, err)
	require.Len(t, tokens, 0)
}

func TestExtractTokensInvalid(t *testing.T) {
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	tokens, err := a.extractTokens(`{ "jwts": ["aaaaaa"] }`)
	require.Error(t, err)
	require.Empty(t, tokens)
}

func BenchmarkValidateSession(b *testing.B) {
	a, err := newTestAuth(nil, DoOk(nil))
	require.NoError(b, err)

	for n := 0; n < b.N; n++ {
		_, _, _ = a.validateSession(jwtTokenValid, "")
	}
}
