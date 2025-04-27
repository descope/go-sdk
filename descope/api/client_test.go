package api

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/tests/mocks"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseAuthorizationHeader(r *http.Request) (projectID, jwt, accessKey string) {
	reqToken := r.Header.Get(AuthorizationHeaderName)
	if splitToken := strings.Split(reqToken, BearerAuthorizationPrefix); len(splitToken) == 2 {
		bearer := splitToken[1]
		bearers := strings.Split(bearer, ":")
		projectID = bearers[0]
		if len(bearers) == 2 {
			if strings.Contains(bearers[1], ".") {
				jwt = bearers[1]
			} else {
				accessKey = bearers[1]
			}
		}
		if len(bearers) > 2 {
			jwt = bearers[1]
			accessKey = bearers[2]
		}
	}
	return
}

func TestClient(t *testing.T) {
	c := NewClient(ClientParams{})
	assert.NotNil(t, c.httpClient)
	assert.NotNil(t, c.headers)
}

func TestRequestWithDescopeHeaders(t *testing.T) {
	projectID := "test"
	c := NewClient(ClientParams{ProjectID: projectID, DefaultClient: mocks.NewTestClient(func(r *http.Request) (*http.Response, error) {
		assert.Nil(t, r.Body)
		assert.EqualValues(t, "golang", r.Header.Get("X-Descope-Sdk-Name"))
		assert.True(t, strings.HasPrefix(r.Header.Get("X-Descope-Sdk-Go-Version"), "go"))
		assert.Equal(t, projectID, r.Header.Get("x-descope-project-id"))
		// cannot test sdk-version since build info does not work in tests
		return &http.Response{StatusCode: http.StatusOK}, nil
	})})

	_, err := c.DoPostRequest(context.Background(), "path", nil, nil, "")
	require.NoError(t, err)
}

func TestGetRequest(t *testing.T) {
	projectID := "test"
	expectedResponse := "hey"
	c := NewClient(ClientParams{ProjectID: projectID, DefaultClient: mocks.NewTestClient(func(r *http.Request) (*http.Response, error) {
		assert.Nil(t, r.Body)
		assert.EqualValues(t, "/path", r.URL.Path)
		assert.EqualValues(t, "test=1", r.URL.RawQuery)
		actualProject, _, _ := parseAuthorizationHeader(r)
		assert.EqualValues(t, projectID, actualProject)
		return &http.Response{Body: io.NopCloser(strings.NewReader(expectedResponse)), StatusCode: http.StatusOK}, nil
	})})
	res, err := c.DoGetRequest(context.Background(), "path", &HTTPRequest{QueryParams: map[string]string{"test": "1"}}, "")
	require.NoError(t, err)
	assert.EqualValues(t, expectedResponse, res.BodyStr)
}

func TestPutRequest(t *testing.T) {
	type dummy struct {
		Test string
	}

	expectedOutput := &dummy{Test: "test"}
	expectedHeaders := map[string]string{"header1": "value1"}
	projectID := "test"
	accesskey := "accessKey"
	outputBytes, err := utils.Marshal(expectedOutput)
	require.NoError(t, err)
	c := NewClient(ClientParams{ProjectID: projectID, AuthManagementKey: accesskey, DefaultClient: mocks.NewTestClient(func(r *http.Request) (*http.Response, error) {
		assert.NotNil(t, r.Body)
		actualProject, _, actualAccessKey := parseAuthorizationHeader(r)
		assert.EqualValues(t, http.MethodPut, r.Method)
		assert.EqualValues(t, projectID, actualProject)
		assert.EqualValues(t, accesskey, actualAccessKey)
		assert.EqualValues(t, expectedHeaders["header1"], r.Header.Get("header1"))
		return &http.Response{Body: io.NopCloser(bytes.NewReader(outputBytes)), StatusCode: http.StatusOK}, nil
	})})

	actualOutput := &dummy{}
	res, err := c.DoPutRequest(context.Background(), "path", strings.NewReader("test"), &HTTPRequest{ResBodyObj: actualOutput, Headers: expectedHeaders}, "")
	require.NoError(t, err)
	assert.EqualValues(t, string(outputBytes), res.BodyStr)
	assert.EqualValues(t, expectedOutput, actualOutput)
}

func TestPostRequest(t *testing.T) {
	type dummy struct {
		Test string
	}

	expectedOutput := &dummy{Test: "test"}
	expectedHeaders := map[string]string{"header1": "value1"}
	projectID := "test"
	accesskey := "accessKey"
	jwtStr := "eyJhbGciOiJFUzM4NCIsImtpZCI6IjI4eVRTeDZRMGNpSzU4QWRDU3ZLZkNKcEJJTiIsInR5cCI6IkpXVCJ9.eyJleHAiOi01Njk3NzcxNjg2LCJpc3MiOiIyOHlUU3g2UTBjaUs1OEFkQ1N2S2ZDSnBCSU4iLCJzdWIiOiIyOHlldzQ3NTVLdElSNnhmMk1rV2lITDRYSnEifQ.fm5h2AlyOzUCVMIezSQf8wddE6xhcfqnSAzpG4SoOy6HK387T8hxcpbmCc7qbFOQfaPDdhVhqS7JkX7wessaTznbiK_xiDac6CkENgzrl_V8eMXEHt1HcyCW1s6IQd5D"
	outputBytes, err := utils.Marshal(expectedOutput)
	require.NoError(t, err)
	c := NewClient(ClientParams{ProjectID: projectID, AuthManagementKey: accesskey, DefaultClient: mocks.NewTestClient(func(r *http.Request) (*http.Response, error) {
		assert.NotNil(t, r.Body)
		actualProject, actualJwt, actualAccessKey := parseAuthorizationHeader(r)
		assert.EqualValues(t, http.MethodPost, r.Method)
		assert.EqualValues(t, projectID, actualProject)
		assert.EqualValues(t, accesskey, actualAccessKey)
		assert.EqualValues(t, jwtStr, actualJwt)
		assert.EqualValues(t, expectedHeaders["header1"], r.Header.Get("header1"))
		return &http.Response{Body: io.NopCloser(bytes.NewReader(outputBytes)), StatusCode: http.StatusOK}, nil
	})})

	actualOutput := &dummy{}
	res, err := c.DoPostRequest(context.Background(), "path", strings.NewReader("test"), &HTTPRequest{ResBodyObj: actualOutput, Headers: expectedHeaders}, jwtStr)
	require.NoError(t, err)
	assert.EqualValues(t, string(outputBytes), res.BodyStr)
	assert.EqualValues(t, expectedOutput, actualOutput)
}

func TestPostCustomHeaders(t *testing.T) {
	projectID := "test"
	headers := map[string]string{"test": "a", "test2": "b"}
	c := NewClient(ClientParams{ProjectID: projectID, CustomDefaultHeaders: headers, DefaultClient: mocks.NewTestClient(func(r *http.Request) (*http.Response, error) {
		assert.Nil(t, r.Body)
		for k, v := range headers {
			assert.EqualValues(t, v, r.Header.Get(k))
		}
		return &http.Response{StatusCode: http.StatusOK}, nil
	})})

	_, err := c.DoPostRequest(context.Background(), "path", nil, nil, "")
	require.NoError(t, err)
}

func TestPostCustomCookies(t *testing.T) {
	projectID := "test"
	expectedCookie := &http.Cookie{Name: "test", Value: "value"}
	c := NewClient(ClientParams{ProjectID: projectID, DefaultClient: mocks.NewTestClient(func(r *http.Request) (*http.Response, error) {
		assert.Nil(t, r.Body)
		assert.NotEmpty(t, r.Header.Get("Cookie"))
		assert.Contains(t, r.Header.Get("Cookie"), expectedCookie.Value)
		return &http.Response{StatusCode: http.StatusOK}, nil
	})})

	_, err := c.DoPostRequest(context.Background(), "path", nil, &HTTPRequest{Cookies: []*http.Cookie{expectedCookie}}, "")
	require.NoError(t, err)
}

func TestPostCustomURL(t *testing.T) {
	projectID := "test"
	body := "aaaa"
	c := NewClient(ClientParams{ProjectID: projectID, DefaultClient: mocks.NewTestClient(func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, "overriden.com", r.URL.Hostname())
		assert.EqualValues(t, "/path", r.URL.Path)
		assert.EqualValues(t, "test=1", r.URL.RawQuery)
		b, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		assert.EqualValues(t, body, string(b))
		return &http.Response{StatusCode: http.StatusOK}, nil
	})})

	req, err := http.NewRequest(http.MethodPost, "hello.com/path?test=1", bytes.NewBufferString(body))
	require.NoError(t, err)
	res, err := c.DoPostRequest(context.Background(), "path", nil, &HTTPRequest{Request: req, BaseURL: "https://overriden.com"}, "")
	require.NoError(t, err)
	assert.EqualValues(t, http.StatusOK, res.Res.StatusCode)
}

func TestPostCustomBaseURL(t *testing.T) {
	projectID := "test"
	url := "http://test.com"
	c := NewClient(ClientParams{ProjectID: projectID, DefaultClient: mocks.NewTestClient(func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, fmt.Sprintf("%s/path", url), r.URL.String())
		return &http.Response{StatusCode: http.StatusOK}, nil
	})})

	res, err := c.DoPostRequest(context.Background(), "path", nil, &HTTPRequest{BaseURL: url}, "")
	require.NoError(t, err)
	assert.EqualValues(t, http.StatusOK, res.Res.StatusCode)
}

func TestPostUnauthorized(t *testing.T) {
	projectID := "test"
	c := NewClient(ClientParams{ProjectID: projectID, DefaultClient: mocks.NewTestClient(func(r *http.Request) (*http.Response, error) {
		assert.Nil(t, r.Body)
		return &http.Response{StatusCode: http.StatusUnauthorized}, nil
	})})

	_, err := c.DoPostRequest(context.Background(), "path", nil, nil, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidResponse)
	assert.True(t, descope.IsUnauthorizedError(err))
}

func TestPostRateLimitExceeded(t *testing.T) {
	c := NewClient(ClientParams{ProjectID: "test", DefaultClient: mocks.NewTestClient(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusTooManyRequests, Body: io.NopCloser(strings.NewReader(`{"errorCode":"E130429"}`))}, nil
	})})

	_, err := c.DoPostRequest(context.Background(), "path", nil, nil, "")
	require.ErrorIs(t, err, descope.ErrRateLimitExceeded)
	require.Nil(t, err.(*descope.Error).Info[descope.ErrorInfoKeys.RateLimitExceededRetryAfter])

	c = NewClient(ClientParams{ProjectID: "test", DefaultClient: mocks.NewTestClient(func(_ *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{"Retry-After": []string{"10"}}, Body: io.NopCloser(strings.NewReader(`{"errorCode":"E130429"}`))}, nil
	})})

	_, err = c.DoPostRequest(context.Background(), "path", nil, nil, "")
	require.ErrorIs(t, err, descope.ErrRateLimitExceeded)
	require.Equal(t, 10, err.(*descope.Error).Info[descope.ErrorInfoKeys.RateLimitExceededRetryAfter])
}

func TestPostDescopeError(t *testing.T) {
	projectID := "test"
	code := "this is an error"
	c := NewClient(ClientParams{ProjectID: projectID, DefaultClient: mocks.NewTestClient(func(r *http.Request) (*http.Response, error) {
		assert.Nil(t, r.Body)
		return &http.Response{StatusCode: http.StatusBadRequest, Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{ "errorCode": "%s" }`, code)))}, nil
	})})

	_, err := c.DoPostRequest(context.Background(), "path", nil, nil, "")
	require.Error(t, err)
	assert.EqualValues(t, code, err.(*descope.Error).Code)
}

func TestPostError(t *testing.T) {
	projectID := "test"
	expectedErr := "error here"
	c := NewClient(ClientParams{ProjectID: projectID, DefaultClient: mocks.NewTestClient(func(r *http.Request) (*http.Response, error) {
		assert.Nil(t, r.Body)
		return nil, fmt.Errorf("%s", expectedErr)
	})})

	_, err := c.DoPostRequest(context.Background(), "path", nil, nil, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), expectedErr)
}

func TestPostUnknownError(t *testing.T) {
	projectID := "test"
	code := "this is an error"
	c := NewClient(ClientParams{ProjectID: projectID, DefaultClient: mocks.NewTestClient(func(r *http.Request) (*http.Response, error) {
		assert.Nil(t, r.Body)
		return &http.Response{StatusCode: http.StatusBadRequest, Body: io.NopCloser(strings.NewReader(code))}, nil
	})})

	_, err := c.DoPostRequest(context.Background(), "path", nil, nil, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidResponse)
}

func TestPostNotFoundError(t *testing.T) {
	projectID := "test"
	c := NewClient(ClientParams{ProjectID: projectID, DefaultClient: mocks.NewTestClient(func(r *http.Request) (*http.Response, error) {
		assert.Nil(t, r.Body)
		return &http.Response{StatusCode: http.StatusNotFound, Request: r}, nil
	})})

	_, err := c.DoPostRequest(context.Background(), "path", nil, nil, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrInvalidResponse)
	assert.True(t, descope.IsNotFoundError(err))
}

func TestDoRequestDefault(t *testing.T) {
	projectID := "test"
	c := NewClient(ClientParams{ProjectID: projectID, DefaultClient: mocks.NewTestClient(func(r *http.Request) (*http.Response, error) {
		assert.Nil(t, r.Body)
		assert.True(t, strings.HasPrefix(r.URL.String(), defaultURL), "BaseURL should be defaultURL")
		assertValidUUIDHeader(t, r)
		return &http.Response{StatusCode: http.StatusOK}, nil
	})})

	_, err := c.DoRequest(context.Background(), http.MethodGet, "path", nil, nil, "")
	require.NoError(t, err)
}

func assertValidUUIDHeader(t *testing.T, r *http.Request) {
	_, err := uuid.Parse(r.Header.Get("x-descope-sdk-uuid"))
	require.NoError(t, err, "uuid header should be a valid uuid")
}

func TestRoutesSignInOTP(t *testing.T) {
	r := Routes.SignInOTP()
	assert.EqualValues(t, "/v1/auth/otp/signin", r)
}

func TestSkipVerifyValue(t *testing.T) {
	require.True(t, CertificateVerifyNever.SkipVerifyValue("foo"))
	require.False(t, CertificateVerifyAlways.SkipVerifyValue("foo"))
	require.False(t, CertificateVerifyAutomatic.SkipVerifyValue("https://.com"))
	require.False(t, CertificateVerifyAutomatic.SkipVerifyValue("https://example.com"))
	require.False(t, CertificateVerifyAutomatic.SkipVerifyValue("http://example.com"))
	require.False(t, CertificateVerifyAutomatic.SkipVerifyValue(defaultURL))
	require.False(t, CertificateVerifyAutomatic.SkipVerifyValue(defaultURL+"/v1/auth"))
	require.False(t, CertificateVerifyAutomatic.SkipVerifyValue(defaultAPIPrefix+"."+"use1"+defaultDomainName+"/v1/auth"))
	require.False(t, CertificateVerifyAutomatic.SkipVerifyValue(" http://example.com"))
	require.True(t, CertificateVerifyAutomatic.SkipVerifyValue("https://localhost"))
	require.True(t, CertificateVerifyAutomatic.SkipVerifyValue("https://apache/foo"))
	require.True(t, CertificateVerifyAutomatic.SkipVerifyValue("https://127.0.0.1"))
	require.True(t, CertificateVerifyAutomatic.SkipVerifyValue("https://example.com:8443"))
}

func TestBaseURLForProjectID(t *testing.T) {
	useURL := fmt.Sprintf("%s.use1.%s", defaultAPIPrefix, defaultDomainName)
	assert.EqualValues(t, defaultURL, baseURLForProjectID("P2aAc4T2V93bddihGEx2Ryhc8e5Z"))
	assert.EqualValues(t, defaultURL, baseURLForProjectID(""))
	assert.EqualValues(t, defaultURL, baseURLForProjectID("Puse"))
	assert.EqualValues(t, defaultURL, baseURLForProjectID("Puse1ar"))
	assert.EqualValues(t, useURL, baseURLForProjectID("Puse12aAc4T2V93bddihGEx2Ryhc8e5Zfoobar"))
	assert.EqualValues(t, useURL, baseURLForProjectID("Puse12aAc4T2V93bddihGEx2Ryhc8e5Z"))
}
