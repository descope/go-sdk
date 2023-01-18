package api

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/tests/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getProjectAndJwt(r *http.Request) (string, string) {
	var projectID, jwt string
	reqToken := r.Header.Get(AuthorizationHeaderName)
	if splitToken := strings.Split(reqToken, BearerAuthorizationPrefix); len(splitToken) == 2 {
		bearer := splitToken[1]
		bearers := strings.Split(bearer, ":")
		projectID = bearers[0]
		if len(bearers) > 1 {
			jwt = bearers[1]
		}
	}
	return projectID, jwt
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
		// cannot test sdk-version since build info does not work in tests
		return &http.Response{StatusCode: http.StatusOK}, nil
	})})

	_, err := c.DoPostRequest("path", nil, nil, "")
	require.NoError(t, err)
}

func TestGetRequest(t *testing.T) {
	projectID := "test"
	expectedResponse := "hey"
	c := NewClient(ClientParams{ProjectID: projectID, DefaultClient: mocks.NewTestClient(func(r *http.Request) (*http.Response, error) {
		assert.Nil(t, r.Body)
		assert.EqualValues(t, "/path", r.URL.Path)
		assert.EqualValues(t, "test=1", r.URL.RawQuery)
		actualProject, _ := getProjectAndJwt(r)
		assert.EqualValues(t, projectID, actualProject)
		return &http.Response{Body: io.NopCloser(strings.NewReader(expectedResponse)), StatusCode: http.StatusOK}, nil
	})})
	res, err := c.DoGetRequest("path", &HTTPRequest{QueryParams: map[string]string{"test": "1"}}, "")
	require.NoError(t, err)
	assert.EqualValues(t, expectedResponse, res.BodyStr)
}

func TestPostRequest(t *testing.T) {
	type dummy struct {
		Test string
	}

	expectedOutput := &dummy{Test: "test"}
	expectedHeaders := map[string]string{"header1": "value1"}
	projectID := "test"
	outputBytes, err := utils.Marshal(expectedOutput)
	require.NoError(t, err)
	c := NewClient(ClientParams{ProjectID: projectID, DefaultClient: mocks.NewTestClient(func(r *http.Request) (*http.Response, error) {
		assert.NotNil(t, r.Body)
		actualProject, _ := getProjectAndJwt(r)
		assert.EqualValues(t, projectID, actualProject)
		assert.EqualValues(t, expectedHeaders["header1"], r.Header.Get("header1"))
		return &http.Response{Body: io.NopCloser(bytes.NewReader(outputBytes)), StatusCode: http.StatusOK}, nil
	})})

	actualOutput := &dummy{}
	res, err := c.DoPostRequest("path", strings.NewReader("test"), &HTTPRequest{ResBodyObj: actualOutput, Headers: expectedHeaders}, "")
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

	_, err := c.DoPostRequest("path", nil, nil, "")
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

	_, err := c.DoPostRequest("path", nil, &HTTPRequest{Cookies: []*http.Cookie{expectedCookie}}, "")
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
	res, err := c.DoPostRequest("path", nil, &HTTPRequest{Request: req, BaseURL: "https://overriden.com"}, "")
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

	res, err := c.DoPostRequest("path", nil, &HTTPRequest{BaseURL: url}, "")
	require.NoError(t, err)
	assert.EqualValues(t, http.StatusOK, res.Res.StatusCode)
}

func TestPostUnauthorized(t *testing.T) {
	projectID := "test"
	c := NewClient(ClientParams{ProjectID: projectID, DefaultClient: mocks.NewTestClient(func(r *http.Request) (*http.Response, error) {
		assert.Nil(t, r.Body)
		return &http.Response{StatusCode: http.StatusUnauthorized}, nil
	})})

	_, err := c.DoPostRequest("path", nil, nil, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrUnexpectedResponse)
}

func TestPostRateLimitExceeded(t *testing.T) {
	c := NewClient(ClientParams{ProjectID: "test", DefaultClient: mocks.NewTestClient(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusTooManyRequests}, nil
	})})

	_, err := c.DoPostRequest("path", nil, nil, "")
	require.ErrorIs(t, err, descope.ErrRateLimitExceeded)
	require.ErrorContains(t, err, "Try again")
	require.Empty(t, err.(*descope.Error).Info)

	c = NewClient(ClientParams{ProjectID: "test", DefaultClient: mocks.NewTestClient(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{"Retry-After": []string{"10"}}}, nil
	})})

	_, err = c.DoPostRequest("path", nil, nil, "")
	require.ErrorIs(t, err, descope.ErrRateLimitExceeded)
	require.ErrorContains(t, err, "Try again in 10 seconds")
	require.Equal(t, 10, err.(*descope.Error).Info[descope.ErrorInfoKeys.RateLimitExceededRetryAfter])
}

func TestPostDescopeError(t *testing.T) {
	projectID := "test"
	code := "this is an error"
	c := NewClient(ClientParams{ProjectID: projectID, DefaultClient: mocks.NewTestClient(func(r *http.Request) (*http.Response, error) {
		assert.Nil(t, r.Body)
		return &http.Response{StatusCode: http.StatusBadRequest, Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{ "errorCode": "%s" }`, code)))}, nil
	})})

	_, err := c.DoPostRequest("path", nil, nil, "")
	require.Error(t, err)
	assert.EqualValues(t, code, err.(*descope.Error).Code)
}

func TestPostError(t *testing.T) {
	projectID := "test"
	expectedErr := "error here"
	c := NewClient(ClientParams{ProjectID: projectID, DefaultClient: mocks.NewTestClient(func(r *http.Request) (*http.Response, error) {
		assert.Nil(t, r.Body)
		return nil, fmt.Errorf(expectedErr)
	})})

	_, err := c.DoPostRequest("path", nil, nil, "")
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

	_, err := c.DoPostRequest("path", nil, nil, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrUnexpectedResponse)
}

func TestPostNotFoundError(t *testing.T) {
	projectID := "test"
	c := NewClient(ClientParams{ProjectID: projectID, DefaultClient: mocks.NewTestClient(func(r *http.Request) (*http.Response, error) {
		assert.Nil(t, r.Body)
		return &http.Response{StatusCode: http.StatusNotFound, Request: r}, nil
	})})

	_, err := c.DoPostRequest("path", nil, nil, "")
	require.Error(t, err)
	assert.ErrorIs(t, err, descope.ErrUnexpectedResponse)
}

func TestDoRequestDefault(t *testing.T) {
	projectID := "test"
	c := NewClient(ClientParams{ProjectID: projectID, DefaultClient: mocks.NewTestClient(func(r *http.Request) (*http.Response, error) {
		assert.Nil(t, r.Body)
		return &http.Response{StatusCode: http.StatusOK}, nil
	})})

	_, err := c.DoRequest(http.MethodGet, "path", nil, nil, "")
	require.NoError(t, err)
}

func TestRoutesSignInOTP(t *testing.T) {
	r := Routes.SignInOTP()
	assert.EqualValues(t, "/v1/auth/otp/signin", r)
}
