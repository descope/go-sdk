package auth

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockClient struct {
	callback Do
}

func newTestClient(callback Do) *mockClient {
	return &mockClient{callback: callback}
}

func (c *mockClient) Do(r *http.Request) (*http.Response, error) {
	if c.callback == nil {
		return nil, nil
	}
	return c.callback(r)
}

func TestPost(t *testing.T) {
	projectID := "test"
	expectedResponse := "hey"
	c := newClient(&Config{ProjectID: projectID, DefaultClient: newTestClient(func(r *http.Request) (*http.Response, error) {
		assert.NotNil(t, r.Body)
		actualProject, _, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.EqualValues(t, projectID, actualProject)
		return &http.Response{Body: io.NopCloser(strings.NewReader(expectedResponse)), StatusCode: http.StatusOK}, nil
	})})

	body, _, err := c.Post("path", nil)
	require.NoError(t, err)
	assert.EqualValues(t, expectedResponse, string(body))
}

func TestPostCustomHeaders(t *testing.T) {
	projectID := "test"
	headers := map[string]string{"test": "a", "test2": "b"}
	c := newClient(&Config{ProjectID: projectID, CustomDefaultHeaders: headers, DefaultClient: newTestClient(func(r *http.Request) (*http.Response, error) {
		assert.NotNil(t, r.Body)
		for k, v := range headers {
			assert.EqualValues(t, v, r.Header.Get(k))
		}
		return &http.Response{StatusCode: http.StatusOK}, nil
	})})

	_, _, err := c.Post("path", nil)
	require.NoError(t, err)
}

func TestPostUnauthorized(t *testing.T) {
	projectID := "test"
	c := newClient(&Config{ProjectID: projectID, DefaultClient: newTestClient(func(r *http.Request) (*http.Response, error) {
		assert.NotNil(t, r.Body)
		return &http.Response{StatusCode: http.StatusUnauthorized}, nil
	})})

	_, _, err := c.Post("path", nil)
	require.Error(t, err)
	assert.EqualValues(t, badRequestErrorCode, err.(*WebError).Code)
}

func TestPostWebError(t *testing.T) {
	projectID := "test"
	code := "this is an error"
	c := newClient(&Config{ProjectID: projectID, DefaultClient: newTestClient(func(r *http.Request) (*http.Response, error) {
		assert.NotNil(t, r.Body)
		return &http.Response{StatusCode: http.StatusBadRequest, Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{ "error": "%s" }`, code)))}, nil
	})})

	_, _, err := c.Post("path", nil)
	require.Error(t, err)
	assert.EqualValues(t, code, err.(*WebError).Code)
}

func TestPostError(t *testing.T) {
	projectID := "test"
	expectedErr := "error here"
	c := newClient(&Config{ProjectID: projectID, DefaultClient: newTestClient(func(r *http.Request) (*http.Response, error) {
		assert.NotNil(t, r.Body)
		return nil, errors.New(expectedErr)
	})})

	_, _, err := c.Post("path", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), expectedErr)
}

func TestPostUnknownError(t *testing.T) {
	projectID := "test"
	code := "this is an error"
	c := newClient(&Config{ProjectID: projectID, LogLevel: LogDebug, DefaultClient: newTestClient(func(r *http.Request) (*http.Response, error) {
		assert.NotNil(t, r.Body)
		return &http.Response{StatusCode: http.StatusBadRequest, Body: io.NopCloser(strings.NewReader(code))}, nil
	})})

	_, _, err := c.Post("path", nil)
	require.Error(t, err)
	assert.EqualValues(t, code, err.Error())
}
