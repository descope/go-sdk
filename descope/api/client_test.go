package api

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/descope/go-sdk/descope/errors"
	"github.com/descope/go-sdk/descope/tests"
	"github.com/descope/go-sdk/descope/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetRequest(t *testing.T) {
	projectID := "test"
	expectedResponse := "hey"
	c := NewClient(ClientParams{ProjectID: projectID, DefaultClient: tests.NewTestClient(func(r *http.Request) (*http.Response, error) {
		assert.Nil(t, r.Body)
		assert.EqualValues(t, "/path", r.URL.Path)
		actualProject, _, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.EqualValues(t, projectID, actualProject)
		return &http.Response{Body: io.NopCloser(strings.NewReader(expectedResponse)), StatusCode: http.StatusOK}, nil
	})})
	res, err := c.DoGetRequest("path", nil)
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
	c := NewClient(ClientParams{ProjectID: projectID, DefaultClient: tests.NewTestClient(func(r *http.Request) (*http.Response, error) {
		assert.NotNil(t, r.Body)
		actualProject, _, ok := r.BasicAuth()
		assert.True(t, ok)
		assert.EqualValues(t, projectID, actualProject)
		assert.EqualValues(t, expectedHeaders["header1"], r.Header.Get("header1"))
		return &http.Response{Body: io.NopCloser(bytes.NewReader(outputBytes)), StatusCode: http.StatusOK}, nil
	})})

	actualOutput := &dummy{}
	res, err := c.DoPostRequest("path", strings.NewReader("test"), &HTTPRequest{ResBodyObj: actualOutput, Headers: expectedHeaders})
	require.NoError(t, err)
	assert.EqualValues(t, string(outputBytes), res.BodyStr)
	assert.EqualValues(t, expectedOutput, actualOutput)
}

func TestPostCustomHeaders(t *testing.T) {
	projectID := "test"
	headers := map[string]string{"test": "a", "test2": "b"}
	c := NewClient(ClientParams{ProjectID: projectID, CustomDefaultHeaders: headers, DefaultClient: tests.NewTestClient(func(r *http.Request) (*http.Response, error) {
		assert.Nil(t, r.Body)
		for k, v := range headers {
			assert.EqualValues(t, v, r.Header.Get(k))
		}
		return &http.Response{StatusCode: http.StatusOK}, nil
	})})

	_, err := c.DoPostRequest("path", nil, nil)
	require.NoError(t, err)
}

func TestPostUnauthorized(t *testing.T) {
	projectID := "test"
	c := NewClient(ClientParams{ProjectID: projectID, DefaultClient: tests.NewTestClient(func(r *http.Request) (*http.Response, error) {
		assert.Nil(t, r.Body)
		return &http.Response{StatusCode: http.StatusUnauthorized}, nil
	})})

	_, err := c.DoPostRequest("path", nil, nil)
	require.Error(t, err)
	assert.EqualValues(t, errors.BadRequestErrorCode, err.(*errors.WebError).Code)
}

func TestPostWebError(t *testing.T) {
	projectID := "test"
	code := "this is an error"
	c := NewClient(ClientParams{ProjectID: projectID, DefaultClient: tests.NewTestClient(func(r *http.Request) (*http.Response, error) {
		assert.Nil(t, r.Body)
		return &http.Response{StatusCode: http.StatusBadRequest, Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{ "error": "%s" }`, code)))}, nil
	})})

	_, err := c.DoPostRequest("path", nil, nil)
	require.Error(t, err)
	assert.EqualValues(t, code, err.(*errors.WebError).Code)
}

func TestPostError(t *testing.T) {
	projectID := "test"
	expectedErr := "error here"
	c := NewClient(ClientParams{ProjectID: projectID, DefaultClient: tests.NewTestClient(func(r *http.Request) (*http.Response, error) {
		assert.Nil(t, r.Body)
		return nil, fmt.Errorf(expectedErr)
	})})

	_, err := c.DoPostRequest("path", nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), expectedErr)
}

func TestPostUnknownError(t *testing.T) {
	projectID := "test"
	code := "this is an error"
	c := NewClient(ClientParams{ProjectID: projectID, DefaultClient: tests.NewTestClient(func(r *http.Request) (*http.Response, error) {
		assert.Nil(t, r.Body)
		return &http.Response{StatusCode: http.StatusBadRequest, Body: io.NopCloser(strings.NewReader(code))}, nil
	})})

	_, err := c.DoPostRequest("path", nil, nil)
	require.Error(t, err)
	assert.EqualValues(t, code, err.Error())
}

func TestPostNotFoundError(t *testing.T) {
	projectID := "test"
	c := NewClient(ClientParams{ProjectID: projectID, DefaultClient: tests.NewTestClient(func(r *http.Request) (*http.Response, error) {
		assert.Nil(t, r.Body)
		return &http.Response{StatusCode: http.StatusNotFound, Request: r}, nil
	})})

	_, err := c.DoPostRequest("path", nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "404")
}

func TestRoutesSignInOTP(t *testing.T) {
	r := Routes.SignInOTP()
	assert.EqualValues(t, "/v1/auth/signin/otp", r)
}
