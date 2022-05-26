package mocks

import (
	"net/http"
)

type Do func(r *http.Request) (*http.Response, error)

type mockHTTPClient struct {
	callback Do
}

func NewTestClient(callback Do) *mockHTTPClient {
	return &mockHTTPClient{callback: callback}
}

func (c *mockHTTPClient) Do(r *http.Request) (*http.Response, error) {
	if c.callback == nil {
		return nil, nil
	}
	return c.callback(r)
}
