package tests

import (
	"net/http"
)

type Do func(r *http.Request) (*http.Response, error)

type mockClient struct {
	callback Do
}

func NewTestClient(callback Do) *mockClient {
	return &mockClient{callback: callback}
}

func (c *mockClient) Do(r *http.Request) (*http.Response, error) {
	if c.callback == nil {
		return nil, nil
	}
	return c.callback(r)
}
