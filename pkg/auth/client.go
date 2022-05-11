package auth

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"path"
	"time"
)

const (
	defaultURI = "http://localhost:8080"
)

type iClient interface {
	post(path string, body interface{}) ([]byte, *WebError)
}

type client struct {
	httpClient *http.Client
	uri        string
	headers    map[string]string
}

func newClient(authentication string) *client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConns = 100
	t.MaxConnsPerHost = 100
	t.MaxIdleConnsPerHost = 100

	httpClient := &http.Client{
		Timeout:   time.Second * 10,
		Transport: t,
	}

	defaultHeaders := map[string]string{
		"Authorization": authentication,
	}

	return &client{
		uri:        defaultURI,
		httpClient: httpClient,
		headers:    defaultHeaders,
	}
}

func (c *client) post(uriPath string, body interface{}) ([]byte, *WebError) {
	buf := new(bytes.Buffer)
	if err := json.NewEncoder(buf).Encode(body); err != nil {
		return nil, NewFromErrorError("", err)
	}
	req, err := http.NewRequest("POST", path.Join(c.uri, uriPath), buf)
	if err != nil {
		return nil, NewFromErrorError("", err)
	}

	for key, value := range c.headers {
		req.Header.Add(key, value)
	}
	req.Header.Set("Content-Type", "application/json")

	response, err := c.httpClient.Do(req)
	if err != nil {
		return nil, NewFromErrorError("", err)
	}

	defer response.Body.Close()
	resBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, NewFromErrorError("", err)
	}
	statusOK := response.StatusCode >= 200 && response.StatusCode < 300
	if !statusOK {
		var responseErr *WebError
		json.Unmarshal(resBytes, responseErr)
		return nil, responseErr
	}
	return resBytes, nil
}
