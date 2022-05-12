package auth

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"path"
	"time"
)

type client struct {
	httpClient *http.Client
	uri        string
	headers    map[string]string
	conf       *Config
}

func newClient(conf *Config) *client {
	httpClient := conf.DefaultClient
	if httpClient == nil {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.MaxIdleConns = 100
		t.MaxConnsPerHost = 100
		t.MaxIdleConnsPerHost = 100

		httpClient = &http.Client{
			Timeout:   time.Second * 10,
			Transport: t,
		}
	}
	defaultHeaders := map[string]string{
		"Authorization": conf.ProjectID,
	}

	return &client{
		uri:        defaultURI,
		httpClient: httpClient,
		headers:    defaultHeaders,
		conf:       conf,
	}
}

func (c *client) post(uriPath string, body interface{}) ([]byte, *WebError) {
	buf := new(bytes.Buffer)
	if err := json.NewEncoder(buf).Encode(body); err != nil {
		return nil, NewFromError("", err)
	}
	req, err := http.NewRequest(http.MethodPost, path.Join(c.uri, uriPath), buf)
	if err != nil {
		return nil, NewFromError("", err)
	}

	for key, value := range c.headers {
		req.Header.Add(key, value)
	}
	req.Header.Set("Content-Type", "application/json")

	c.conf.LogDebug("sending request to [%s]", uriPath)
	response, err := c.httpClient.Do(req)
	if err != nil {
		c.conf.LogInfo("failed sending request to [%s]", uriPath)
		return nil, NewFromError("", err)
	}

	defer response.Body.Close()
	resBytes, err := ioutil.ReadAll(response.Body)
	if err != nil {
		c.conf.LogInfo("failed reading body from request to [%s]", uriPath)
		return nil, NewFromError("", err)
	}
	if !isResponseOK(response) {
		var responseErr *WebError
		json.Unmarshal(resBytes, responseErr)
		return nil, responseErr
	}
	return resBytes, nil
}

func isResponseOK(response *http.Response) bool {
	return response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices
}