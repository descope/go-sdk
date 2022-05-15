package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

type client struct {
	httpClient IHttpClient
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
	defaultHeaders := map[string]string{}

	for key, value := range conf.CustomDefaultHeaders {
		defaultHeaders[key] = value
	}

	return &client{
		uri:        conf.DefaultURL,
		httpClient: httpClient,
		headers:    defaultHeaders,
		conf:       conf,
	}
}

func (c *client) Post(uriPath string, body interface{}) ([]byte, *http.Response, error) {
	buf := new(bytes.Buffer)
	if err := json.NewEncoder(buf).Encode(body); err != nil {
		return nil, nil, NewFromError("", err)
	}
	url := fmt.Sprintf("%s/%s", c.uri, strings.TrimLeft(uriPath, "/"))
	req, err := http.NewRequest(http.MethodPost, url, buf)
	if err != nil {
		return nil, nil, NewFromError("", err)
	}

	for key, value := range c.headers {
		req.Header.Add(key, value)
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(c.conf.ProjectID, "")

	c.conf.LogDebug("sending request to [%s]", uriPath)
	response, err := c.httpClient.Do(req)
	if err != nil {
		c.conf.LogInfo("failed sending request to [%s]", uriPath)
		return nil, nil, NewFromError("", err)
	}

	var resBytes []byte
	if response.Body != nil {
		defer response.Body.Close()
		resBytes, err = ioutil.ReadAll(response.Body)
		if err != nil {
			c.conf.LogInfo("failed reading body from request to [%s]", uriPath)
			return nil, nil, NewFromError("", err)
		}
	}
	if !isResponseOK(response) {
		return nil, nil, c.parseResponseError(response, resBytes)
	}
	return resBytes, response, nil
}

func (c *client) parseResponseError(response *http.Response, body []byte) error {
	if response.StatusCode == http.StatusUnauthorized {
		return NewUnauthorizedError()
	}

	var responseErr *WebError
	if err := json.Unmarshal(body, &responseErr); err != nil {
		c.conf.LogInfo("failed to load error from response [error: %s]", err)
		return errors.New(string(body))
	}
	return responseErr
}

func isResponseOK(response *http.Response) bool {
	return response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices
}
