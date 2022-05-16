package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
type HTTPResponse struct {
	req     *http.Request
	res     *http.Response
	bodyStr string
}
type HTTPRequest struct {
	headers    map[string]string
	resBodyObj interface{}
	username   string
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

func (c *client) DoGetRequest(uri string, options *HTTPRequest) (*HTTPResponse, error) {
	return c.DoRequest(http.MethodGet, uri, nil, options)
}

func (c *client) DoPostRequest(uri string, body interface{}, options *HTTPRequest) (*HTTPResponse, error) {
	if options == nil {
		options = &HTTPRequest{}
	}
	if options.headers == nil {
		options.headers = map[string]string{}
	}
	if _, ok := options.headers["Content-Type"]; !ok {
		options.headers["Content-Type"] = "application/json"
	}

	var payload io.Reader
	if body != nil {
		if b, err := Marshal(body); err == nil {
			payload = bytes.NewBuffer(b)
		} else {
			return nil, err
		}
	}

	return c.DoRequest(http.MethodPost, uri, payload, options)
}

func (c *client) DoRequest(method, uriPath string, body io.Reader, options *HTTPRequest) (*HTTPResponse, error) {
	buf := new(bytes.Buffer)
	if options == nil {
		options = &HTTPRequest{}
	}
	if err := json.NewEncoder(buf).Encode(body); err != nil {
		return nil, NewFromError("", err)
	}
	url := fmt.Sprintf("%s/%s", c.uri, strings.TrimLeft(uriPath, "/"))
	req, err := http.NewRequest(method, url, buf)
	if err != nil {
		return nil, NewFromError("", err)
	}

	for key, value := range c.headers {
		req.Header.Add(key, value)
	}
	req.SetBasicAuth(c.conf.ProjectID, "")

	c.conf.LogDebug("sending request to [%s]", uriPath)
	response, err := c.httpClient.Do(req)
	if err != nil {
		c.conf.LogInfo("failed sending request to [%s]", uriPath)
		return nil, NewFromError("", err)
	}

	if response.Body != nil {
		defer response.Body.Close()
	}
	if !isResponseOK(response) {
		return nil, c.parseResponseError(response)
	}

	resBytes, err := c.parseBody(response)
	if err != nil {
		return nil, err
	}

	if options.resBodyObj != nil {
		if err = Unmarshal(resBytes, &options.resBodyObj); err != nil {
			return nil, err
		}
	}

	return &HTTPResponse{
		req:     req,
		res:     response,
		bodyStr: string(resBytes),
	}, nil
}

func (c *client) parseBody(response *http.Response) (resBytes []byte, err error) {
	if response.Body != nil {
		resBytes, err = ioutil.ReadAll(response.Body)
		if err != nil {
			c.conf.LogInfo("failed reading body from request to [%s]", response.Request.URL.String())
			return nil, NewFromError("", err)
		}
	}
	return
}

func (c *client) parseResponseError(response *http.Response) error {
	if response.StatusCode == http.StatusUnauthorized {
		return NewUnauthorizedError()
	}

	body, err := c.parseBody(response)
	if err != nil {
		return err
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
