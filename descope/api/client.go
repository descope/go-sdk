package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	urlpkg "net/url"
	"path"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/descope/go-sdk/descope/errors"
	"github.com/descope/go-sdk/descope/logger"
	"github.com/descope/go-sdk/descope/utils"
)

const (
	defaultURL                = "https://api.descope.com"
	AuthorizationHeaderName   = "Authorization"
	BearerAuthorizationPrefix = "Bearer "
)

var (
	Routes = endpoints{
		version: "/v1/",
		auth: struct {
			signInOTP                string
			signUpOTP                string
			signUpOrInOTP            string
			signUpTOTP               string
			updateTOTP               string
			verifyTOTPCode           string
			verifyCode               string
			signInMagicLink          string
			signUpMagicLink          string
			signUpOrInMagicLink      string
			verifyMagicLink          string
			oauthStart               string
			exchangeTokenOAuth       string
			samlStart                string
			exchangeTokenSAML        string
			webauthnSignupStart      string
			webauthnSignupFinish     string
			webauthnSigninStart      string
			webauthnSigninFinish     string
			webauthnUpdateStart      string
			webauthnUpdateFinish     string
			getMagicLinkSession      string
			updateUserEmailMagicLink string
			updateUserEmailOTP       string
			updateUserPhoneMagicLink string
			updateUserPhoneOTP       string
			exchangeAccessKey        string
		}{
			signInOTP:                "auth/otp/signin",
			signUpOTP:                "auth/otp/signup",
			signUpOrInOTP:            "auth/otp/signup-in",
			signUpTOTP:               "auth/totp/signup",
			updateTOTP:               "auth/totp/update",
			verifyTOTPCode:           "auth/totp/verify",
			verifyCode:               "auth/otp/verify",
			signInMagicLink:          "auth/magiclink/signin",
			signUpMagicLink:          "auth/magiclink/signup",
			signUpOrInMagicLink:      "auth/magiclink/signup-in",
			verifyMagicLink:          "auth/magiclink/verify",
			oauthStart:               "auth/oauth/authorize",
			exchangeTokenOAuth:       "auth/oauth/exchange",
			samlStart:                "auth/saml/authorize",
			exchangeTokenSAML:        "auth/saml/exchange",
			webauthnSignupStart:      "auth/webauthn/signup/start",
			webauthnSignupFinish:     "auth/webauthn/signup/finish",
			webauthnSigninStart:      "auth/webauthn/signin/start",
			webauthnSigninFinish:     "auth/webauthn/signin/finish",
			webauthnUpdateStart:      "auth/webauthn/update/start",
			webauthnUpdateFinish:     "auth/webauthn/update/finish",
			getMagicLinkSession:      "auth/magiclink/pending-session",
			updateUserEmailMagicLink: "auth/magiclink/update/email",
			updateUserEmailOTP:       "auth/otp/update/email",
			updateUserPhoneMagicLink: "auth/magiclink/update/phone",
			updateUserPhoneOTP:       "auth/otp/update/phone",
			exchangeAccessKey:        "auth/accesskey/exchange",
		},
		logout:  "auth/logoutall",
		keys:    "/keys/",
		refresh: "auth/refresh",
		me:      "auth/me",
	}
)

type endpoints struct {
	version string
	auth    struct {
		signInOTP                string
		signUpOTP                string
		signUpOrInOTP            string
		signUpTOTP               string
		updateTOTP               string
		verifyTOTPCode           string
		verifyCode               string
		signInMagicLink          string
		signUpMagicLink          string
		signUpOrInMagicLink      string
		verifyMagicLink          string
		oauthStart               string
		exchangeTokenOAuth       string
		samlStart                string
		exchangeTokenSAML        string
		webauthnSignupStart      string
		webauthnSignupFinish     string
		webauthnSigninStart      string
		webauthnSigninFinish     string
		webauthnUpdateStart      string
		webauthnUpdateFinish     string
		getMagicLinkSession      string
		updateUserEmailMagicLink string
		updateUserEmailOTP       string
		updateUserPhoneMagicLink string
		updateUserPhoneOTP       string
		exchangeAccessKey        string
	}
	logout  string
	keys    string
	refresh string
	me      string
}

func (e *endpoints) SignInOTP() string {
	return path.Join(e.version, e.auth.signInOTP)
}
func (e *endpoints) SignUpOTP() string {
	return path.Join(e.version, e.auth.signUpOTP)
}
func (e *endpoints) SignUpOrInOTP() string {
	return path.Join(e.version, e.auth.signUpOrInOTP)
}
func (e *endpoints) SignUpTOTP() string {
	return path.Join(e.version, e.auth.signUpTOTP)
}
func (e *endpoints) UpdateTOTP() string {
	return path.Join(e.version, e.auth.updateTOTP)
}
func (e *endpoints) VerifyCode() string {
	return path.Join(e.version, e.auth.verifyCode)
}
func (e *endpoints) VerifyTOTPCode() string {
	return path.Join(e.version, e.auth.verifyTOTPCode)
}
func (e *endpoints) SignInMagicLink() string {
	return path.Join(e.version, e.auth.signInMagicLink)
}
func (e *endpoints) SignUpMagicLink() string {
	return path.Join(e.version, e.auth.signUpMagicLink)
}
func (e *endpoints) SignUpOrInMagicLink() string {
	return path.Join(e.version, e.auth.signUpOrInMagicLink)
}
func (e *endpoints) VerifyMagicLink() string {
	return path.Join(e.version, e.auth.verifyMagicLink)
}
func (e *endpoints) OAuthStart() string {
	return path.Join(e.version, e.auth.oauthStart)
}
func (e *endpoints) ExchangeTokenOAuth() string {
	return path.Join(e.version, e.auth.exchangeTokenOAuth)
}
func (e *endpoints) SAMLStart() string {
	return path.Join(e.version, e.auth.samlStart)
}
func (e *endpoints) ExchangeTokenSAML() string {
	return path.Join(e.version, e.auth.exchangeTokenSAML)
}
func (e *endpoints) WebAuthnSignupStart() string {
	return path.Join(e.version, e.auth.webauthnSignupStart)
}
func (e *endpoints) WebAuthnSignupFinish() string {
	return path.Join(e.version, e.auth.webauthnSignupFinish)
}
func (e *endpoints) WebAuthnSigninStart() string {
	return path.Join(e.version, e.auth.webauthnSigninStart)
}
func (e *endpoints) WebAuthnSigninFinish() string {
	return path.Join(e.version, e.auth.webauthnSigninFinish)
}
func (e *endpoints) WebAuthnUpdateUserDeviceStart() string {
	return path.Join(e.version, e.auth.webauthnUpdateStart)
}
func (e *endpoints) WebAuthnUpdateUserDeviceFinish() string {
	return path.Join(e.version, e.auth.webauthnUpdateFinish)
}
func (e *endpoints) GetMagicLinkSession() string {
	return path.Join(e.version, e.auth.getMagicLinkSession)
}
func (e *endpoints) Logout() string {
	return path.Join(e.version, e.logout)
}
func (e *endpoints) Me() string {
	return path.Join(e.version, e.me)
}
func (e *endpoints) GetKeys() string {
	return path.Join(e.version, e.keys)
}
func (e *endpoints) RefreshToken() string {
	return path.Join(e.version, e.refresh)
}

func (e *endpoints) UpdateUserEmailMagiclink() string {
	return path.Join(e.version, e.auth.updateUserEmailMagicLink)
}

func (e *endpoints) UpdateUserEmailOTP() string {
	return path.Join(e.version, e.auth.updateUserEmailOTP)
}

func (e *endpoints) UpdateUserPhoneMagicLink() string {
	return path.Join(e.version, e.auth.updateUserPhoneMagicLink)
}

func (e *endpoints) UpdateUserPhoneOTP() string {
	return path.Join(e.version, e.auth.updateUserPhoneOTP)
}

func (e *endpoints) ExchangeAccessKey() string {
	return path.Join(e.version, e.auth.exchangeAccessKey)
}

type ClientParams struct {
	BaseURL              string
	DefaultClient        IHttpClient
	CustomDefaultHeaders map[string]string

	ProjectID string
}

type IHttpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type Client struct {
	httpClient IHttpClient
	uri        string
	headers    map[string]string
	conf       ClientParams
	buildInfo  *debug.BuildInfo
}
type HTTPResponse struct {
	Req     *http.Request
	Res     *http.Response
	BodyStr string
}
type HTTPRequest struct {
	Headers     map[string]string
	QueryParams map[string]string
	BaseURL     string
	ResBodyObj  interface{}
	Request     *http.Request
	Cookies     []*http.Cookie
}

func NewClient(conf ClientParams) *Client {
	httpClient := conf.DefaultClient
	if httpClient == nil {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.MaxIdleConns = 100
		t.MaxConnsPerHost = 100
		t.MaxIdleConnsPerHost = 100

		httpClient = &http.Client{
			Timeout:   time.Second * 10,
			Transport: t,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	defaultHeaders := map[string]string{}

	for key, value := range conf.CustomDefaultHeaders {
		defaultHeaders[key] = value
	}

	if conf.BaseURL == "" {
		conf.BaseURL = defaultURL
	}

	bi, _ := debug.ReadBuildInfo()

	return &Client{
		uri:        conf.BaseURL,
		httpClient: httpClient,
		headers:    defaultHeaders,
		conf:       conf,
		buildInfo:  bi,
	}
}

func (c *Client) DoGetRequest(uri string, options *HTTPRequest, pswd string) (*HTTPResponse, error) {
	return c.DoRequest(http.MethodGet, uri, nil, options, pswd)
}

func (c *Client) DoPostRequest(uri string, body interface{}, options *HTTPRequest, pswd string) (*HTTPResponse, error) {
	if options == nil {
		options = &HTTPRequest{}
	}
	if options.Headers == nil {
		options.Headers = map[string]string{}
	}
	if _, ok := options.Headers["Content-Type"]; !ok {
		options.Headers["Content-Type"] = "application/json"
	}

	var payload io.Reader
	if body != nil {
		if b, err := utils.Marshal(body); err == nil {
			payload = bytes.NewBuffer(b)
		} else {
			return nil, err
		}
	}

	return c.DoRequest(http.MethodPost, uri, payload, options, pswd)
}

func (c *Client) DoRequest(method, uriPath string, body io.Reader, options *HTTPRequest, pswd string) (*HTTPResponse, error) {
	if options == nil {
		options = &HTTPRequest{}
	}

	base := c.uri
	if options.BaseURL != "" {
		base = options.BaseURL
	}

	url := fmt.Sprintf("%s/%s", base, strings.TrimLeft(uriPath, "/"))
	req := options.Request
	if req == nil {
		var err error
		req, err = http.NewRequest(method, url, body)
		if err != nil {
			return nil, err
		}
	} else {
		query := req.URL.Query().Encode()
		if query != "" {
			url = fmt.Sprintf("%s?%s", url, query)
		}
		parsedURL, err := urlpkg.Parse(url)
		if err != nil {
			return nil, err
		}
		parsedURL.Query().Encode()
		req.URL = parsedURL
	}

	queryString := req.URL.Query()
	for key, value := range options.QueryParams {
		queryString.Set(key, value)
	}
	req.URL.RawQuery = queryString.Encode()

	for key, value := range c.headers {
		req.Header.Add(key, value)
	}

	for key, value := range options.Headers {
		req.Header.Add(key, value)
	}
	for _, cookie := range options.Cookies {
		req.AddCookie(cookie)
	}
	bearer := c.conf.ProjectID
	if len(pswd) > 0 {
		bearer = fmt.Sprintf("%s:%s", bearer, pswd)
	}
	req.Header.Set(AuthorizationHeaderName, BearerAuthorizationPrefix+bearer)
	addDescopeHeaders(req)

	logger.LogDebug("sending request to [%s]", url)
	response, err := c.httpClient.Do(req)
	if err != nil {
		logger.LogInfo("failed sending request to [%s]", url)
		return nil, err
	}

	if response.Body != nil {
		defer response.Body.Close()
	}
	if !isResponseOK(response) {
		err = c.parseResponseError(response)
		logger.LogDebug("failed sending request to [%s] with [%s]", url, err)
		return nil, err
	}

	resBytes, err := c.parseBody(response)
	if err != nil {
		return nil, err
	}

	if options.ResBodyObj != nil {
		if err = utils.Unmarshal(resBytes, &options.ResBodyObj); err != nil {
			return nil, err
		}
	}

	return &HTTPResponse{
		Req:     req,
		Res:     response,
		BodyStr: string(resBytes),
	}, nil
}

func (c *Client) parseBody(response *http.Response) (resBytes []byte, err error) {
	if response.Body != nil {
		resBytes, err = io.ReadAll(response.Body)
		if err != nil {
			logger.LogInfo("failed reading body from request to [%s]", response.Request.URL.String())
			return nil, err
		}
	}
	return
}

func (c *Client) parseResponseError(response *http.Response) error {
	if response.StatusCode == http.StatusUnauthorized {
		return errors.NewUnauthorizedError()
	}
	if response.StatusCode == http.StatusNotFound {
		return errors.NewError("404", fmt.Sprintf("url [%s] not found", response.Request.URL.String()))
	}

	body, err := c.parseBody(response)
	if err != nil {
		return err
	}

	var responseErr *errors.WebError
	if err := json.Unmarshal(body, &responseErr); err != nil {
		logger.LogInfo("failed to load error from response [error: %s]", err)
		return errors.NewValidationError(string(body))
	}
	return responseErr
}

func isResponseOK(response *http.Response) bool {
	return response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices || response.StatusCode == http.StatusTemporaryRedirect
}

func (c *Client) addDescopeHeaders(req *http.Request) {
	req.Header.Set("x-descope-sdk-name", "golang")
	req.Header.Set("x-descope-sdk-go-version", runtime.Version())
	if c.buildInfo != nil {
		for _, dep := range c.buildInfo.Deps {
			if strings.HasPrefix(dep.Path, "github.com/descope/go-sdk/descope") {
				req.Header.Set("x-descope-sdk-version", dep.Version)
				req.Header.Set("x-descope-sdk-sha", dep.Sum)
				break
			}
		}
	}
}
