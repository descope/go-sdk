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
	"strconv"
	"strings"
	"time"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/logger"
)

const (
	defaultURL                = "https://api.descope.com"
	AuthorizationHeaderName   = "Authorization"
	BearerAuthorizationPrefix = "Bearer "
	nullString                = "null"
)

var (
	Routes = endpoints{
		version:   "/v1/",
		versionV2: "/v2/",
		auth: authEndpoints{
			signInOTP:                    "auth/otp/signin",
			signUpOTP:                    "auth/otp/signup",
			signUpOrInOTP:                "auth/otp/signup-in",
			signUpTOTP:                   "auth/totp/signup",
			updateTOTP:                   "auth/totp/update",
			verifyTOTPCode:               "auth/totp/verify",
			verifyCode:                   "auth/otp/verify",
			signInMagicLink:              "auth/magiclink/signin",
			signUpMagicLink:              "auth/magiclink/signup",
			signUpOrInMagicLink:          "auth/magiclink/signup-in",
			verifyMagicLink:              "auth/magiclink/verify",
			signInEnchantedLink:          "auth/enchantedlink/signin",
			signUpEnchantedLink:          "auth/enchantedlink/signup",
			signUpOrInEnchantedLink:      "auth/enchantedlink/signup-in",
			verifyEnchantedLink:          "auth/enchantedlink/verify",
			getEnchantedLinkSession:      "auth/enchantedlink/pending-session",
			updateUserEmailEnchantedLink: "auth/enchantedlink/update/email",
			oauthStart:                   "auth/oauth/authorize",
			exchangeTokenOAuth:           "auth/oauth/exchange",
			samlStart:                    "auth/saml/authorize",
			exchangeTokenSAML:            "auth/saml/exchange",
			webauthnSignUpStart:          "auth/webauthn/signup/start",
			webauthnSignUpFinish:         "auth/webauthn/signup/finish",
			webauthnSignInStart:          "auth/webauthn/signin/start",
			webauthnSignInFinish:         "auth/webauthn/signin/finish",
			webauthnSignUpOrInStart:      "auth/webauthn/signup-in/start",
			webauthnUpdateStart:          "auth/webauthn/update/start",
			webauthnUpdateFinish:         "auth/webauthn/update/finish",
			updateUserEmailMagicLink:     "auth/magiclink/update/email",
			updateUserEmailOTP:           "auth/otp/update/email",
			updateUserPhoneMagicLink:     "auth/magiclink/update/phone",
			updateUserPhoneOTP:           "auth/otp/update/phone",
			exchangeAccessKey:            "auth/accesskey/exchange",
		},
		mgmt: mgmtEndpoints{
			tenantCreate:                "mgmt/tenant/create",
			tenantUpdate:                "mgmt/tenant/update",
			tenantDelete:                "mgmt/tenant/delete",
			tenantLoadAll:               "mgmt/tenant/all",
			userCreate:                  "mgmt/user/create",
			userUpdate:                  "mgmt/user/update",
			userDelete:                  "mgmt/user/delete",
			userLoad:                    "mgmt/user",
			userSearchAll:               "mgmt/user/search",
			userUpdateStatus:            "mgmt/user/update/status",
			userUpdateEmail:             "mgmt/user/update/email",
			userUpdatePhone:             "mgmt/user/update/phone",
			userUpdateName:              "mgmt/user/update/name",
			userAddTenant:               "mgmt/user/update/tenant/add",
			userRemoveTenant:            "mgmt/user/update/tenant/remove",
			userAddRole:                 "mgmt/user/update/role/add",
			userRemoveRole:              "mgmt/user/update/role/remove",
			accessKeyCreate:             "mgmt/accesskey/create",
			accessKeyLoad:               "mgmt/accesskey",
			accessKeySearchAll:          "mgmt/accesskey/search",
			accessKeyUpdate:             "mgmt/accesskey/update",
			accessKeyDeactivate:         "mgmt/accesskey/deactivate",
			accessKeyActivate:           "mgmt/accesskey/activate",
			accessKeyDelete:             "mgmt/accesskey/delete",
			ssoConfigure:                "mgmt/sso/settings",
			ssoMetadata:                 "mgmt/sso/metadata",
			ssoMapping:                  "mgmt/sso/mapping",
			updateJWT:                   "mgmt/jwt/update",
			permissionCreate:            "mgmt/permission/create",
			permissionUpdate:            "mgmt/permission/update",
			permissionDelete:            "mgmt/permission/delete",
			permissionLoadAll:           "mgmt/permission/all",
			roleCreate:                  "mgmt/role/create",
			roleUpdate:                  "mgmt/role/update",
			roleDelete:                  "mgmt/role/delete",
			roleLoadAll:                 "mgmt/role/all",
			groupLoadAllGroups:          "mgmt/group/all",
			groupLoadAllGroupsForMember: "mgmt/group/member/all",
			groupLoadAllGroupMembers:    "mgmt/group/members",
		},
		logout:    "auth/logout",
		logoutAll: "auth/logoutall",
		keys:      "/keys/",
		refresh:   "auth/refresh",
		me:        "auth/me",
	}
)

type endpoints struct {
	version   string
	versionV2 string
	auth      authEndpoints
	mgmt      mgmtEndpoints
	logout    string
	logoutAll string
	keys      string
	refresh   string
	me        string
}

type authEndpoints struct {
	signInOTP                    string
	signUpOTP                    string
	signUpOrInOTP                string
	signUpTOTP                   string
	updateTOTP                   string
	verifyTOTPCode               string
	verifyCode                   string
	signInMagicLink              string
	signUpMagicLink              string
	signUpOrInMagicLink          string
	verifyMagicLink              string
	signInEnchantedLink          string
	signUpEnchantedLink          string
	signUpOrInEnchantedLink      string
	verifyEnchantedLink          string
	getEnchantedLinkSession      string
	updateUserEmailEnchantedLink string
	oauthStart                   string
	exchangeTokenOAuth           string
	samlStart                    string
	exchangeTokenSAML            string
	webauthnSignUpStart          string
	webauthnSignUpFinish         string
	webauthnSignInStart          string
	webauthnSignInFinish         string
	webauthnSignUpOrInStart      string
	webauthnUpdateStart          string
	webauthnUpdateFinish         string
	updateUserEmailMagicLink     string
	updateUserEmailOTP           string
	updateUserPhoneMagicLink     string
	updateUserPhoneOTP           string
	exchangeAccessKey            string
}

type mgmtEndpoints struct {
	tenantCreate  string
	tenantUpdate  string
	tenantDelete  string
	tenantLoadAll string

	userCreate       string
	userUpdate       string
	userDelete       string
	userLoad         string
	userSearchAll    string
	userUpdateStatus string
	userUpdateEmail  string
	userUpdatePhone  string
	userUpdateName   string
	userAddTenant    string
	userRemoveTenant string
	userAddRole      string
	userRemoveRole   string

	accessKeyCreate     string
	accessKeyLoad       string
	accessKeySearchAll  string
	accessKeyUpdate     string
	accessKeyDeactivate string
	accessKeyActivate   string
	accessKeyDelete     string

	ssoConfigure string
	ssoMetadata  string
	ssoMapping   string
	updateJWT    string

	permissionCreate  string
	permissionUpdate  string
	permissionDelete  string
	permissionLoadAll string

	roleCreate  string
	roleUpdate  string
	roleDelete  string
	roleLoadAll string

	groupLoadAllGroups          string
	groupLoadAllGroupsForMember string
	groupLoadAllGroupMembers    string
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

func (e *endpoints) SignInEnchantedLink() string {
	return path.Join(e.version, e.auth.signInEnchantedLink)
}
func (e *endpoints) SignUpEnchantedLink() string {
	return path.Join(e.version, e.auth.signUpEnchantedLink)
}
func (e *endpoints) SignUpOrInEnchantedLink() string {
	return path.Join(e.version, e.auth.signUpOrInEnchantedLink)
}
func (e *endpoints) UpdateUserEmailEnchantedlink() string {
	return path.Join(e.version, e.auth.updateUserEmailEnchantedLink)
}
func (e *endpoints) VerifyEnchantedLink() string {
	return path.Join(e.version, e.auth.verifyEnchantedLink)
}
func (e *endpoints) GetEnchantedLinkSession() string {
	return path.Join(e.version, e.auth.getEnchantedLinkSession)
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
func (e *endpoints) WebAuthnSignUpStart() string {
	return path.Join(e.version, e.auth.webauthnSignUpStart)
}
func (e *endpoints) WebAuthnSignUpFinish() string {
	return path.Join(e.version, e.auth.webauthnSignUpFinish)
}
func (e *endpoints) WebAuthnSignInStart() string {
	return path.Join(e.version, e.auth.webauthnSignInStart)
}
func (e *endpoints) WebAuthnSignInFinish() string {
	return path.Join(e.version, e.auth.webauthnSignInFinish)
}
func (e *endpoints) WebAuthnSignUpOrInStart() string {
	return path.Join(e.version, e.auth.webauthnSignUpOrInStart)
}
func (e *endpoints) WebAuthnUpdateUserDeviceStart() string {
	return path.Join(e.version, e.auth.webauthnUpdateStart)
}
func (e *endpoints) WebAuthnUpdateUserDeviceFinish() string {
	return path.Join(e.version, e.auth.webauthnUpdateFinish)
}
func (e *endpoints) Logout() string {
	return path.Join(e.version, e.logout)
}
func (e *endpoints) LogoutAll() string {
	return path.Join(e.version, e.logoutAll)
}
func (e *endpoints) Me() string {
	return path.Join(e.version, e.me)
}
func (e *endpoints) GetKeys() string {
	return path.Join(e.versionV2, e.keys)
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

func (e *endpoints) ManagementTenantCreate() string {
	return path.Join(e.version, e.mgmt.tenantCreate)
}

func (e *endpoints) ManagementTenantUpdate() string {
	return path.Join(e.version, e.mgmt.tenantUpdate)
}

func (e *endpoints) ManagementTenantDelete() string {
	return path.Join(e.version, e.mgmt.tenantDelete)
}

func (e *endpoints) ManagementTenantLoadAll() string {
	return path.Join(e.version, e.mgmt.tenantLoadAll)
}

func (e *endpoints) ManagementUserCreate() string {
	return path.Join(e.version, e.mgmt.userCreate)
}

func (e *endpoints) ManagementUserUpdate() string {
	return path.Join(e.version, e.mgmt.userUpdate)
}

func (e *endpoints) ManagementUserDelete() string {
	return path.Join(e.version, e.mgmt.userDelete)
}

func (e *endpoints) ManagementUserLoad() string {
	return path.Join(e.version, e.mgmt.userLoad)
}

func (e *endpoints) ManagementUserSearchAll() string {
	return path.Join(e.version, e.mgmt.userSearchAll)
}

func (e *endpoints) ManagementUserUpdateStatus() string {
	return path.Join(e.version, e.mgmt.userUpdateStatus)
}

func (e *endpoints) ManagementUserUpdateEmail() string {
	return path.Join(e.version, e.mgmt.userUpdateEmail)
}

func (e *endpoints) ManagementUserUpdatePhone() string {
	return path.Join(e.version, e.mgmt.userUpdatePhone)
}

func (e *endpoints) ManagementUserUpdateDisplayName() string {
	return path.Join(e.version, e.mgmt.userUpdateName)
}

func (e *endpoints) ManagementUserAddTenant() string {
	return path.Join(e.version, e.mgmt.userAddTenant)
}

func (e *endpoints) ManagementUserRemoveTenant() string {
	return path.Join(e.version, e.mgmt.userRemoveTenant)
}

func (e *endpoints) ManagementUserAddRole() string {
	return path.Join(e.version, e.mgmt.userAddRole)
}

func (e *endpoints) ManagementUserRemoveRole() string {
	return path.Join(e.version, e.mgmt.userRemoveRole)
}

func (e *endpoints) ManagementAccessKeyCreate() string {
	return path.Join(e.version, e.mgmt.accessKeyCreate)
}

func (e *endpoints) ManagementAccessKeyLoad() string {
	return path.Join(e.version, e.mgmt.accessKeyLoad)
}

func (e *endpoints) ManagementAccessKeySearchAll() string {
	return path.Join(e.version, e.mgmt.accessKeySearchAll)
}

func (e *endpoints) ManagementAccessKeyUpdate() string {
	return path.Join(e.version, e.mgmt.accessKeyUpdate)
}

func (e *endpoints) ManagementAccessKeyDeactivate() string {
	return path.Join(e.version, e.mgmt.accessKeyDeactivate)
}

func (e *endpoints) ManagementAccessKeyActivate() string {
	return path.Join(e.version, e.mgmt.accessKeyActivate)
}

func (e *endpoints) ManagementAccessKeyDelete() string {
	return path.Join(e.version, e.mgmt.accessKeyDelete)
}

func (e *endpoints) ManagementSSOConfigure() string {
	return path.Join(e.version, e.mgmt.ssoConfigure)
}

func (e *endpoints) ManagementSSOMetadata() string {
	return path.Join(e.version, e.mgmt.ssoMetadata)
}

func (e *endpoints) ManagementSSOMapping() string {
	return path.Join(e.version, e.mgmt.ssoMapping)
}

func (e *endpoints) ManagementUpdateJWT() string {
	return path.Join(e.version, e.mgmt.updateJWT)
}

func (e *endpoints) ManagementPermissionCreate() string {
	return path.Join(e.version, e.mgmt.permissionCreate)
}

func (e *endpoints) ManagementPermissionUpdate() string {
	return path.Join(e.version, e.mgmt.permissionUpdate)
}

func (e *endpoints) ManagementPermissionDelete() string {
	return path.Join(e.version, e.mgmt.permissionDelete)
}

func (e *endpoints) ManagementPermissionLoadAll() string {
	return path.Join(e.version, e.mgmt.permissionLoadAll)
}

func (e *endpoints) ManagementRoleCreate() string {
	return path.Join(e.version, e.mgmt.roleCreate)
}

func (e *endpoints) ManagementRoleUpdate() string {
	return path.Join(e.version, e.mgmt.roleUpdate)
}

func (e *endpoints) ManagementRoleDelete() string {
	return path.Join(e.version, e.mgmt.roleDelete)
}

func (e *endpoints) ManagementRoleLoadAll() string {
	return path.Join(e.version, e.mgmt.roleLoadAll)
}

func (e *endpoints) ManagementGroupLoadAllGroups() string {
	return path.Join(e.version, e.mgmt.groupLoadAllGroups)
}

func (e *endpoints) ManagementGroupLoadAllGroupsForMember() string {
	return path.Join(e.version, e.mgmt.groupLoadAllGroupsForMember)
}

func (e *endpoints) ManagementGroupLoadAllGroupMembers() string {
	return path.Join(e.version, e.mgmt.groupLoadAllGroupMembers)
}

type sdkInfo struct {
	name      string
	version   string
	goVersion string
	sha       string
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
	sdkInfo    *sdkInfo
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

	return &Client{
		uri:        conf.BaseURL,
		httpClient: httpClient,
		headers:    defaultHeaders,
		conf:       conf,
		sdkInfo:    getSDKInfo(),
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
	// Originally this was an object, so nil comparison will not always work
	if body != nil {
		if b, err := utils.Marshal(body); err == nil {
			// According to the above comment, we might get here, and there are parsers that do not like this string
			// We prefer the body will be nil
			if string(b) != nullString {
				payload = bytes.NewBuffer(b)
			}
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
	c.addDescopeHeaders(req)

	logger.LogDebug("sending request to [%s]", url)
	response, err := c.httpClient.Do(req)
	if err != nil {
		logger.LogError("failed sending request to [%s]", err, url)
		return nil, err
	}

	if response.Body != nil {
		defer response.Body.Close()
	}
	if !isResponseOK(response) {
		err = c.parseResponseError(response)
		logger.LogInfo("failed sending request to [%s], error: [%s]", url, err)
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
			logger.LogError("failed reading body from request to [%s]", err, response.Request.URL.String())
			return nil, err
		}
	}
	return
}

func (c *Client) parseResponseError(response *http.Response) error {
	if response.StatusCode == http.StatusTooManyRequests {
		if seconds, _ := strconv.Atoi(response.Header.Get(descope.ErrorInfoKeys.RateLimitExceededRetryAfter)); seconds != 0 {
			return descope.ErrRateLimitExceeded.WithMessage("Try again in %d seconds", seconds).WithInfo(descope.ErrorInfoKeys.RateLimitExceededRetryAfter, seconds)
		}
		return descope.ErrRateLimitExceeded.WithMessage("Try again in a few seconds")
	}

	body, err := c.parseBody(response)
	if err != nil {
		logger.LogError("failed to process error from server response", err)
		return descope.ErrUnexpectedResponse
	}

	var responseErr *descope.Error
	if err := json.Unmarshal(body, &responseErr); err != nil || responseErr.Code == "" {
		logger.LogError("failed to parse error from server response", err)
		return descope.ErrUnexpectedResponse
	}

	if responseErr.Description == "" {
		responseErr.Description = "Server error"
	}

	return responseErr
}

func isResponseOK(response *http.Response) bool {
	return response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices || response.StatusCode == http.StatusTemporaryRedirect
}

func (c *Client) addDescopeHeaders(req *http.Request) {
	req.Header.Set("x-descope-sdk-name", c.sdkInfo.name)
	req.Header.Set("x-descope-sdk-go-version", c.sdkInfo.goVersion)
	req.Header.Set("x-descope-sdk-version", c.sdkInfo.version)
	req.Header.Set("x-descope-sdk-sha", c.sdkInfo.sha)
}

func getSDKInfo() *sdkInfo {
	sdkInfo := &sdkInfo{
		name:      "golang",
		goVersion: runtime.Version(),
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi != nil {
		for _, dep := range bi.Deps {
			if strings.HasPrefix(dep.Path, "github.com/descope/go-sdk/descope") {
				sdkInfo.version = dep.Version
				sdkInfo.sha = dep.Sum
				break
			}
		}
	}
	return sdkInfo
}
