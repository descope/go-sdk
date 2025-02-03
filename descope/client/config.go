package client

import (
	"net/http"
	"time"

	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/logger"
)

// Conf - Configuration struct describes the configurational data for the authentication methods.
type Config struct {
	// ProjectID (required, "") - used to validate and authenticate against descope services.
	ProjectID string
	// ManagementKey (optional, "") - used to provide a management key that's required
	// for using any of the Management APIs. If empty, this value is retrieved
	// from the DESCOPE_MANAGEMENT_KEY environment variable instead. If neither
	// values are set then any Management API call with fail.
	ManagementKey string
	// AuthManagementKey (optional, "") - used to provide a management key to use
	// with Authentication APIs whose public access has been disabled.
	// If empty, this value is retrieved from the DESCOPE_AUTH_MANAGEMENT_KEY environment variable instead.
	// If neither values are set then any disabled authentication methods API calls with fail.
	AuthManagementKey string
	// PublicKey (optional, "") - used to override or implicitly use a dedicated public key in order to decrypt and validate the JWT tokens
	// during ValidateSessionRequest(). If empty, will attempt to fetch all public keys from the specified project id.
	PublicKey string
	// DescopeBaseURL (optional, "https://api.descope.com") - override the default base URL used to communicate with descope services.
	DescopeBaseURL string
	// DefaultClient (optional, http.DefaultClient) - override the default client used to Do the actual http request.
	DefaultClient api.IHttpClient
	// CertificateVerifyMode (optional, CertificateVerifyAutomatic) - override the server certificate verification behavior when using the default client.
	CertificateVerify api.CertificateVerifyMode
	// RequestTimeout (optional, 60 seconds) - override the HTTP request timeout when using the default client.
	RequestTimeout time.Duration
	// CustomDefaultHeaders (optional, nil) - add custom headers to all requests used to communicate with descope services.
	CustomDefaultHeaders map[string]string
	// LogLevel (optional, LogNone) - set a log level (Debug/Info/None) for the sdk to use when logging.
	// Note that this attribute will be used to init a global logger once, in a goroutine safe manner
	LogLevel logger.LogLevel
	// LoggerInterface (optional, log.Default()) - set the logger instance to use for logging with the sdk.
	// Note that this attribute will be used to init a global logger once, in a goroutine safe manner
	Logger logger.LoggerInterface
	// State whether session jwt should be sent to client in cookie or let the calling function handle the transfer of the jwt,
	// defaults to leaving it for calling function, use cookie if session jwt will stay small (less than 1k)
	// session cookie can grow bigger, in case of using authorization, or adding custom claims
	SessionJWTViaCookie bool
	// When using cookies, set the cookie domain here. Alternatively this can be done via the Descope console.
	SessionJWTCookieDomain string
	// When using cookies, set the cookie same site here. Default is SameSiteStrictMode, In production make sure to use SameSiteStrictMode, for security purposes.
	SessionJWTCookieSameSite http.SameSite
}

func (c *Config) setProjectID() string {
	if c.ProjectID == "" {
		if projectID := utils.GetProjectIDEnvVariable(); projectID != "" {
			c.ProjectID = projectID
		} else {
			return ""
		}
	}
	return c.ProjectID
}

func (c *Config) setPublicKey() string {
	if c.PublicKey == "" {
		if publicKey := utils.GetPublicKeyEnvVariable(); publicKey != "" {
			c.PublicKey = publicKey
		} else {
			return ""
		}
	}
	return c.PublicKey
}

func (c *Config) setManagementKey() string {
	if c.ManagementKey == "" {
		if managementKey := utils.GetManagementKeyEnvVariable(); managementKey != "" {
			c.ManagementKey = managementKey
		} else {
			return ""
		}
	}
	return c.ManagementKey
}

func (c *Config) setAuthManagementKey() string {
	if c.AuthManagementKey == "" {
		if authKey := utils.GetAuthManagementKeyEnvVariable(); authKey != "" {
			c.AuthManagementKey = authKey
		} else {
			return ""
		}
	}
	return c.AuthManagementKey
}
