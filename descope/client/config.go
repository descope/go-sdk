package client

import (
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/logger"
)

// Conf - Configuration struct describes the configurational data for the authentication methods.
type Config struct {
	// ProjectID (required, "") - used to validate and authenticate against descope services.
	ProjectID string
	// PublicKey (optional, "") - used to provide a management key that's required
	// for using any of the Management APIs. If empty, this value is retrieved
	// from the DESCOPE_MANAGEMENT_KEY environement variable instead. If neither
	// values are set then any Management API call with fail.
	ManagementKey string
	// PublicKey (optional, "") - used to override or implicitly use a dedicated public key in order to decrypt and validate the JWT tokens
	// during ValidateSessionRequest(). If empty, will attempt to fetch all public keys from the specified project id.
	PublicKey string
	// DescopeBaseURL (optional, "https://api.descope.com") - override the default base URL used to communicate with descope services.
	DescopeBaseURL string
	// DefaultClient (optional, http.DefaultClient) - override the default client used to Do the actual http request.
	DefaultClient api.IHttpClient
	// CustomDefaultHeaders (optional, nil) - add custom headers to all requests used to communicate with descope services.
	CustomDefaultHeaders map[string]string
	// LogLevel (optional, LogNone) - set a log level (Debug/Info/None) for the sdk to use when logging.
	LogLevel logger.LogLevel
	// LoggerInterface (optional, log.Default()) - set the logger instance to use for logging with the sdk.
	Logger logger.LoggerInterface
	// State whether session jwt should be sent to client in cookie or let the calling function handle the transfer of the jwt,
	// defaults to leaving it for calling function, use cookie if session jwt will stay small (less than 1k)
	// session cookie can grow bigger, in case of using authorization, or adding custom claims
	SessionJWTViaCookie bool
	// When using cookies, set the cookie domain here. Alternatively this can be done via the Descope console.
	SessionJWTCookieDomain string
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
