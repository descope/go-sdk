package descope

import (
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/auth"
	"github.com/descope/go-sdk/descope/errors"
	"github.com/descope/go-sdk/descope/logger"
	"github.com/descope/go-sdk/descope/utils"
)

// Conf - Configuration struct describes the configurational data for the authentication methods.
type Config struct {
	// ProjectID (required, "") - used to validate and authenticate against descope services.
	ProjectID string
	// PublicKey (optional, "") - used to override or implicitly use a dedicated public key in order to decrypt and validate the JWT tokens
	// during ValidateSession() and ValidateSessionRequest(). If empty, will attempt to fetch all public keys from the specified project id.
	PublicKey string

	// DefaultURL (optional, "https://descope.com") - override the default base URL used to communicate with descope services.
	DefaultURL string
	// DefaultClient (optional, http.DefaultClient) - override the default client used to Do the actual http request.
	DefaultClient api.IHttpClient
	// CustomDefaultHeaders (optional, nil) - add custom headers to all requests used to communicate with descope services.
	CustomDefaultHeaders map[string]string

	// LogLevel (optional, LogNone) - set a log level (Debug/Info/None) for the sdk to use when logging.
	LogLevel logger.LogLevel
	// LoggerInterface (optional, log.Default()) - set the logger instance to use for logging with the sdk.
	Logger logger.LoggerInterface
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

type API struct {
	Auth   auth.IAuth
	config *Config
}

func NewDescopeAPI(config Config) (*API, error) {
	logger.Init(config.LogLevel, config.Logger)

	if config.setProjectID() == "" {
		return nil, errors.NewValidationError("project id is missing. Make sure to add it in the Config struct or the environment variable \"%s\"", utils.EnvironmentVariableProjectID)
	}
	if config.setPublicKey() != "" {
		logger.LogInfo("provided public key is set, forcing only provided public key validation")
	}
	c := api.NewClient(api.ClientParams{DefaultURL: config.DefaultURL, CustomDefaultHeaders: config.CustomDefaultHeaders, DefaultClient: config.DefaultClient, ProjectID: config.ProjectID})

	authService, err := auth.NewAuth(auth.AuthParams{ProjectID: config.ProjectID, PublicKey: config.PublicKey}, c)
	if err != nil {
		return nil, err
	}
	return &API{Auth: authService, config: &config}, nil
}
