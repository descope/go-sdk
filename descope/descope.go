package descope

import (
	"strings"

	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/auth"
	"github.com/descope/go-sdk/descope/errors"
	"github.com/descope/go-sdk/descope/logger"
	"github.com/descope/go-sdk/descope/mgmt"
	"github.com/descope/go-sdk/descope/utils"
)

// Conf - Configuration struct describes the configurational data for the authentication methods.
type Config struct {
	// ProjectID (required, "") - used to validate and authenticate against descope services.
	ProjectID string
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

// DescopeClient - The main entry point for working with the Descope SDK.
type DescopeClient struct {
	// Provides functions for authenticating users, validating sessions, working with
	// permissions and roles, etc.
	Auth auth.Authentication

	// Provides various APIs for managing a Descope project programmatically. All the
	// functions expect a valid management key as the first parameter. Management keys
	// can be generated in the Descope console.
	Management mgmt.Management

	config *Config
}

// Creates a new DescopeClient object. The value for the Descope projectID must be set
// in the DESCOPE_PROJECT_ID environment variable.
func NewDescopeClient() (*DescopeClient, error) {
	return NewDescopeClientWithConfig(&Config{})
}

// Creates a new DescopeClient object with the provided Config object. The value for
// the Descope projectID should either be provided as a field in the Config parameter
// or set in the DESCOPE_PROJECT_ID environment variable.
func NewDescopeClientWithConfig(config *Config) (*DescopeClient, error) {
	if config == nil {
		return nil, errors.NewInvalidArgumentError("config")
	}
	logger.Init(config.LogLevel, config.Logger)

	if strings.TrimSpace(config.setProjectID()) == "" {
		return nil, errors.NewValidationError("project id is missing. Make sure to add it in the Config struct or the environment variable \"%s\"", utils.EnvironmentVariableProjectID)
	}
	if config.setPublicKey() != "" {
		logger.LogInfo("provided public key is set, forcing only provided public key validation")
	}
	c := api.NewClient(api.ClientParams{BaseURL: config.DescopeBaseURL, CustomDefaultHeaders: config.CustomDefaultHeaders, DefaultClient: config.DefaultClient, ProjectID: config.ProjectID})

	authService, err := auth.NewAuth(auth.AuthParams{ProjectID: config.ProjectID, PublicKey: config.PublicKey}, c)
	if err != nil {
		return nil, err
	}
	return &DescopeClient{Auth: authService, config: config}, nil
}
