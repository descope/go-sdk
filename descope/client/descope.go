package client

import (
	"strings"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/errors"
	"github.com/descope/go-sdk/descope/internal/auth"
	"github.com/descope/go-sdk/descope/internal/mgmt"
	"github.com/descope/go-sdk/descope/logger"
	"github.com/descope/go-sdk/descope/sdk"
)

// DescopeClient - The main entry point for working with the Descope SDK.
type DescopeClient struct {
	// Provides functions for authenticating users, validating sessions, working with
	// permissions and roles, etc.
	Auth sdk.Authentication

	// Provides functions for managing a Descope project programmatically. A management key
	// must be provided in the Config object or by setting the DESCOPE_MANAGEMENT_KEY
	// environment variable. Management keys can be generated in the Descope console.
	Management sdk.Management

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
		return nil, errors.NewValidationError("project id is missing, make sure to add it in the Config struct or the environment variable \"%s\"", descope.EnvironmentVariableProjectID)
	}
	if config.setPublicKey() != "" {
		logger.LogInfo("provided public key is set, forcing only provided public key validation")
	}
	config.setManagementKey()

	c := api.NewClient(api.ClientParams{BaseURL: config.DescopeBaseURL, CustomDefaultHeaders: config.CustomDefaultHeaders, DefaultClient: config.DefaultClient, ProjectID: config.ProjectID})

	authService, err := auth.NewAuth(auth.AuthParams{ProjectID: config.ProjectID, PublicKey: config.PublicKey, SessionJWTViaCookie: config.SessionJWTViaCookie}, c)
	if err != nil {
		return nil, err
	}

	managementService := mgmt.NewManagement(mgmt.ManagementParams{ProjectID: config.ProjectID, ManagementKey: config.ManagementKey}, c)

	return &DescopeClient{Auth: authService, Management: managementService, config: config}, nil
}
