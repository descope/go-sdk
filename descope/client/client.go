package client

import (
	"context"
	"time"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/auth"
	"github.com/descope/go-sdk/descope/internal/mgmt"
	"github.com/descope/go-sdk/descope/internal/utils"
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
func New() (*DescopeClient, error) {
	return NewWithConfig(&Config{})
}

// Creates a new DescopeClient object with the provided Config object. The value for
// the Descope projectID should either be provided as a field in the Config parameter
// or set in the DESCOPE_PROJECT_ID environment variable.
func NewWithConfig(config *Config) (*DescopeClient, error) {
	if config == nil {
		return nil, utils.NewInvalidArgumentError("config")
	}
	logger.Init(config.LogLevel, config.Logger)

	if v := config.setProjectID(); v == "" && !config.AllowEmptyProjectID {
		return nil, descope.ErrMissingProjectID.WithMessage("Project ID is missing, make sure to add it in the Config struct or the environment variable \"%s\"", descope.EnvironmentVariableProjectID)
	}
	if config.setPublicKey() != "" {
		logger.LogInfo("Provided public key is set, forcing only provided public key validation")
	}
	config.setManagementKey()
	config.setAuthManagementKey()

	// Auth initialzes a client with the auth management key if provided
	authClient := api.NewClient(api.ClientParams{
		ProjectID:            config.ProjectID,
		BaseURL:              config.DescopeBaseURL,
		ManagementKey:        config.AuthManagementKey,
		DefaultClient:        config.DefaultClient,
		CustomDefaultHeaders: config.CustomDefaultHeaders,
		ExternalRequestID:    config.ExternalRequestID,
		CertificateVerify:    config.CertificateVerify,
		RequestTimeout:       config.RequestTimeout,
	})
	conf := &auth.AuthParams{
		ProjectID:           config.ProjectID,
		PublicKey:           config.PublicKey,
		SessionJWTViaCookie: config.SessionJWTViaCookie,
		CookieDomain:        config.SessionJWTCookieDomain,
		CookieSameSite:      config.SessionJWTCookieSameSite,
		RefreshCookieName:   config.RefreshCookieName,
		SessionCookieName:   config.SessionCookieName,
		JWTLeeway:           config.JWTLeeway,
	}
	provider := auth.NewProvider(authClient, conf)
	authService, err := auth.NewAuthWithProvider(*conf, provider, authClient, config.RequestTokensProvider)
	if err != nil {
		return nil, err
	}

	// Managament initializes its own client with the management key
	mgmtClient := api.NewClient(api.ClientParams{
		ProjectID:            config.ProjectID,
		BaseURL:              config.DescopeBaseURL,
		ManagementKey:        config.ManagementKey,
		DefaultClient:        config.DefaultClient,
		CustomDefaultHeaders: config.CustomDefaultHeaders,
		ExternalRequestID:    config.ExternalRequestID,
		CertificateVerify:    config.CertificateVerify,
		RequestTimeout:       config.RequestTimeout,
	})

	if config.ManagementKey != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if rateLimitTier, err := mgmtClient.FetchLicense(ctx); err != nil {
			logger.LogInfo("License handshake failed, continuing without header: %v", err)
		} else {
			mgmtClient.SetRateLimitTier(rateLimitTier)
		}
	}

	managementService := mgmt.NewManagement(mgmt.ManagementParams{ProjectID: config.ProjectID, FGACacheURL: config.FGACacheURL}, provider, mgmtClient)

	return &DescopeClient{Auth: authService, Management: managementService, config: config}, nil
}
