package mgmt

import (
	"context"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
)

type password struct {
	managementBase
}

func (s *password) GetSettings(ctx context.Context, tenantID string) (*descope.PasswordSettings, error) {
	req := &api.HTTPRequest{
		QueryParams: map[string]string{"tenantId": tenantID},
	}
	res, err := s.client.DoGetRequest(ctx, api.Routes.ManagementPasswordSettings(), req, s.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalPasswordSettingsResponse(res)
}

func (s *password) ConfigureSettings(ctx context.Context, tenantID string, passwordSettings *descope.PasswordSettings) error {
	req := map[string]any{
		"tenantId":        tenantID,
		"enabled":         passwordSettings.Enabled,
		"minLength":       passwordSettings.MinLength,
		"lowercase":       passwordSettings.Lowercase,
		"uppercase":       passwordSettings.Uppercase,
		"number":          passwordSettings.Number,
		"nonAlphanumeric": passwordSettings.NonAlphanumeric,
		"expiration":      passwordSettings.Expiration,
		"expirationWeeks": passwordSettings.ExpirationWeeks,
		"reuse":           passwordSettings.Reuse,
		"reuseAmount":     passwordSettings.ReuseAmount,
		"lock":            passwordSettings.Lock,
		"lockAttempts":    passwordSettings.LockAttempts,
	}
	_, err := s.client.DoPostRequest(ctx, api.Routes.ManagementPasswordSettings(), req, nil, s.conf.ManagementKey)
	return err
}

func unmarshalPasswordSettingsResponse(res *api.HTTPResponse) (*descope.PasswordSettings, error) {
	var passwordSettingsRes *descope.PasswordSettings
	err := utils.Unmarshal([]byte(res.BodyStr), &passwordSettingsRes)
	if err != nil {
		return nil, err
	}
	return passwordSettingsRes, err
}
