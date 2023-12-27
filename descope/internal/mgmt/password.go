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

func (s *password) GetSettings(ctx context.Context, tenantID string) (*descope.PasswordSettingsResponse, error) {
	req := &api.HTTPRequest{
		QueryParams: map[string]string{"tenantId": tenantID},
	}
	res, err := s.client.DoGetRequest(ctx, api.Routes.ManagementPasswordSettings(), req, s.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalPasswordSettingsResponse(res)
}

func (s *password) ConfigureSettings(ctx context.Context, tenantID string, enabled bool, minLength int, lowercase, uppercase, number, nonNumber, expiration bool, expirationWeeks int, reuse bool, reuseAmount int, lock bool, lockAttempts int, emailServiceProvider, emailSubject, emailBody, emailBodyPlainText string, useEmailBodyPlainText bool) error {
	req := map[string]any{
		"tenantId":              tenantID,
		"enabled":               enabled,
		"minLength":             minLength,
		"lowercase":             lowercase,
		"uppercase":             uppercase,
		"number":                number,
		"nonAlphanumeric":       nonNumber,
		"expiration":            expiration,
		"expirationWeeks":       expirationWeeks,
		"reuse":                 reuse,
		"reuseAmount":           reuseAmount,
		"lock":                  lock,
		"lockAttempts":          lockAttempts,
		"emailServiceProvider":  emailServiceProvider,
		"emailSubject":          emailSubject,
		"emailBody":             emailBody,
		"emailBodyPlainText":    emailBodyPlainText,
		"useEmailBodyPlainText": useEmailBodyPlainText,
	}
	_, err := s.client.DoPostRequest(ctx, api.Routes.ManagementPasswordSettings(), req, nil, s.conf.ManagementKey)
	return err
}

func unmarshalPasswordSettingsResponse(res *api.HTTPResponse) (*descope.PasswordSettingsResponse, error) {
	var passwordSettingsRes *descope.PasswordSettingsResponse
	err := utils.Unmarshal([]byte(res.BodyStr), &passwordSettingsRes)
	if err != nil {
		return nil, err
	}
	return passwordSettingsRes, err
}
