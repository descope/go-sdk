package mgmt

import (
	"context"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
)

type sso struct {
	managementBase
}

func (s *sso) LoadSettings(ctx context.Context, tenantID string) (*descope.SSOTenantSettingsResponse, error) {
	if tenantID == "" {
		return nil, utils.NewInvalidArgumentError("tenantID")
	}

	req := &api.HTTPRequest{
		QueryParams: map[string]string{"tenantId": tenantID},
	}
	res, err := s.client.DoGetRequest(ctx, api.Routes.ManagementSSOLoadSettings(), req, s.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalSSOTenantSettingsResponse(res)
}

func (s *sso) ConfigureSAMLSettings(ctx context.Context, tenantID string, settings *descope.SSOSAMLSettings, redirectURL string, domain string) error {
	if tenantID == "" {
		return utils.NewInvalidArgumentError("tenantID")
	}

	if settings == nil {
		return utils.NewInvalidArgumentError("settings")
	}

	if settings.IdpURL == "" {
		return utils.NewInvalidArgumentError("idpURL")
	}

	if settings.IdpCert == "" {
		return utils.NewInvalidArgumentError("idpCert")
	}

	if settings.IdpEntityID == "" {
		return utils.NewInvalidArgumentError("idpEntityID")
	}

	mappings := []map[string]any{}
	for i := range settings.RoleMappings {
		mappings = append(mappings, map[string]any{
			"groups":   settings.RoleMappings[i].Groups,
			"roleName": settings.RoleMappings[i].Role,
		})
	}

	req := map[string]any{
		"tenantId": tenantID,
		"settings": map[string]any{
			"idpURL":           settings.IdpURL,
			"entityId":         settings.IdpEntityID,
			"idpCert":          settings.IdpCert,
			"roleMappings":     mappings,
			"attributeMapping": settings.AttributeMapping,
		},
		"redirectURL": redirectURL,
		"domain":      domain,
	}
	_, err := s.client.DoPostRequest(ctx, api.Routes.ManagementSSOSAMLSettings(), req, nil, s.conf.ManagementKey)
	return err
}
func (s *sso) ConfigureSAMLSettingsByMetadata(ctx context.Context, tenantID string, settings *descope.SSOSAMLSettingsByMetadata, redirectURL string, domain string) error {
	if tenantID == "" {
		return utils.NewInvalidArgumentError("tenantID")
	}

	if settings == nil {
		return utils.NewInvalidArgumentError("settings")
	}

	if settings.IdpMetadataURL == "" {
		return utils.NewInvalidArgumentError("idpMetadataURL")
	}

	mappings := []map[string]any{}
	for i := range settings.RoleMappings {
		mappings = append(mappings, map[string]any{
			"groups":   settings.RoleMappings[i].Groups,
			"roleName": settings.RoleMappings[i].Role,
		})
	}

	req := map[string]any{
		"tenantId": tenantID,
		"settings": map[string]any{
			"idpMetadataURL":   settings.IdpMetadataURL,
			"roleMappings":     mappings,
			"attributeMapping": settings.AttributeMapping,
		},
		"redirectURL": redirectURL,
		"domain":      domain,
	}
	_, err := s.client.DoPostRequest(ctx, api.Routes.ManagementSSOSAMLSettingsByMetadata(), req, nil, s.conf.ManagementKey)
	return err
}

func (s *sso) ConfigureOIDCSettings(ctx context.Context, tenantID string, settings *descope.SSOOIDCSettings, redirectURL string, domain string) error {
	if tenantID == "" {
		return utils.NewInvalidArgumentError("tenantID")
	}

	if settings == nil {
		return utils.NewInvalidArgumentError("settings")
	}

	req := map[string]any{
		"tenantId":    tenantID,
		"settings":    settings,
		"redirectURL": redirectURL,
		"domain":      domain,
	}

	_, err := s.client.DoPostRequest(ctx, api.Routes.ManagementSSOOIDCSettings(), req, nil, s.conf.ManagementKey)
	return err
}

func (s *sso) GetSettings(ctx context.Context, tenantID string) (*descope.SSOSettingsResponse, error) {
	if tenantID == "" {
		return nil, utils.NewInvalidArgumentError("tenantID")
	}
	req := &api.HTTPRequest{
		QueryParams: map[string]string{"tenantId": tenantID},
	}
	res, err := s.client.DoGetRequest(ctx, api.Routes.ManagementSSOSettings(), req, s.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalSSOSettingsResponse(res)
}

func (s *sso) DeleteSettings(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return utils.NewInvalidArgumentError("tenantID")
	}
	req := &api.HTTPRequest{
		QueryParams: map[string]string{"tenantId": tenantID},
	}
	_, err := s.client.DoDeleteRequest(ctx, api.Routes.ManagementSSOSettings(), req, s.conf.ManagementKey)
	if err != nil {
		return err
	}
	return nil
}

func (s *sso) ConfigureSettings(ctx context.Context, tenantID, idpURL, idpCert, entityID, redirectURL, domain string) error {
	if tenantID == "" {
		return utils.NewInvalidArgumentError("tenantID")
	}
	if idpURL == "" {
		return utils.NewInvalidArgumentError("idpURL")
	}
	if idpCert == "" {
		return utils.NewInvalidArgumentError("idpCert")
	}
	if entityID == "" {
		return utils.NewInvalidArgumentError("entityID")
	}
	req := map[string]any{
		"tenantId":    tenantID,
		"idpURL":      idpURL,
		"idpCert":     idpCert,
		"entityId":    entityID,
		"redirectURL": redirectURL,
		"domain":      domain,
	}
	_, err := s.client.DoPostRequest(ctx, api.Routes.ManagementSSOSettings(), req, nil, s.conf.ManagementKey)
	return err
}

func (s *sso) ConfigureMetadata(ctx context.Context, tenantID, idpMetadataURL, redirectURL, domain string) error {
	if tenantID == "" {
		return utils.NewInvalidArgumentError("tenantID")
	}
	if idpMetadataURL == "" {
		return utils.NewInvalidArgumentError("idpMetadataURL")
	}
	req := map[string]any{
		"tenantId":       tenantID,
		"idpMetadataURL": idpMetadataURL,
		"redirectURL":    redirectURL,
		"domain":         domain,
	}
	_, err := s.client.DoPostRequest(ctx, api.Routes.ManagementSSOMetadata(), req, nil, s.conf.ManagementKey)
	return err
}

func (s *sso) ConfigureMapping(ctx context.Context, tenantID string, roleMappings []*descope.RoleMapping, attributeMapping *descope.AttributeMapping) error {
	if tenantID == "" {
		return utils.NewInvalidArgumentError("tenantID")
	}
	mappings := []map[string]any{}
	for i := range roleMappings {
		mappings = append(mappings, map[string]any{
			"groups":   roleMappings[i].Groups,
			"roleName": roleMappings[i].Role,
		})
	}
	req := map[string]any{
		"tenantId":         tenantID,
		"roleMappings":     mappings,
		"attributeMapping": attributeMapping,
	}
	_, err := s.client.DoPostRequest(ctx, api.Routes.ManagementSSOMapping(), req, nil, s.conf.ManagementKey)
	return err
}

func unmarshalSSOSettingsResponse(res *api.HTTPResponse) (*descope.SSOSettingsResponse, error) {
	var ssoSettingsRes *descope.SSOSettingsResponse
	err := utils.Unmarshal([]byte(res.BodyStr), &ssoSettingsRes)
	if err != nil {
		return nil, err
	}
	return ssoSettingsRes, err
}

func unmarshalSSOTenantSettingsResponse(res *api.HTTPResponse) (*descope.SSOTenantSettingsResponse, error) {
	var ssoSettingsRes *descope.SSOTenantSettingsResponse
	err := utils.Unmarshal([]byte(res.BodyStr), &ssoSettingsRes)
	if err != nil {
		return nil, err
	}
	return ssoSettingsRes, err
}
