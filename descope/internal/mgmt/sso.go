package mgmt

import (
	"context"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/sdk"
)

type sso struct {
	managementBase
}

var _ sdk.SSO = &sso{}

func (s *sso) LoadSettings(ctx context.Context, tenantID string, ssoID string) (*descope.SSOTenantSettingsResponse, error) {
	if tenantID == "" {
		return nil, utils.NewInvalidArgumentError("tenantID")
	}

	req := &api.HTTPRequest{
		QueryParams: map[string]string{"tenantId": tenantID},
	}
	if len(ssoID) > 0 {
		req.QueryParams["ssoId"] = ssoID
	}
	res, err := s.client.DoGetRequest(ctx, api.Routes.ManagementSSOLoadSettings(), req, s.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalSSOTenantSettingsResponse(res)
}

func (s *sso) LoadAllSettings(ctx context.Context, tenantID string) ([]*descope.SSOTenantSettingsResponse, error) {
	if tenantID == "" {
		return nil, utils.NewInvalidArgumentError("tenantID")
	}

	req := &api.HTTPRequest{
		QueryParams: map[string]string{"tenantId": tenantID},
	}
	res, err := s.client.DoGetRequest(ctx, api.Routes.ManagementSSOLoadAllSettings(), req, s.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalSSOTenantAllSettingsResponse(res)
}

func (s *sso) ConfigureSAMLSettings(ctx context.Context, tenantID string, settings *descope.SSOSAMLSettings, redirectURL string, domains []string, ssoID string) error {
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
			"idpUrl":           settings.IdpURL,
			"entityId":         settings.IdpEntityID,
			"idpCert":          settings.IdpCert,
			"roleMappings":     mappings,
			"attributeMapping": settings.AttributeMapping,
			"spACSUrl":         settings.SpACSUrl,
			"spEntityId":       settings.SpEntityID,
		},
		"redirectUrl": redirectURL,
		"domains":     domains,
	}
	if len(ssoID) > 0 {
		req["ssoId"] = ssoID
	}
	_, err := s.client.DoPostRequest(ctx, api.Routes.ManagementSSOSAMLSettings(), req, nil, s.conf.ManagementKey)
	return err
}
func (s *sso) ConfigureSAMLSettingsByMetadata(ctx context.Context, tenantID string, settings *descope.SSOSAMLSettingsByMetadata, redirectURL string, domains []string, ssoID string) error {
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
			"idpMetadataUrl":   settings.IdpMetadataURL,
			"roleMappings":     mappings,
			"attributeMapping": settings.AttributeMapping,
			"spACSUrl":         settings.SpACSUrl,
			"spEntityId":       settings.SpEntityID,
		},
		"redirectUrl": redirectURL,
		"domains":     domains,
	}
	if len(ssoID) > 0 {
		req["ssoId"] = ssoID
	}
	_, err := s.client.DoPostRequest(ctx, api.Routes.ManagementSSOSAMLSettingsByMetadata(), req, nil, s.conf.ManagementKey)
	return err
}

func (s *sso) ConfigureOIDCSettings(ctx context.Context, tenantID string, settings *descope.SSOOIDCSettings, domains []string, ssoID string) error {
	if tenantID == "" {
		return utils.NewInvalidArgumentError("tenantID")
	}

	if settings == nil {
		return utils.NewInvalidArgumentError("settings")
	}

	req := map[string]any{
		"tenantId": tenantID,
		"settings": settings,
		"domains":  domains,
	}
	if len(ssoID) > 0 {
		req["ssoId"] = ssoID
	}

	_, err := s.client.DoPostRequest(ctx, api.Routes.ManagementSSOOIDCSettings(), req, nil, s.conf.ManagementKey)
	return err
}

// * Deprecated (use LoadSettings() instead) *//
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

func (s *sso) NewSettings(ctx context.Context, tenantID string, ssoID string, displayName string) (*descope.SSOTenantSettingsResponse, error) {
	if tenantID == "" {
		return nil, utils.NewInvalidArgumentError("tenantID")
	}

	if displayName == "" {
		return nil, utils.NewInvalidArgumentError("displayName")
	}

	req := map[string]any{
		"tenantId":    tenantID,
		"ssoId":       ssoID,
		"displayName": displayName,
	}
	res, err := s.client.DoPostRequest(ctx, api.Routes.ManagementNewSSOSettings(), req, nil, s.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalSSOTenantSettingsResponse(res)
}

func (s *sso) DeleteSettings(ctx context.Context, tenantID string, ssoID string) error {
	if tenantID == "" {
		return utils.NewInvalidArgumentError("tenantID")
	}
	req := &api.HTTPRequest{
		QueryParams: map[string]string{"tenantId": tenantID},
	}
	if len(ssoID) > 0 {
		req.QueryParams["ssoId"] = ssoID
	}
	_, err := s.client.DoDeleteRequest(ctx, api.Routes.ManagementSSOSettings(), req, s.conf.ManagementKey)
	if err != nil {
		return err
	}
	return nil
}

// * Deprecated (use ConfigureSAMLSettings() instead) *//
func (s *sso) ConfigureSettings(ctx context.Context, tenantID, idpURL, idpCert, entityID, redirectURL string, domains []string) error {
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
		"domains":     domains,
	}
	_, err := s.client.DoPostRequest(ctx, api.Routes.ManagementSSOSettings(), req, nil, s.conf.ManagementKey)
	return err
}

// * Deprecated (use ConfigureSAMLSettingsByMetadata() instead) *//
func (s *sso) ConfigureMetadata(ctx context.Context, tenantID, idpMetadataURL, redirectURL string, domains []string) error {
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
		"domains":        domains,
	}
	_, err := s.client.DoPostRequest(ctx, api.Routes.ManagementSSOMetadata(), req, nil, s.conf.ManagementKey)
	return err
}

// * Deprecated (use ConfigureSAMLSettings() or ConfigureSAMLSettingsByMetadata() instead) *//
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

func unmarshalSSOTenantAllSettingsResponse(res *api.HTTPResponse) ([]*descope.SSOTenantSettingsResponse, error) {
	var ssoAllSettingsRes *descope.SSOTenantAllSettingsResponse
	err := utils.Unmarshal([]byte(res.BodyStr), &ssoAllSettingsRes)
	if err != nil {
		return nil, err
	}
	return ssoAllSettingsRes.SSOSettings, err
}
