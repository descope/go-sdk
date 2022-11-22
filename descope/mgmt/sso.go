package mgmt

import (
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/errors"
)

type sso struct {
	managementBase
}

func (s *sso) ConfigureSettings(managementKey, tenantID string, enabled bool, idpURL, idpCert, entityID, redirectURL string) error {
	if tenantID == "" {
		return errors.NewInvalidArgumentError("tenantID")
	}
	if idpURL == "" {
		return errors.NewInvalidArgumentError("idpURL")
	}
	if idpCert == "" {
		return errors.NewInvalidArgumentError("idpCert")
	}
	if entityID == "" {
		return errors.NewInvalidArgumentError("entityID")
	}
	req := map[string]any{
		"tenantId":    tenantID,
		"enabled":     enabled,
		"idpURL":      idpURL,
		"idpCert":     idpCert,
		"entityId":    entityID,
		"redirectURL": redirectURL,
	}
	_, err := s.client.DoPostRequest(api.Routes.ManagementSSOConfigure(), req, nil, managementKey)
	return err
}

func (s *sso) ConfigureMetadata(managementKey, tenantID string, enabled bool, idpMetadataURL string) error {
	if tenantID == "" {
		return errors.NewInvalidArgumentError("tenantID")
	}
	if idpMetadataURL == "" {
		return errors.NewInvalidArgumentError("idpMetadataURL")
	}
	req := map[string]any{
		"tenantId":       tenantID,
		"enabled":        enabled,
		"idpMetadataURL": idpMetadataURL,
	}
	_, err := s.client.DoPostRequest(api.Routes.ManagementSSOMetadata(), req, nil, managementKey)
	return err
}

func (s *sso) ConfigureRoleMapping(managementKey, tenantID string, roleMappings []RoleMapping) error {
	if tenantID == "" {
		return errors.NewInvalidArgumentError("tenantID")
	}
	mappings := []map[string]any{}
	for i := range roleMappings {
		mappings = append(mappings, map[string]any{
			"groups":   roleMappings[i].Groups,
			"roleName": roleMappings[i].Role,
		})
	}
	req := map[string]any{
		"tenantId":    tenantID,
		"roleMapping": mappings,
	}
	_, err := s.client.DoPostRequest(api.Routes.ManagementSSORoleMapping(), req, nil, managementKey)
	return err
}
