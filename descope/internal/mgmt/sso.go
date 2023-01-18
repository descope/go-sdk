package mgmt

import (
	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
)

type sso struct {
	managementBase
}

func (s *sso) ConfigureSettings(tenantID, idpURL, idpCert, entityID, redirectURL string) error {
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
	}
	_, err := s.client.DoPostRequest(api.Routes.ManagementSSOConfigure(), req, nil, s.conf.ManagementKey)
	return err
}

func (s *sso) ConfigureMetadata(tenantID, idpMetadataURL string) error {
	if tenantID == "" {
		return utils.NewInvalidArgumentError("tenantID")
	}
	if idpMetadataURL == "" {
		return utils.NewInvalidArgumentError("idpMetadataURL")
	}
	req := map[string]any{
		"tenantId":       tenantID,
		"idpMetadataURL": idpMetadataURL,
	}
	_, err := s.client.DoPostRequest(api.Routes.ManagementSSOMetadata(), req, nil, s.conf.ManagementKey)
	return err
}

func (s *sso) ConfigureMapping(tenantID string, roleMappings []*descope.RoleMapping, attributeMapping *descope.AttributeMapping) error {
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
	_, err := s.client.DoPostRequest(api.Routes.ManagementSSOMapping(), req, nil, s.conf.ManagementKey)
	return err
}
