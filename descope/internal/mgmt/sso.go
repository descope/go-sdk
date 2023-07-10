package mgmt

import (
	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
)

type sso struct {
	managementBase
}

func (s *sso) GetSettings(tenantID string) (*descope.SSOSettingsResponse, error) {
	if tenantID == "" {
		return nil, utils.NewInvalidArgumentError("tenantID")
	}
	req := &api.HTTPRequest{
		QueryParams: map[string]string{"tenantId": tenantID},
	}
	res, err := s.client.DoGetRequest(api.Routes.ManagementSSOSettings(), req, s.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalSSOSettingsResponse(res)
}

func (s *sso) DeleteSettings(tenantID string) error {
	if tenantID == "" {
		return utils.NewInvalidArgumentError("tenantID")
	}
	req := &api.HTTPRequest{
		QueryParams: map[string]string{"tenantId": tenantID},
	}
	_, err := s.client.DoDeleteRequest(api.Routes.ManagementSSOSettings(), req, s.conf.ManagementKey)
	if err != nil {
		return err
	}
	return nil
}

func (s *sso) ConfigureSettings(tenantID, idpURL, idpCert, entityID, redirectURL, domain string) error {
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
	_, err := s.client.DoPostRequest(api.Routes.ManagementSSOSettings(), req, nil, s.conf.ManagementKey)
	return err
}

func (s *sso) ConfigureMetadata(tenantID, idpMetadataURL, redirectURL, domain string) error {
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

func unmarshalSSOSettingsResponse(res *api.HTTPResponse) (*descope.SSOSettingsResponse, error) {
	var ssoSettingsRes *descope.SSOSettingsResponse
	err := utils.Unmarshal([]byte(res.BodyStr), &ssoSettingsRes)
	if err != nil {
		return nil, err
	}
	return ssoSettingsRes, err
}
