package mgmt

import (
	"context"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
)

type tenant struct {
	managementBase
}

func (t *tenant) Create(ctx context.Context, tenantRequest *descope.TenantRequest) (id string, err error) {
	if tenantRequest == nil {
		tenantRequest = &descope.TenantRequest{}
	}
	return t.createWithID(ctx, "", tenantRequest)
}

func (t *tenant) CreateWithID(ctx context.Context, id string, tenantRequest *descope.TenantRequest) error {
	if id == "" {
		return utils.NewInvalidArgumentError("id")
	}
	if tenantRequest == nil {
		tenantRequest = &descope.TenantRequest{}
	}
	_, err := t.createWithID(ctx, id, tenantRequest)
	return err
}

func (t *tenant) createWithID(ctx context.Context, id string, tenantRequest *descope.TenantRequest) (string, error) {
	if tenantRequest.Name == "" {
		return "", utils.NewInvalidArgumentError("name")
	}
	req := makeCreateUpdateTenantRequest(id, tenantRequest)
	httpRes, err := t.client.DoPostRequest(ctx, api.Routes.ManagementTenantCreate(), req, nil, t.conf.ManagementKey)
	if err != nil {
		return "", err
	}
	res := &struct {
		ID string `json:"id"`
	}{}
	if err = utils.Unmarshal([]byte(httpRes.BodyStr), res); err != nil {
		return "", err
	}
	return res.ID, nil
}

func (t *tenant) Update(ctx context.Context, id string, tenantRequest *descope.TenantRequest) error {
	if id == "" {
		return utils.NewInvalidArgumentError("id")
	}
	if tenantRequest.Name == "" {
		return utils.NewInvalidArgumentError("name")
	}
	req := makeCreateUpdateTenantRequest(id, tenantRequest)
	_, err := t.client.DoPostRequest(ctx, api.Routes.ManagementTenantUpdate(), req, nil, t.conf.ManagementKey)
	return err
}

func (t *tenant) Delete(ctx context.Context, id string) error {
	if id == "" {
		return utils.NewInvalidArgumentError("id")
	}
	req := map[string]any{"id": id}
	_, err := t.client.DoPostRequest(ctx, api.Routes.ManagementTenantDelete(), req, nil, t.conf.ManagementKey)
	return err
}

func (t *tenant) Load(ctx context.Context, id string) (*descope.Tenant, error) {
	if id == "" {
		return nil, utils.NewInvalidArgumentError("id")
	}
	req := &api.HTTPRequest{
		QueryParams: map[string]string{"id": id},
	}
	res, err := t.client.DoGetRequest(ctx, api.Routes.ManagementTenantLoad(), req, t.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalLoadTenantResponse(res)
}

func (t *tenant) LoadAll(ctx context.Context) ([]*descope.Tenant, error) {
	res, err := t.client.DoGetRequest(ctx, api.Routes.ManagementTenantLoadAll(), nil, t.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalLoadAllTenantsResponse(res)
}

func (t *tenant) SearchAll(ctx context.Context, options *descope.TenantSearchOptions) ([]*descope.Tenant, error) {
	// Init empty options if non given
	if options == nil {
		options = &descope.TenantSearchOptions{}
	}

	req := makeSearchTenantRequest(options)
	res, err := t.client.DoPostRequest(ctx, api.Routes.ManagementTenantSearchAll(), req, nil, t.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalLoadAllTenantsResponse(res)
}

func (t *tenant) GetSettings(ctx context.Context, tenantID string) (*descope.TenantSettings, error) {
	if tenantID == "" {
		return nil, utils.NewInvalidArgumentError("tenantID")
	}
	req := &api.HTTPRequest{
		QueryParams: map[string]string{"tenantId": tenantID},
	}
	res, err := t.client.DoGetRequest(ctx, api.Routes.ManagementTenantSettings(), req, t.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalTenantSettingsResponse(res)
}

func (t *tenant) ConfigureSettings(ctx context.Context, tenantID string, settings *descope.TenantSettings) error {
	if tenantID == "" {
		return utils.NewInvalidArgumentError("tenantID")
	}
	req := map[string]any{
		"tenantId":                   tenantID,
		"selfProvisioningDomains":    settings.SelfProvisioningDomains,
		"enabled":                    settings.SessionSettingsEnabled,
		"sessionTokenExpiration":     settings.SessionTokenExpiration,
		"refreshTokenExpiration":     settings.RefreshTokenExpiration,
		"sessionTokenExpirationUnit": settings.SessionTokenExpirationUnit,
		"refreshTokenExpirationUnit": settings.RefreshTokenExpirationUnit,
		"inactivityTime":             settings.InactivityTime,
		"inactivityTimeUnit":         settings.InactivityTimeUnit,
		"enableInactivity":           settings.EnableInactivity,
		"rotateJwt":                  settings.RotateJwt,
		"domains":                    settings.Domains,
	}
	_, err := t.client.DoPostRequest(ctx, api.Routes.ManagementTenantSettings(), req, nil, t.conf.ManagementKey)
	return err
}

func makeCreateUpdateTenantRequest(id string, tenantRequest *descope.TenantRequest) map[string]any {
	return map[string]any{"id": id, "name": tenantRequest.Name, "selfProvisioningDomains": tenantRequest.SelfProvisioningDomains, "customAttributes": tenantRequest.CustomAttributes}
}

func unmarshalLoadTenantResponse(res *api.HTTPResponse) (*descope.Tenant, error) {
	var tres *descope.Tenant
	err := utils.Unmarshal([]byte(res.BodyStr), &tres)
	if err != nil {
		return nil, err
	}
	return tres, nil
}

func unmarshalLoadAllTenantsResponse(res *api.HTTPResponse) ([]*descope.Tenant, error) {
	tres := struct {
		Tenants []*descope.Tenant
	}{}
	err := utils.Unmarshal([]byte(res.BodyStr), &tres)
	if err != nil {
		return nil, err
	}
	return tres.Tenants, nil
}

func makeSearchTenantRequest(options *descope.TenantSearchOptions) map[string]any {
	return map[string]any{
		"tenantIds":                     options.IDs,
		"tenantNames":                   options.Names,
		"tenantSelfProvisioningDomains": options.SelfProvisioningDomains,
		"customAttributes":              options.CustomAttributes,
	}
}

func unmarshalTenantSettingsResponse(res *api.HTTPResponse) (*descope.TenantSettings, error) {
	var tres *struct {
		*descope.TenantSettings
		Enabled bool `json:"enabled"`
	}
	err := utils.Unmarshal([]byte(res.BodyStr), &tres)
	if err != nil {
		return nil, err
	}
	tres.TenantSettings.SessionSettingsEnabled = tres.Enabled
	return tres.TenantSettings, nil
}
