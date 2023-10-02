package mgmt

import (
	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
)

type tenant struct {
	managementBase
}

func (t *tenant) Create(tenantRequest *descope.TenantRequest) (id string, err error) {
	if tenantRequest == nil {
		tenantRequest = &descope.TenantRequest{}
	}
	return t.createWithID("", tenantRequest)
}

func (t *tenant) CreateWithID(id string, tenantRequest *descope.TenantRequest) error {
	if id == "" {
		return utils.NewInvalidArgumentError("id")
	}
	if tenantRequest == nil {
		tenantRequest = &descope.TenantRequest{}
	}
	_, err := t.createWithID(id, tenantRequest)
	return err
}

func (t *tenant) createWithID(id string, tenantRequest *descope.TenantRequest) (string, error) {
	if tenantRequest.Name == "" {
		return "", utils.NewInvalidArgumentError("name")
	}
	req := makeCreateUpdateTenantRequest(id, tenantRequest)
	httpRes, err := t.client.DoPostRequest(api.Routes.ManagementTenantCreate(), req, nil, t.conf.ManagementKey)
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

func (t *tenant) Update(id string, tenantRequest *descope.TenantRequest) error {
	if id == "" {
		return utils.NewInvalidArgumentError("id")
	}
	if tenantRequest.Name == "" {
		return utils.NewInvalidArgumentError("name")
	}
	req := makeCreateUpdateTenantRequest(id, tenantRequest)
	_, err := t.client.DoPostRequest(api.Routes.ManagementTenantUpdate(), req, nil, t.conf.ManagementKey)
	return err
}

func (t *tenant) Delete(id string) error {
	if id == "" {
		return utils.NewInvalidArgumentError("id")
	}
	req := map[string]any{"id": id}
	_, err := t.client.DoPostRequest(api.Routes.ManagementTenantDelete(), req, nil, t.conf.ManagementKey)
	return err
}

func (t *tenant) Load(id string) (*descope.Tenant, error) {
	if id == "" {
		return nil, utils.NewInvalidArgumentError("id")
	}
	req := &api.HTTPRequest{
		QueryParams: map[string]string{"id": id},
	}
	res, err := t.client.DoGetRequest(api.Routes.ManagementTenantLoad(), req, t.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalLoadTenantResponse(res)
}

func (t *tenant) LoadAll() ([]*descope.Tenant, error) {
	res, err := t.client.DoGetRequest(api.Routes.ManagementTenantLoadAll(), nil, t.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalLoadAllTenantsResponse(res)
}

func (t *tenant) SearchAll(options *descope.TenantSearchOptions) ([]*descope.Tenant, error) {
	// Init empty options if non given
	if options == nil {
		options = &descope.TenantSearchOptions{}
	}

	req := makeSearchTenantRequest(options)
	res, err := t.client.DoPostRequest(api.Routes.ManagementTenantSearchAll(), req, nil, t.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalLoadAllTenantsResponse(res)
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
