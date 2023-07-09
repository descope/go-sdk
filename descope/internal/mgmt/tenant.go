package mgmt

import (
	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
)

type tenant struct {
	managementBase
}

func (t *tenant) Create(name string, selfProvisioningDomains []string) (id string, err error) {
	return t.createWithID("", name, selfProvisioningDomains)
}

func (t *tenant) CreateWithID(id, name string, selfProvisioningDomains []string) error {
	if id == "" {
		return utils.NewInvalidArgumentError("id")
	}
	_, err := t.createWithID(id, name, selfProvisioningDomains)
	return err
}

func (t *tenant) createWithID(id, name string, selfProvisioningDomains []string) (string, error) {
	if name == "" {
		return "", utils.NewInvalidArgumentError("name")
	}
	req := makeCreateUpdateTenantRequest(id, name, selfProvisioningDomains)
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

func (t *tenant) Update(id, name string, selfProvisioningDomains []string) error {
	if id == "" {
		return utils.NewInvalidArgumentError("id")
	}
	if name == "" {
		return utils.NewInvalidArgumentError("name")
	}
	req := makeCreateUpdateTenantRequest(id, name, selfProvisioningDomains)
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

func makeCreateUpdateTenantRequest(id, name string, selfProvisioningDomains []string) map[string]any {
	return map[string]any{"id": id, "name": name, "selfProvisioningDomains": selfProvisioningDomains}
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
