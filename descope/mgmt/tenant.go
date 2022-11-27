package mgmt

import (
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/errors"
	"github.com/descope/go-sdk/descope/utils"
)

type tenant struct {
	managementBase
}

func (t *tenant) Create(name string, selfProvisioningDomains []string) (id string, err error) {
	return t.createWithID("", name, selfProvisioningDomains)
}

func (t *tenant) CreateWithID(id, name string, selfProvisioningDomains []string) error {
	if id == "" {
		return errors.NewInvalidArgumentError("id")
	}
	_, err := t.createWithID(id, name, selfProvisioningDomains)
	return err
}

func (t *tenant) createWithID(id, name string, selfProvisioningDomains []string) (string, error) {
	if name == "" {
		return "", errors.NewInvalidArgumentError("name")
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
		return errors.NewInvalidArgumentError("id")
	}
	if name == "" {
		return errors.NewInvalidArgumentError("name")
	}
	req := makeCreateUpdateTenantRequest(id, name, selfProvisioningDomains)
	_, err := t.client.DoPostRequest(api.Routes.ManagementTenantUpdate(), req, nil, t.conf.ManagementKey)
	return err
}

func (t *tenant) Delete(id string) error {
	if id == "" {
		return errors.NewInvalidArgumentError("id")
	}
	req := map[string]any{"id": id}
	_, err := t.client.DoPostRequest(api.Routes.ManagementTenantDelete(), req, nil, t.conf.ManagementKey)
	return err
}

func makeCreateUpdateTenantRequest(id, name string, selfProvisioningDomains []string) map[string]any {
	return map[string]any{"id": id, "name": name, "selfProvisioningDomains": selfProvisioningDomains}
}
