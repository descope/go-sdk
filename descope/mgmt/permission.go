package mgmt

import (
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/auth"
	"github.com/descope/go-sdk/descope/errors"
	"github.com/descope/go-sdk/descope/utils"
)

type permission struct {
	managementBase
}

func (p *permission) Create(name, description string) error {
	if name == "" {
		return errors.NewInvalidArgumentError("name")
	}
	body := map[string]any{
		"name":        name,
		"description": description,
	}
	_, err := p.client.DoPostRequest(api.Routes.ManagementPermissionCreate(), body, nil, p.conf.ManagementKey)
	return err
}

func (p *permission) Update(name, newName, description string) error {
	if name == "" {
		return errors.NewInvalidArgumentError("name")
	}
	if newName == "" {
		return errors.NewInvalidArgumentError("newName")
	}
	body := map[string]any{
		"name":        name,
		"newName":     newName,
		"description": description,
	}
	_, err := p.client.DoPostRequest(api.Routes.ManagementPermissionUpdate(), body, nil, p.conf.ManagementKey)
	return err
}

func (p *permission) Delete(name string) error {
	if name == "" {
		return errors.NewInvalidArgumentError("name")
	}
	body := map[string]any{"name": name}
	_, err := p.client.DoPostRequest(api.Routes.ManagementPermissionDelete(), body, nil, p.conf.ManagementKey)
	return err
}

func (p *permission) LoadAll() ([]*auth.Permission, error) {
	res, err := p.client.DoGetRequest(api.Routes.ManagementPermissionLoadAll(), nil, p.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalPermissionsLoadAllResponse(res)
}

func unmarshalPermissionsLoadAllResponse(res *api.HTTPResponse) ([]*auth.Permission, error) {
	pres := struct {
		Permissions []*auth.Permission
	}{}
	err := utils.Unmarshal([]byte(res.BodyStr), &pres)
	if err != nil {
		return nil, err
	}
	return pres.Permissions, err
}
