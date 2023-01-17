package mgmt

import (
	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/errors"
	"github.com/descope/go-sdk/descope/internal/utils"
)

type accessKey struct {
	managementBase
}

func (a *accessKey) Create(name string, expireTime int64, roleNames []string, keyTenants []*descope.AssociatedTenant) (string, *descope.AccessKeyResponse, error) {
	if name == "" {
		return "", nil, errors.NewInvalidArgumentError("name")
	}
	body := makeCreateAccessKeyBody(name, expireTime, roleNames, keyTenants)
	res, err := a.client.DoPostRequest(api.Routes.ManagementAccessKeyCreate(), body, nil, a.conf.ManagementKey)
	if err != nil {
		return "", nil, err
	}
	return unmarshalCreatedAccessKeyResponse(res)
}

func (a *accessKey) Load(id string) (*descope.AccessKeyResponse, error) {
	if id == "" {
		return nil, errors.NewInvalidArgumentError("id")
	}
	req := &api.HTTPRequest{
		QueryParams: map[string]string{"id": id},
	}
	res, err := a.client.DoGetRequest(api.Routes.ManagementAccessKeyLoad(), req, a.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalAccessKeyResponse(res)
}

func (a *accessKey) SearchAll(tenantIDs []string) ([]*descope.AccessKeyResponse, error) {
	body := map[string]any{"tenantIds": tenantIDs}
	res, err := a.client.DoPostRequest(api.Routes.ManagementAccessKeySearchAll(), body, nil, a.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalAccessKeySearchAllResponse(res)
}

func (a *accessKey) Update(id, name string) (*descope.AccessKeyResponse, error) {
	if id == "" {
		return nil, errors.NewInvalidArgumentError("id")
	}
	if name == "" {
		return nil, errors.NewInvalidArgumentError("name")
	}
	body := map[string]any{"id": id, "name": name}
	res, err := a.client.DoPostRequest(api.Routes.ManagementAccessKeyUpdate(), body, nil, a.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalAccessKeyResponse(res)
}

func (a *accessKey) Deactivate(id string) error {
	if id == "" {
		return errors.NewInvalidArgumentError("id")
	}
	body := map[string]any{"id": id}
	_, err := a.client.DoPostRequest(api.Routes.ManagementAccessKeyDeactivate(), body, nil, a.conf.ManagementKey)
	return err
}

func (a *accessKey) Activate(id string) error {
	if id == "" {
		return errors.NewInvalidArgumentError("id")
	}
	body := map[string]any{"id": id}
	_, err := a.client.DoPostRequest(api.Routes.ManagementAccessKeyActivate(), body, nil, a.conf.ManagementKey)
	return err
}

func (a *accessKey) Delete(id string) error {
	if id == "" {
		return errors.NewInvalidArgumentError("id")
	}
	body := map[string]any{"id": id}
	_, err := a.client.DoPostRequest(api.Routes.ManagementAccessKeyDelete(), body, nil, a.conf.ManagementKey)
	return err
}

func makeCreateAccessKeyBody(name string, expireTime int64, roleNames []string, tenants []*descope.AssociatedTenant) map[string]any {
	return map[string]any{
		"name":       name,
		"expireTime": expireTime,
		"roleNames":  roleNames,
		"keyTenants": makeAssociatedTenantList(tenants),
	}
}

func unmarshalCreatedAccessKeyResponse(res *api.HTTPResponse) (string, *descope.AccessKeyResponse, error) {
	akres := struct {
		Cleartext string
		Key       *descope.AccessKeyResponse
	}{}
	err := utils.Unmarshal([]byte(res.BodyStr), &akres)
	if err != nil {
		return "", nil, err
	}
	return akres.Cleartext, akres.Key, err
}

func unmarshalAccessKeyResponse(res *api.HTTPResponse) (*descope.AccessKeyResponse, error) {
	akres := struct {
		Key *descope.AccessKeyResponse
	}{}
	err := utils.Unmarshal([]byte(res.BodyStr), &akres)
	if err != nil {
		return nil, err
	}
	return akres.Key, err
}

func unmarshalAccessKeySearchAllResponse(res *api.HTTPResponse) ([]*descope.AccessKeyResponse, error) {
	akres := struct {
		Keys []*descope.AccessKeyResponse
	}{}
	err := utils.Unmarshal([]byte(res.BodyStr), &akres)
	if err != nil {
		return nil, err
	}
	return akres.Keys, err
}
