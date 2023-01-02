package mgmt

import (
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/auth"
	"github.com/descope/go-sdk/descope/errors"
	"github.com/descope/go-sdk/descope/utils"
)

type accessKey struct {
	managementBase
}

func (a *accessKey) Create(name string, expireTime int64, roleNames []string, keyTenants []*AssociatedTenant) (string, *auth.AccessKeyResponse, error) {
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

func (a *accessKey) Load(id string) (*auth.AccessKeyResponse, error) {
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

func (a *accessKey) SearchAll(tenantIDs []string) ([]*auth.AccessKeyResponse, error) {
	body := map[string]any{"tenantIds": tenantIDs}
	res, err := a.client.DoPostRequest(api.Routes.ManagementAccessKeySearchAll(), body, nil, a.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalAccessKeySearchAllResponse(res)
}

func (a *accessKey) Update(id, name string) (*auth.AccessKeyResponse, error) {
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

func makeCreateAccessKeyBody(name string, expireTime int64, roleNames []string, tenants []*AssociatedTenant) map[string]any {
	return map[string]any{
		"name":       name,
		"expireTime": expireTime,
		"roleNames":  roleNames,
		"keyTenants": makeAssociatedTenantList(tenants),
	}
}

func unmarshalCreatedAccessKeyResponse(res *api.HTTPResponse) (string, *auth.AccessKeyResponse, error) {
	akres := struct {
		Hash string
		Key  *auth.AccessKeyResponse
	}{}
	err := utils.Unmarshal([]byte(res.BodyStr), &akres)
	if err != nil {
		return "", nil, err
	}
	return akres.Hash, akres.Key, err
}

func unmarshalAccessKeyResponse(res *api.HTTPResponse) (*auth.AccessKeyResponse, error) {
	akres := struct {
		Key *auth.AccessKeyResponse
	}{}
	err := utils.Unmarshal([]byte(res.BodyStr), &akres)
	if err != nil {
		return nil, err
	}
	return akres.Key, err
}

func unmarshalAccessKeySearchAllResponse(res *api.HTTPResponse) ([]*auth.AccessKeyResponse, error) {
	akres := struct {
		Keys []*auth.AccessKeyResponse
	}{}
	err := utils.Unmarshal([]byte(res.BodyStr), &akres)
	if err != nil {
		return nil, err
	}
	return akres.Keys, err
}
