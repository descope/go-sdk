package mgmt

import (
	"context"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
)

type accessKey struct {
	managementBase
}

func (a *accessKey) Create(ctx context.Context, name string, expireTime int64, roleNames []string, keyTenants []*descope.AssociatedTenant, userID string, customClaims map[string]any, description string, permittedIPs []string) (string, *descope.AccessKeyResponse, error) {
	if name == "" {
		return "", nil, utils.NewInvalidArgumentError("name")
	}
	body := makeCreateAccessKeyBody(name, expireTime, roleNames, keyTenants, userID, customClaims, description, permittedIPs)
	res, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAccessKeyCreate(), body, nil, a.conf.ManagementKey)
	if err != nil {
		return "", nil, err
	}
	return unmarshalCreatedAccessKeyResponse(res)
}

func (a *accessKey) Load(ctx context.Context, id string) (*descope.AccessKeyResponse, error) {
	if id == "" {
		return nil, utils.NewInvalidArgumentError("id")
	}
	req := &api.HTTPRequest{
		QueryParams: map[string]string{"id": id},
	}
	res, err := a.client.DoGetRequest(ctx, api.Routes.ManagementAccessKeyLoad(), req, a.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalAccessKeyResponse(res)
}

func (a *accessKey) SearchAll(ctx context.Context, tenantIDs []string) ([]*descope.AccessKeyResponse, error) {
	body := map[string]any{"tenantIds": tenantIDs}
	res, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAccessKeySearchAll(), body, nil, a.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalAccessKeySearchAllResponse(res)
}

func (a *accessKey) Update(ctx context.Context, id, name string, description *string) (*descope.AccessKeyResponse, error) {
	if id == "" {
		return nil, utils.NewInvalidArgumentError("id")
	}
	if name == "" {
		return nil, utils.NewInvalidArgumentError("name")
	}
	body := map[string]any{"id": id, "name": name}
	if description != nil {
		body["description"] = *description
	}
	res, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAccessKeyUpdate(), body, nil, a.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalAccessKeyResponse(res)
}

func (a *accessKey) Deactivate(ctx context.Context, id string) error {
	if id == "" {
		return utils.NewInvalidArgumentError("id")
	}
	body := map[string]any{"id": id}
	_, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAccessKeyDeactivate(), body, nil, a.conf.ManagementKey)
	return err
}

func (a *accessKey) Activate(ctx context.Context, id string) error {
	if id == "" {
		return utils.NewInvalidArgumentError("id")
	}
	body := map[string]any{"id": id}
	_, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAccessKeyActivate(), body, nil, a.conf.ManagementKey)
	return err
}

func (a *accessKey) Delete(ctx context.Context, id string) error {
	if id == "" {
		return utils.NewInvalidArgumentError("id")
	}
	body := map[string]any{"id": id}
	_, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAccessKeyDelete(), body, nil, a.conf.ManagementKey)
	return err
}

func makeCreateAccessKeyBody(name string, expireTime int64, roleNames []string, tenants []*descope.AssociatedTenant, userID string, customClaims map[string]any, description string, permittedIPs []string) map[string]any {
	return map[string]any{
		"name":         name,
		"expireTime":   expireTime,
		"roleNames":    roleNames,
		"keyTenants":   makeAssociatedTenantList(tenants),
		"userId":       userID,
		"customClaims": customClaims,
		"description":  description,
		"permittedIps": permittedIPs,
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
