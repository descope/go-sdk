package mgmt

import (
	"context"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/sdk"
)

type mgmtkey struct {
	managementBase
}

var _ sdk.ManagementKey = &mgmtkey{}

type mgmtKeyCreateResp struct {
	Cleartext string           `json:"cleartext,omitempty"`
	Key       *descope.MgmtKey `json:"key,omitempty"`
}

type mgmtKeyGenericResp struct {
	Key *descope.MgmtKey `json:"key,omitempty"`
}
type mgmtKeySearchResp struct {
	Keys []*descope.MgmtKey `json:"keys,omitempty"`
}
type mgmtKeyDeleteResp struct {
	Total int `json:"total,omitempty"`
}

func (r *mgmtkey) Create(ctx context.Context, name, description string, expiresIn uint64, permittedIPs []string, reBac *descope.MgmtKeyReBac) (key *descope.MgmtKey, cleartext string, err error) {
	return r.CreateWithOptions(ctx, &descope.MgmtKeyCreateOptions{
		Name:         name,
		Description:  description,
		ExpiresIn:    expiresIn,
		PermittedIPs: permittedIPs,
		ReBac:        reBac,
	})
}

func (r *mgmtkey) CreateWithOptions(ctx context.Context, options *descope.MgmtKeyCreateOptions) (key *descope.MgmtKey, cleartext string, err error) {
	if options == nil {
		return nil, "", utils.NewInvalidArgumentError("options")
	}
	if options.Name == "" {
		return nil, "", utils.NewInvalidArgumentError("name")
	}
	body := map[string]any{
		"name":         options.Name,
		"description":  options.Description,
		"expiresIn":    options.ExpiresIn,
		"permittedIps": options.PermittedIPs,
		"reBac":        options.ReBac,
	}
	if options.TrustedIssuer != nil {
		body["trustedIssuer"] = options.TrustedIssuer
	}
	resp, err := r.client.DoPutRequest(ctx, api.Routes.ManagementMgmtKeyCreate(), body, nil, "")
	if err != nil {
		return nil, "", err
	}
	res := &mgmtKeyCreateResp{}
	err = utils.Unmarshal([]byte(resp.BodyStr), res)
	if err != nil {
		return nil, "", err
	}
	return res.Key, res.Cleartext, nil
}

func (r *mgmtkey) Update(ctx context.Context, id, name, description string, permittedIPs []string, status descope.MgmtKeyStatus) (*descope.MgmtKey, error) {
	return r.UpdateWithOptions(ctx, &descope.MgmtKeyUpdateOptions{
		ID:           id,
		Name:         name,
		Description:  description,
		PermittedIPs: permittedIPs,
		Status:       status,
	})
}

func (r *mgmtkey) UpdateWithOptions(ctx context.Context, options *descope.MgmtKeyUpdateOptions) (*descope.MgmtKey, error) {
	if options == nil {
		return nil, utils.NewInvalidArgumentError("options")
	}
	if options.ID == "" {
		return nil, utils.NewInvalidArgumentError("id")
	}
	body := map[string]any{
		"id": options.ID,
		// following fields are updated on the object
		"name":         options.Name,
		"description":  options.Description,
		"permittedIps": options.PermittedIPs,
		"status":       options.Status,
	}
	if options.TrustedIssuer != nil {
		body["trustedIssuer"] = options.TrustedIssuer
	}
	resp, err := r.client.DoPatchRequest(ctx, api.Routes.ManagementMgmtKeyUpdate(), body, nil, "")
	if err != nil {
		return nil, err
	}
	res := &mgmtKeyGenericResp{}
	err = utils.Unmarshal([]byte(resp.BodyStr), res)
	if err != nil {
		return nil, err
	}
	return res.Key, err
}

func (r *mgmtkey) Get(ctx context.Context, id string) (*descope.MgmtKey, error) {
	if id == "" {
		return nil, utils.NewInvalidArgumentError("id")
	}
	req := &api.HTTPRequest{
		QueryParams: map[string]string{"id": id},
	}
	resp, err := r.client.DoGetRequest(ctx, api.Routes.ManagementMgmtKeyGet(), req, "")
	if err != nil {
		return nil, err
	}

	res := &mgmtKeyGenericResp{}
	err = utils.Unmarshal([]byte(resp.BodyStr), &res)
	if err != nil {
		return nil, err
	}
	return res.Key, nil
}

func (r *mgmtkey) Delete(ctx context.Context, ids []string) (int, error) {
	if len(ids) == 0 {
		return 0, utils.NewInvalidArgumentError("ids")
	}
	body := map[string]any{
		"ids": ids,
	}
	resp, err := r.client.DoPostRequest(ctx, api.Routes.ManagementMgmtKeyDelete(), body, nil, "")
	if err != nil {
		return 0, err
	}
	res := &mgmtKeyDeleteResp{}
	err = utils.Unmarshal([]byte(resp.BodyStr), res)
	if err != nil {
		return 0, err
	}
	return res.Total, nil
}

func (r *mgmtkey) Search(ctx context.Context, options *descope.MgmtKeySearchOptions) ([]*descope.MgmtKey, error) {
	if options == nil {
		return nil, utils.NewInvalidArgumentError("options")
	}
	resp, err := r.client.DoGetRequest(ctx, api.Routes.ManagementMgmtKeySearch(), nil, "")
	if err != nil {
		return nil, err
	}

	res := mgmtKeySearchResp{}
	err = utils.Unmarshal([]byte(resp.BodyStr), &res)
	if err != nil {
		return nil, err
	}
	return res.Keys, nil
}
