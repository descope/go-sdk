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

type createResp struct {
	Cleartext string           `json:"cleartext,omitempty"`
	Key       *descope.MgmtKey `json:"key,omitempty"`
}

type genericResp struct {
	Key *descope.MgmtKey `json:"key,omitempty"`
}
type searchResp struct {
	Keys []*descope.MgmtKey `json:"keys,omitempty"`
}
type deleteResp struct {
	Total int `json:"total,omitempty"`
}

func (r *mgmtkey) Create(ctx context.Context, name, description string, expiresIn uint64, permittedIPs []string, reBac *descope.MgmtKeyReBac) (key *descope.MgmtKey, cleartext string, err error) {
	if name == "" {
		return nil, "", utils.NewInvalidArgumentError("name")
	}
	body := map[string]any{
		"name":         name,
		"description":  description,
		"expiresIn":    expiresIn,
		"permittedIps": permittedIPs,
		"reBac":        reBac,
	}
	resp, err := r.client.DoPutRequest(ctx, api.Routes.ManagementMgmtKeyCreate(), body, nil, "")
	if err != nil {
		return nil, "", err
	}
	res := &createResp{}
	err = utils.Unmarshal([]byte(resp.BodyStr), res)
	if err != nil {
		return nil, "", err
	}
	return res.Key, res.Cleartext, nil
}

func (r *mgmtkey) Update(ctx context.Context, id, name, description string, permittedIPs []string, status descope.MgmtKeyStatus) (*descope.MgmtKey, error) {
	if id == "" {
		return nil, utils.NewInvalidArgumentError("id")
	}
	body := map[string]any{
		"id": id,
		// to be updated
		"name":         name,
		"description":  description,
		"permittedIps": permittedIPs,
		"status":       status,
	}
	resp, err := r.client.DoPatchRequest(ctx, api.Routes.ManagementMgmtKeyUpdate(), body, nil, "")
	if err != nil {
		return nil, err
	}
	res := &genericResp{}
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

	res := &genericResp{}
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
	res := &deleteResp{}
	err = utils.Unmarshal([]byte(resp.BodyStr), res)
	if err != nil {
		return 0, err
	}
	return res.Total, err
}

func (r *mgmtkey) Search(ctx context.Context, options *descope.MgmtKeySearchOptions) ([]*descope.MgmtKey, error) {
	if options == nil {
		return nil, utils.NewInvalidArgumentError("options")
	}
	resp, err := r.client.DoGetRequest(ctx, api.Routes.ManagementMgmtKeySearch(), nil, "")
	if err != nil {
		return nil, err
	}

	res := searchResp{}
	err = utils.Unmarshal([]byte(resp.BodyStr), &res)
	if err != nil {
		return nil, err
	}
	return res.Keys, nil
}
