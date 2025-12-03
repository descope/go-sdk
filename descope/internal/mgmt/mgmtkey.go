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
	MgmtKeys []*descope.MgmtKey `json:"mgmtKeys,omitempty"`
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
	if err != nil { // notest
		return nil, "", err
	}
	res := &createResp{}
	err = utils.Unmarshal([]byte(resp.BodyStr), res)
	return res.Key, res.Cleartext, nil
}

func (r *mgmtkey) Update(ctx context.Context, id, name, description string, expiresIn uint64, permittedIPs []string, reBac *descope.MgmtKeyReBac) (*descope.MgmtKey, error) {
	if id == "" {
		return nil, utils.NewInvalidArgumentError("id")
	}
	body := map[string]any{
		"id":           id,
		"name":         name,
		"description":  description,
		"expiresIn":    expiresIn,
		"permittedIps": permittedIPs,
		"reBac":        reBac,
	}
	resp, err := r.client.DoPatchRequest(ctx, api.Routes.ManagementMgmtKeyUpdate(), body, nil, "")
	if err != nil { // notest
		return nil, err
	}
	res := &genericResp{}
	err = utils.Unmarshal([]byte(resp.BodyStr), res)
	if err != nil { // notest
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

func (r *mgmtkey) Delete(ctx context.Context, id string) error {
	if id == "" {
		return utils.NewInvalidArgumentError("id")
	}
	body := map[string]any{
		"id": id,
	}
	_, err := r.client.DoPostRequest(ctx, api.Routes.ManagementMgmtKeyDelete(), body, nil, "")
	return err
}

func (r *mgmtkey) Search(ctx context.Context, options *descope.MgmtKeySearchOptions) ([]*descope.MgmtKey, error) {
	resp, err := r.client.DoGetRequest(ctx, api.Routes.ManagementMgmtKeySearch(), nil, "")
	if err != nil {
		return nil, err
	}

	res := searchResp{}
	err = utils.Unmarshal([]byte(resp.BodyStr), &res)
	if err != nil {
		return nil, err
	}
	return res.MgmtKeys, nil
}
