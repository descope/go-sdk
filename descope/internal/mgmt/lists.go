package mgmt

import (
	"context"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/sdk"
)

type lists struct {
	managementBase
}

var _ sdk.List = &lists{}

func (l *lists) Create(ctx context.Context, request *descope.ListRequest) (*descope.List, error) {
	if request == nil {
		return nil, utils.NewInvalidArgumentError("request")
	}
	if request.Name == "" {
		return nil, utils.NewInvalidArgumentError("name")
	}
	if request.Type == "" {
		return nil, utils.NewInvalidArgumentError("type")
	}
	res, err := l.client.DoPostRequest(ctx, api.Routes.ManagementListCreate(), request, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalListResponse(res)
}

func (l *lists) Update(ctx context.Context, id string, request *descope.ListRequest) (*descope.List, error) {
	if id == "" {
		return nil, utils.NewInvalidArgumentError("id")
	}
	if request == nil {
		return nil, utils.NewInvalidArgumentError("request")
	}
	if request.Name == "" {
		return nil, utils.NewInvalidArgumentError("name")
	}
	if request.Type == "" {
		return nil, utils.NewInvalidArgumentError("type")
	}
	req := &descope.ListUpdateRequest{
		ID:          id,
		Name:        request.Name,
		Description: request.Description,
		Type:        request.Type,
		Data:        request.Data,
	}
	res, err := l.client.DoPostRequest(ctx, api.Routes.ManagementListUpdate(), req, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalListResponse(res)
}

func (l *lists) Delete(ctx context.Context, id string) error {
	if id == "" {
		return utils.NewInvalidArgumentError("id")
	}
	req := &descope.ListIDRequest{ID: id}
	_, err := l.client.DoPostRequest(ctx, api.Routes.ManagementListDelete(), req, nil, "")
	return err
}

func (l *lists) Load(ctx context.Context, id string) (*descope.List, error) {
	if id == "" {
		return nil, utils.NewInvalidArgumentError("id")
	}
	res, err := l.client.DoGetRequest(ctx, api.Routes.ManagementListLoad(id), nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalListResponse(res)
}

func (l *lists) LoadByName(ctx context.Context, name string) (*descope.List, error) {
	if name == "" {
		return nil, utils.NewInvalidArgumentError("name")
	}
	res, err := l.client.DoGetRequest(ctx, api.Routes.ManagementListLoadByName(name), nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalListResponse(res)
}

func (l *lists) LoadAll(ctx context.Context) ([]*descope.List, error) {
	res, err := l.client.DoGetRequest(ctx, api.Routes.ManagementListLoadAll(), nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalListsResponse(res)
}

func (l *lists) Import(ctx context.Context, lists []*descope.List) error {
	if lists == nil {
		return utils.NewInvalidArgumentError("lists")
	}
	req := &descope.ListImportRequest{Lists: lists}
	_, err := l.client.DoPostRequest(ctx, api.Routes.ManagementListImport(), req, nil, "")
	return err
}

func (l *lists) AddIPs(ctx context.Context, id string, ips []string) error {
	if id == "" {
		return utils.NewInvalidArgumentError("id")
	}
	if ips == nil {
		return utils.NewInvalidArgumentError("ips")
	}
	req := &descope.ListIPsRequest{
		ID:  id,
		IPs: ips,
	}
	_, err := l.client.DoPostRequest(ctx, api.Routes.ManagementListAddIPs(), req, nil, "")
	return err
}

func (l *lists) RemoveIPs(ctx context.Context, id string, ips []string) error {
	if id == "" {
		return utils.NewInvalidArgumentError("id")
	}
	if ips == nil {
		return utils.NewInvalidArgumentError("ips")
	}
	req := &descope.ListIPsRequest{
		ID:  id,
		IPs: ips,
	}
	_, err := l.client.DoPostRequest(ctx, api.Routes.ManagementListRemoveIPs(), req, nil, "")
	return err
}

func (l *lists) CheckIP(ctx context.Context, id string, ip string) (bool, error) {
	if id == "" {
		return false, utils.NewInvalidArgumentError("id")
	}
	if ip == "" {
		return false, utils.NewInvalidArgumentError("ip")
	}
	req := &descope.ListCheckIPRequest{
		ID: id,
		IP: ip,
	}
	res, err := l.client.DoPostRequest(ctx, api.Routes.ManagementListCheckIP(), req, nil, "")
	if err != nil {
		return false, err
	}

	var checkRes struct {
		Exists bool `json:"exists"`
	}
	if err := utils.Unmarshal([]byte(res.BodyStr), &checkRes); err != nil {
		return false, err
	}
	return checkRes.Exists, nil
}

func (l *lists) Clear(ctx context.Context, id string) error {
	if id == "" {
		return utils.NewInvalidArgumentError("id")
	}
	req := &descope.ListIDRequest{ID: id}
	_, err := l.client.DoPostRequest(ctx, api.Routes.ManagementListClear(), req, nil, "")
	return err
}

func unmarshalListResponse(res *api.HTTPResponse) (*descope.List, error) {
	var listRes struct {
		List *descope.List `json:"list"`
	}
	if err := utils.Unmarshal([]byte(res.BodyStr), &listRes); err != nil {
		return nil, err
	}
	return listRes.List, nil
}

func unmarshalListsResponse(res *api.HTTPResponse) ([]*descope.List, error) {
	var listsRes struct {
		Lists []*descope.List `json:"lists"`
	}
	if err := utils.Unmarshal([]byte(res.BodyStr), &listsRes); err != nil {
		return nil, err
	}
	return listsRes.Lists, nil
}
