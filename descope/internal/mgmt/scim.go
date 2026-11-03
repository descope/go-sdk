package mgmt

import (
	"context"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/sdk"
)

type scim struct {
	managementBase
}

var _ sdk.SCIM = &scim{}

func (s *scim) CreateAccessKey(ctx context.Context, request *descope.SCIMAccessKeyCreateRequest) (*descope.SCIMAccessKeyResponse, error) {
	if request == nil {
		return nil, utils.NewInvalidArgumentError("request")
	}
	if request.TenantID == "" {
		return nil, utils.NewInvalidArgumentError("tenantID")
	}
	res, err := s.client.DoPostRequest(ctx, api.Routes.ManagementSCIMKeyCreate(), request, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalSCIMAccessKeyResponse(res)
}

func (s *scim) RotateAccessKey(ctx context.Context, request *descope.SCIMAccessKeyRotateRequest) (*descope.SCIMAccessKeyResponse, error) {
	if request == nil {
		return nil, utils.NewInvalidArgumentError("request")
	}
	if request.TenantID == "" {
		return nil, utils.NewInvalidArgumentError("tenantID")
	}
	res, err := s.client.DoPostRequest(ctx, api.Routes.ManagementSCIMKeyRotate(), request, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalSCIMAccessKeyResponse(res)
}

func (s *scim) RevokeAccessKeys(ctx context.Context, tenantID, ssoID string, revokeMode descope.SCIMKeyRevokeMode) ([]string, error) {
	if tenantID == "" {
		return nil, utils.NewInvalidArgumentError("tenantID")
	}
	body := map[string]any{"tenantId": tenantID}
	if ssoID != "" {
		body["ssoId"] = ssoID
	}
	if revokeMode != "" {
		body["revokeMode"] = revokeMode
	}
	res, err := s.client.DoPostRequest(ctx, api.Routes.ManagementSCIMKeyRevoke(), body, nil, "")
	if err != nil {
		return nil, err
	}
	tmp := &struct {
		RevokedKeyIDs []string `json:"revokedKeyIds"`
	}{}
	if err = utils.Unmarshal([]byte(res.BodyStr), tmp); err != nil {
		return nil, err
	}
	return tmp.RevokedKeyIDs, nil
}

func (s *scim) ActivateAccessKeys(ctx context.Context, tenantID, ssoID string, keyIDs []string) ([]string, error) {
	if tenantID == "" {
		return nil, utils.NewInvalidArgumentError("tenantID")
	}
	if len(keyIDs) == 0 {
		return nil, utils.NewInvalidArgumentError("keyIDs")
	}
	for _, id := range keyIDs {
		if id == "" {
			return nil, utils.NewInvalidArgumentError("keyIDs")
		}
	}
	body := map[string]any{"tenantId": tenantID, "keyIds": keyIDs}
	if ssoID != "" {
		body["ssoId"] = ssoID
	}
	res, err := s.client.DoPostRequest(ctx, api.Routes.ManagementSCIMKeyActivate(), body, nil, "")
	if err != nil {
		return nil, err
	}
	tmp := &struct {
		ActivatedKeyIDs []string `json:"activatedKeyIds"`
	}{}
	if err = utils.Unmarshal([]byte(res.BodyStr), tmp); err != nil {
		return nil, err
	}
	return tmp.ActivatedKeyIDs, nil
}

func (s *scim) LoadAccessKeys(ctx context.Context, tenantID, ssoID string) ([]*descope.SCIMAccessKey, error) {
	params := map[string]string{}
	if tenantID != "" {
		params["tenantId"] = tenantID
	}
	if ssoID != "" {
		params["ssoId"] = ssoID
	}
	res, err := s.client.DoGetRequest(ctx, api.Routes.ManagementSCIMKeyLoad(), &api.HTTPRequest{QueryParams: params}, "")
	if err != nil {
		return nil, err
	}
	tmp := &struct {
		Keys []*descope.SCIMAccessKey `json:"keys"`
	}{}
	if err = utils.Unmarshal([]byte(res.BodyStr), tmp); err != nil {
		return nil, err
	}
	return tmp.Keys, nil
}

func unmarshalSCIMAccessKeyResponse(res *api.HTTPResponse) (*descope.SCIMAccessKeyResponse, error) {
	tmp := &descope.SCIMAccessKeyResponse{}
	if err := utils.Unmarshal([]byte(res.BodyStr), tmp); err != nil {
		return nil, err
	}
	return tmp, nil
}
