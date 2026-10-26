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

func (s *scim) CreateAccessKey(ctx context.Context, request *descope.CreateSCIMAccessKeyRequest) (*descope.SCIMAccessKeyResponse, error) {
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

func (s *scim) RotateAccessKey(ctx context.Context, request *descope.RotateSCIMAccessKeyRequest) (*descope.SCIMAccessKeyResponse, error) {
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

func (s *scim) RevokeAccessKeys(ctx context.Context, request *descope.RevokeSCIMAccessKeysRequest) ([]string, error) {
	if request == nil {
		return nil, utils.NewInvalidArgumentError("request")
	}
	if request.TenantID == "" {
		return nil, utils.NewInvalidArgumentError("tenantID")
	}
	res, err := s.client.DoPostRequest(ctx, api.Routes.ManagementSCIMKeyRevoke(), request, nil, "")
	if err != nil {
		return nil, err
	}
	sres := struct {
		RevokedKeyIDs []string `json:"revokedKeyIds"`
	}{}
	if err := utils.Unmarshal([]byte(res.BodyStr), &sres); err != nil {
		return nil, err // notest
	}
	return sres.RevokedKeyIDs, nil
}

func (s *scim) ActivateAccessKeys(ctx context.Context, request *descope.ActivateSCIMAccessKeysRequest) ([]string, error) {
	if request == nil {
		return nil, utils.NewInvalidArgumentError("request")
	}
	if request.TenantID == "" {
		return nil, utils.NewInvalidArgumentError("tenantID")
	}
	if len(request.KeyIDs) == 0 {
		return nil, utils.NewInvalidArgumentError("keyIDs")
	}
	for _, id := range request.KeyIDs {
		if id == "" {
			return nil, utils.NewInvalidArgumentError("keyIDs")
		}
	}
	res, err := s.client.DoPostRequest(ctx, api.Routes.ManagementSCIMKeyActivate(), request, nil, "")
	if err != nil {
		return nil, err
	}
	sres := struct {
		ActivatedKeyIDs []string `json:"activatedKeyIds"`
	}{}
	if err := utils.Unmarshal([]byte(res.BodyStr), &sres); err != nil {
		return nil, err // notest
	}
	return sres.ActivatedKeyIDs, nil
}

func (s *scim) LoadAccessKeys(ctx context.Context, tenantID, ssoID string) ([]*descope.SCIMAccessKey, error) {
	if tenantID == "" {
		return nil, utils.NewInvalidArgumentError("tenantID")
	}
	req := &api.HTTPRequest{
		QueryParams: map[string]string{"tenantId": tenantID},
	}
	if ssoID != "" {
		req.QueryParams["ssoId"] = ssoID
	}
	res, err := s.client.DoGetRequest(ctx, api.Routes.ManagementSCIMKeyLoad(), req, "")
	if err != nil {
		return nil, err
	}
	sres := struct {
		Keys []*descope.SCIMAccessKey `json:"keys"`
	}{}
	if err := utils.Unmarshal([]byte(res.BodyStr), &sres); err != nil {
		return nil, err // notest
	}
	return sres.Keys, nil
}

func unmarshalSCIMAccessKeyResponse(res *api.HTTPResponse) (*descope.SCIMAccessKeyResponse, error) {
	sres := &descope.SCIMAccessKeyResponse{}
	if err := utils.Unmarshal([]byte(res.BodyStr), sres); err != nil {
		return nil, err // notest
	}
	return sres, nil
}
