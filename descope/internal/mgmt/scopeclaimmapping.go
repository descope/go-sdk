package mgmt

import (
	"context"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/sdk"
)

type scopeClaimMapping struct {
	managementBase
}

var _ sdk.ScopeClaimMapping = &scopeClaimMapping{}

func (s *scopeClaimMapping) Get(ctx context.Context) ([]*descope.ScopeClaimMappingEntry, error) {
	res, err := s.client.DoPostRequest(ctx, api.Routes.ManagementScopeClaimMappingGet(), nil, nil, "")
	if err != nil {
		return nil, err
	}
	tmp := &struct {
		Mappings []*descope.ScopeClaimMappingEntry `json:"mappings"`
	}{}
	if err = utils.Unmarshal([]byte(res.BodyStr), tmp); err != nil {
		return nil, err
	}
	return tmp.Mappings, nil
}

func (s *scopeClaimMapping) Set(ctx context.Context, mappings []*descope.ScopeClaimMappingEntry) error {
	body := map[string]any{"mappings": mappings}
	_, err := s.client.DoPostRequest(ctx, api.Routes.ManagementScopeClaimMappingSet(), body, nil, "")
	return err
}

func (s *scopeClaimMapping) Delete(ctx context.Context) error {
	_, err := s.client.DoPostRequest(ctx, api.Routes.ManagementScopeClaimMappingDelete(), nil, nil, "")
	return err
}
