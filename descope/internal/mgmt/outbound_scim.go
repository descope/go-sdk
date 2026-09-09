package mgmt

import (
	"context"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/sdk"
)

type outboundSCIM struct {
	managementBase
}

var _ sdk.OutboundSCIM = &outboundSCIM{}

func (s *outboundSCIM) CreateConfiguration(ctx context.Context, request *descope.CreateOutboundSCIMConfigurationRequest) (*descope.OutboundSCIMConfiguration, error) {
	if request == nil {
		return nil, utils.NewInvalidArgumentError("request")
	}
	if request.AppID == "" {
		return nil, utils.NewInvalidArgumentError("request.AppID")
	}

	// Descope grpc-gateway rejects unknown JSON request fields — build the body from an explicit
	// map so only the proto-declared fields are sent.
	body := map[string]any{
		"appId":         request.AppID,
		"configuration": request.Configuration,
	}
	httpRes, err := s.client.DoPostRequest(ctx, api.Routes.ManagementOutboundSCIMCreate(), body, nil, "")
	if err != nil {
		return nil, err
	}
	return s.unmarshalConfigurationResponse(httpRes)
}

func (s *outboundSCIM) UpdateConfiguration(ctx context.Context, request *descope.UpdateOutboundSCIMConfigurationRequest) (*descope.OutboundSCIMConfiguration, error) {
	if request == nil {
		return nil, utils.NewInvalidArgumentError("request")
	}
	if request.AppID == "" {
		return nil, utils.NewInvalidArgumentError("request.AppID")
	}

	// Proto int64 Version must serialize as a JSON string — utils.Marshal honors the ",string"
	// tag on the request struct, so send the struct directly rather than building a map.
	httpRes, err := s.client.DoPostRequest(ctx, api.Routes.ManagementOutboundSCIMUpdate(), request, nil, "")
	if err != nil {
		return nil, err
	}
	return s.unmarshalConfigurationResponse(httpRes)
}

func (s *outboundSCIM) DeleteConfiguration(ctx context.Context, appID string) error {
	if appID == "" {
		return utils.NewInvalidArgumentError("appID")
	}
	req := map[string]any{"appId": appID}
	_, err := s.client.DoPostRequest(ctx, api.Routes.ManagementOutboundSCIMDelete(), req, nil, "")
	return err
}

func (s *outboundSCIM) LoadConfiguration(ctx context.Context, appID string) (*descope.OutboundSCIMConfiguration, error) {
	if appID == "" {
		return nil, utils.NewInvalidArgumentError("appID")
	}
	res, err := s.client.DoGetRequest(ctx, api.Routes.ManagementOutboundSCIMLoad()+"/"+appID, nil, "")
	if err != nil {
		return nil, err
	}
	return s.unmarshalConfigurationResponse(res)
}

func (s *outboundSCIM) SetEnabled(ctx context.Context, appID string, enabled bool) (*descope.OutboundSCIMConfiguration, error) {
	if appID == "" {
		return nil, utils.NewInvalidArgumentError("appID")
	}
	body := map[string]any{"appId": appID, "enabled": enabled}
	httpRes, err := s.client.DoPostRequest(ctx, api.Routes.ManagementOutboundSCIMSetEnabled(), body, nil, "")
	if err != nil {
		return nil, err
	}
	return s.unmarshalConfigurationResponse(httpRes)
}

func (s *outboundSCIM) unmarshalConfigurationResponse(httpRes *api.HTTPResponse) (*descope.OutboundSCIMConfiguration, error) {
	res := &struct {
		Configuration *descope.OutboundSCIMConfiguration `json:"configuration"`
	}{}
	if err := utils.Unmarshal([]byte(httpRes.BodyStr), res); err != nil {
		return nil, err
	}
	return res.Configuration, nil
}
