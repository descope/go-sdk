package mgmt

import (
	"context"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/sdk"
)

type outboundApplication struct {
	managementBase
}

var _ sdk.OutboundApplication = &outboundApplication{}

func (s *outboundApplication) CreateApplication(ctx context.Context, appRequest *descope.CreateOutboundAppRequest) (app *descope.OutboundApp, err error) {
	if appRequest == nil {
		return nil, utils.NewInvalidArgumentError("appRequest")
	}
	if appRequest.Name == "" {
		return nil, utils.NewInvalidArgumentError("appRequest.Name")
	}

	req := makeCreateUpdateOutboundApplicationRequest(&appRequest.OutboundApp)
	req["clientSecret"] = appRequest.ClientSecret
	httpRes, err := s.client.DoPostRequest(ctx, api.Routes.ManagementOutboundApplicationCreate(), req, nil, "")
	if err != nil {
		return nil, err
	}
	return s.unmarshalAppResponse(httpRes)
}

func (s *outboundApplication) UpdateApplication(ctx context.Context, appRequest *descope.OutboundApp, clientSecret *string) (app *descope.OutboundApp, err error) {
	if appRequest == nil {
		return nil, utils.NewInvalidArgumentError("appRequest")
	}
	if appRequest.ID == "" {
		return nil, utils.NewInvalidArgumentError("appRequest.id")
	}
	if appRequest.Name == "" {
		return nil, utils.NewInvalidArgumentError("appRequest.Name")
	}

	req := makeCreateUpdateOutboundApplicationRequest(appRequest)
	if clientSecret != nil {
		req["clientSecret"] = *clientSecret
	}
	httpRes, err := s.client.DoPostRequest(ctx, api.Routes.ManagementOutboundApplicationUpdate(), map[string]any{
		"app": req,
	}, nil, "")
	if err != nil {
		return nil, err
	}
	return s.unmarshalAppResponse(httpRes)
}

func (s *outboundApplication) DeleteApplication(ctx context.Context, id string) error {
	if id == "" {
		return utils.NewInvalidArgumentError("id")
	}
	req := map[string]any{"id": id}
	_, err := s.client.DoPostRequest(ctx, api.Routes.ManagementOutboundApplicationDelete(), req, nil, "")
	return err
}

func (s *outboundApplication) LoadApplication(ctx context.Context, id string) (*descope.OutboundApp, error) {
	if id == "" {
		return nil, utils.NewInvalidArgumentError("id")
	}
	res, err := s.client.DoGetRequest(ctx, api.Routes.ManagementOutboundApplicationLoad()+"/"+id, nil, "")
	if err != nil {
		return nil, err
	}
	return s.unmarshalAppResponse(res)
}

func (s *outboundApplication) LoadAllApplications(ctx context.Context) ([]*descope.OutboundApp, error) {
	res, err := s.client.DoGetRequest(ctx, api.Routes.ManagementOutboundApplicationLoadAll(), nil, "")
	if err != nil {
		return nil, err
	}
	tmp := &struct {
		Apps []*descope.OutboundApp `json:"apps"`
	}{}
	if err = utils.Unmarshal([]byte(res.BodyStr), tmp); err != nil {
		return nil, err
	}
	return tmp.Apps, nil
}

func makeCreateUpdateOutboundApplicationRequest(app *descope.OutboundApp) map[string]any {
	return map[string]any{
		"id":                     app.ID,
		"name":                   app.Name,
		"description":            app.Description,
		"templateId":             app.TemplateID,
		"clientId":               app.ClientID,
		"logo":                   app.Logo,
		"discoveryUrl":           app.DiscoveryURL,
		"authorizationUrl":       app.AuthorizationURL,
		"authorizationUrlParams": app.AuthorizationURLParams,
		"tokenUrl":               app.TokenURL,
		"tokenUrlParams":         app.TokenURLParams,
		"revocationUrl":          app.RevocationURL,
		"defaultScopes":          app.DefaultScopes,
		"defaultRedirectUrl":     app.DefaultRedirectURL,
		"callbackDomain":         app.CallbackDomain,
		"pkce":                   app.Pkce,
		"accessType":             app.AccessType,
		"prompt":                 app.Prompt,
	}
}

func (s *outboundApplication) FetchUserToken(ctx context.Context, request *descope.FetchOutboundAppUserTokenRequest) (*descope.OutboundAppUserToken, error) {
	if request == nil {
		return nil, utils.NewInvalidArgumentError("request")
	}
	if request.AppID == "" {
		return nil, utils.NewInvalidArgumentError("request.AppID")
	}
	if request.UserID == "" {
		return nil, utils.NewInvalidArgumentError("request.UserID")
	}

	httpRes, err := s.client.DoPostRequest(ctx, api.Routes.ManagementOutboundApplicationFetchUserToken(), request, nil, "")
	if err != nil {
		return nil, err
	}

	var response descope.FetchOutboundAppUserTokenResponse
	if err = utils.Unmarshal([]byte(httpRes.BodyStr), &response); err != nil {
		return nil, err
	}
	return response.Token, nil
}

func (s *outboundApplication) DeleteUserTokens(ctx context.Context, appID, userID string) error {
	if appID == "" && userID == "" {
		return utils.NewInvalidArgumentError("either appID or userID must be provided")
	}

	params := map[string]string{}
	if appID != "" {
		params["appId"] = appID
	}
	if userID != "" {
		params["userId"] = userID
	}

	req := &api.HTTPRequest{
		QueryParams: params,
	}
	_, err := s.client.DoDeleteRequest(ctx, api.Routes.ManagementOutboundApplicationDeleteUserTokens(), req, "")
	if err != nil {
		return err
	}
	return nil
}

func (s *outboundApplication) DeleteTokenByID(ctx context.Context, id string) error {
	if id == "" {
		return utils.NewInvalidArgumentError("id")
	}

	req := &api.HTTPRequest{
		QueryParams: map[string]string{"id": id},
	}
	_, err := s.client.DoDeleteRequest(ctx, api.Routes.ManagementOutboundApplicationDeleteTokenByID(), req, "")
	if err != nil {
		return err
	}
	return nil
}

func (s *outboundApplication) unmarshalAppResponse(httpRes *api.HTTPResponse) (*descope.OutboundApp, error) {
	var err error
	res := &struct {
		App *descope.OutboundApp `json:"app"`
	}{}
	if err = utils.Unmarshal([]byte(httpRes.BodyStr), res); err != nil {
		return nil, err
	}
	return res.App, nil
}
