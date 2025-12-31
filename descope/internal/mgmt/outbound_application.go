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

func (s *outboundApplication) FetchUserToken(ctx context.Context, request *descope.OutboundAppUserTokenRequest) (*descope.OutboundAppUserToken, error) {
	if request == nil {
		return nil, utils.NewInvalidArgumentError("request")
	}
	if request.AppID == "" {
		return nil, utils.NewInvalidArgumentError("request.AppID")
	}
	if request.UserID == "" {
		return nil, utils.NewInvalidArgumentError("request.UserID")
	}

	req := map[string]any{
		"appId":  request.AppID,
		"userId": request.UserID,
	}
	if len(request.Scopes) > 0 {
		req["scopes"] = request.Scopes
	}
	if request.Options != nil {
		req["options"] = map[string]any{
			"withRefreshToken": request.Options.WithRefreshToken,
			"forceRefresh":     request.Options.ForceRefresh,
		}
	}
	if request.TenantID != "" {
		req["tenantId"] = request.TenantID
	}

	httpRes, err := s.client.DoPostRequest(ctx, api.Routes.ManagementOutboundApplicationUserToken(), req, nil, "")
	if err != nil {
		return nil, err
	}

	res := &struct {
		Token *descope.OutboundAppUserToken `json:"token"`
	}{}
	if err = utils.Unmarshal([]byte(httpRes.BodyStr), res); err != nil {
		return nil, err
	}
	return res.Token, nil
}

func (s *outboundApplication) DeleteUserTokens(ctx context.Context, appID, userID string) error {
	if appID == "" && userID == "" {
		return utils.NewInvalidArgumentError("appID or userID")
	}

	queryParams := map[string]string{}
	if appID != "" {
		queryParams["appId"] = appID
	}
	if userID != "" {
		queryParams["userId"] = userID
	}

	_, err := s.client.DoDeleteRequest(ctx, api.Routes.ManagementOutboundApplicationDeleteUserTokens(), &api.HTTPRequest{QueryParams: queryParams}, "")
	return err
}

func (s *outboundApplication) DeleteTokenByID(ctx context.Context, tokenID string) error {
	if tokenID == "" {
		return utils.NewInvalidArgumentError("tokenID")
	}

	queryParams := map[string]string{"id": tokenID}
	_, err := s.client.DoDeleteRequest(ctx, api.Routes.ManagementOutboundApplicationDeleteTokenByID(), &api.HTTPRequest{QueryParams: queryParams}, "")
	return err
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
