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
	return s.unmarshalTokenResponse(httpRes)
}

func (s *outboundApplication) FetchLatestUserToken(ctx context.Context, request *descope.FetchOutboundAppUserTokenRequest) (*descope.OutboundAppUserToken, error) {
	if request == nil {
		return nil, utils.NewInvalidArgumentError("request")
	}
	if request.AppID == "" {
		return nil, utils.NewInvalidArgumentError("request.AppID")
	}
	if request.UserID == "" {
		return nil, utils.NewInvalidArgumentError("request.UserID")
	}

	// The "latest" endpoint ignores scopes; send only the relevant fields so we never post a
	// "scopes" key the target message doesn't define (the gateway rejects unknown fields).
	body := map[string]any{"appId": request.AppID, "userId": request.UserID}
	if request.TenantID != "" {
		body["tenantId"] = request.TenantID
	}
	if request.Options != nil {
		body["options"] = request.Options
	}
	httpRes, err := s.client.DoPostRequest(ctx, api.Routes.ManagementOutboundApplicationFetchLatestUserToken(), body, nil, "")
	if err != nil {
		return nil, err
	}
	return s.unmarshalTokenResponse(httpRes)
}

func (s *outboundApplication) FetchTenantToken(ctx context.Context, request *descope.FetchOutboundAppTenantTokenRequest) (*descope.OutboundAppUserToken, error) {
	if request == nil {
		return nil, utils.NewInvalidArgumentError("request")
	}
	if request.AppID == "" {
		return nil, utils.NewInvalidArgumentError("request.AppID")
	}
	if request.TenantID == "" {
		return nil, utils.NewInvalidArgumentError("request.TenantID")
	}

	httpRes, err := s.client.DoPostRequest(ctx, api.Routes.ManagementOutboundApplicationFetchTenantToken(), request, nil, "")
	if err != nil {
		return nil, err
	}
	return s.unmarshalTokenResponse(httpRes)
}

func (s *outboundApplication) FetchLatestTenantToken(ctx context.Context, request *descope.FetchOutboundAppTenantTokenRequest) (*descope.OutboundAppUserToken, error) {
	if request == nil {
		return nil, utils.NewInvalidArgumentError("request")
	}
	if request.AppID == "" {
		return nil, utils.NewInvalidArgumentError("request.AppID")
	}
	if request.TenantID == "" {
		return nil, utils.NewInvalidArgumentError("request.TenantID")
	}

	// The "latest" endpoint ignores scopes; send only the relevant fields (see FetchLatestUserToken).
	body := map[string]any{"appId": request.AppID, "tenantId": request.TenantID}
	if request.Options != nil {
		body["options"] = request.Options
	}
	httpRes, err := s.client.DoPostRequest(ctx, api.Routes.ManagementOutboundApplicationFetchLatestTenantToken(), body, nil, "")
	if err != nil {
		return nil, err
	}
	return s.unmarshalTokenResponse(httpRes)
}

func (s *outboundApplication) ListAppsWithUserToken(ctx context.Context, userID, tenantID string) ([]string, error) {
	if userID == "" {
		return nil, utils.NewInvalidArgumentError("userID")
	}

	params := map[string]string{"userId": userID}
	if tenantID != "" {
		params["tenantId"] = tenantID
	}
	res, err := s.client.DoGetRequest(ctx, api.Routes.ManagementOutboundApplicationListAppsWithUserToken(), &api.HTTPRequest{QueryParams: params}, "")
	if err != nil {
		return nil, err
	}
	tmp := &struct {
		AppIDs []string `json:"appIds"`
	}{}
	if err = utils.Unmarshal([]byte(res.BodyStr), tmp); err != nil {
		return nil, err
	}
	return tmp.AppIDs, nil
}

func (s *outboundApplication) UploadUserAPIKey(ctx context.Context, request *descope.UploadOutboundAppUserAPIKeyRequest) error {
	if request == nil {
		return utils.NewInvalidArgumentError("request")
	}
	if request.AppID == "" {
		return utils.NewInvalidArgumentError("request.AppID")
	}
	if request.UserID == "" {
		return utils.NewInvalidArgumentError("request.UserID")
	}
	if request.APIKey == "" {
		return utils.NewInvalidArgumentError("request.APIKey")
	}

	_, err := s.client.DoPostRequest(ctx, api.Routes.ManagementOutboundApplicationUploadUserAPIKey(), request, nil, "")
	return err
}

func (s *outboundApplication) UploadTenantAPIKey(ctx context.Context, request *descope.UploadOutboundAppTenantAPIKeyRequest) error {
	if request == nil {
		return utils.NewInvalidArgumentError("request")
	}
	if request.AppID == "" {
		return utils.NewInvalidArgumentError("request.AppID")
	}
	if request.TenantID == "" {
		return utils.NewInvalidArgumentError("request.TenantID")
	}
	if request.APIKey == "" {
		return utils.NewInvalidArgumentError("request.APIKey")
	}

	_, err := s.client.DoPostRequest(ctx, api.Routes.ManagementOutboundApplicationUploadTenantAPIKey(), request, nil, "")
	return err
}

func (s *outboundApplication) UploadUserToken(ctx context.Context, request *descope.UploadOutboundAppUserTokenRequest) error {
	if request == nil {
		return utils.NewInvalidArgumentError("request")
	}
	if request.AppID == "" {
		return utils.NewInvalidArgumentError("request.AppID")
	}
	if request.UserID == "" {
		return utils.NewInvalidArgumentError("request.UserID")
	}
	if request.RefreshToken == "" && request.AccessToken == "" {
		return utils.NewInvalidArgumentError("either request.RefreshToken or request.AccessToken must be provided")
	}

	_, err := s.client.DoPostRequest(ctx, api.Routes.ManagementOutboundApplicationUploadUserToken(), request, nil, "")
	return err
}

func (s *outboundApplication) UploadTenantToken(ctx context.Context, request *descope.UploadOutboundAppTenantTokenRequest) error {
	if request == nil {
		return utils.NewInvalidArgumentError("request")
	}
	if request.AppID == "" {
		return utils.NewInvalidArgumentError("request.AppID")
	}
	if request.TenantID == "" {
		return utils.NewInvalidArgumentError("request.TenantID")
	}
	if request.RefreshToken == "" && request.AccessToken == "" {
		return utils.NewInvalidArgumentError("either request.RefreshToken or request.AccessToken must be provided")
	}

	_, err := s.client.DoPostRequest(ctx, api.Routes.ManagementOutboundApplicationUploadTenantToken(), request, nil, "")
	return err
}

func (s *outboundApplication) BatchUploadUserTokens(ctx context.Context, tokens []*descope.OutboundAppUserTokenToUpload) (*descope.BatchUploadOutboundAppTokensResponse, error) {
	if len(tokens) == 0 {
		return nil, utils.NewInvalidArgumentError("tokens")
	}

	httpRes, err := s.client.DoPostRequest(ctx, api.Routes.ManagementOutboundApplicationBatchUploadUserTokens(), map[string]any{"tokens": tokens}, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalBatchUploadResponse(httpRes)
}

func (s *outboundApplication) BatchUploadTenantTokens(ctx context.Context, tokens []*descope.OutboundAppTenantTokenToUpload) (*descope.BatchUploadOutboundAppTokensResponse, error) {
	if len(tokens) == 0 {
		return nil, utils.NewInvalidArgumentError("tokens")
	}

	httpRes, err := s.client.DoPostRequest(ctx, api.Routes.ManagementOutboundApplicationBatchUploadTenantTokens(), map[string]any{"tokens": tokens}, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalBatchUploadResponse(httpRes)
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

func (s *outboundApplication) unmarshalTokenResponse(httpRes *api.HTTPResponse) (*descope.OutboundAppUserToken, error) {
	var response descope.FetchOutboundAppUserTokenResponse
	if err := utils.Unmarshal([]byte(httpRes.BodyStr), &response); err != nil {
		return nil, err
	}
	return response.Token, nil
}

func unmarshalBatchUploadResponse(httpRes *api.HTTPResponse) (*descope.BatchUploadOutboundAppTokensResponse, error) {
	var response descope.BatchUploadOutboundAppTokensResponse
	if err := utils.Unmarshal([]byte(httpRes.BodyStr), &response); err != nil {
		return nil, err
	}
	return &response, nil
}
