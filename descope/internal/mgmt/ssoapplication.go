package mgmt

import (
	"context"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/sdk"
)

type ssoApplication struct {
	managementBase
}

var _ sdk.SSOApplication = &ssoApplication{}

func (s *ssoApplication) CreateOIDCApplication(ctx context.Context, appRequest *descope.OIDCApplicationRequest) (id string, err error) {
	if appRequest == nil {
		return "", utils.NewInvalidArgumentError("appRequest")
	}
	if appRequest.Name == "" {
		return "", utils.NewInvalidArgumentError("appRequest.Name")
	}

	req := makeCreateUpdateOIDCApplicationRequest(appRequest)
	httpRes, err := s.client.DoPostRequest(ctx, api.Routes.ManagementSSOApplicationOIDCCreate(), req, nil, s.conf.ManagementKey)
	if err != nil {
		return "", err
	}
	res := &struct {
		ID string `json:"id"`
	}{}
	if err = utils.Unmarshal([]byte(httpRes.BodyStr), res); err != nil {
		return "", err
	}
	return res.ID, nil
}

func (s *ssoApplication) CreateSAMLApplication(ctx context.Context, appRequest *descope.SAMLApplicationRequest) (id string, err error) {
	if appRequest == nil {
		return "", utils.NewInvalidArgumentError("appRequest")
	}
	if appRequest.Name == "" {
		return "", utils.NewInvalidArgumentError("appRequest.Name")
	}

	req := makeCreateUpdateSAMLApplicationRequest(appRequest)
	httpRes, err := s.client.DoPostRequest(ctx, api.Routes.ManagementSSOApplicationSAMLCreate(), req, nil, s.conf.ManagementKey)
	if err != nil {
		return "", err
	}
	res := &struct {
		ID string `json:"id"`
	}{}
	if err = utils.Unmarshal([]byte(httpRes.BodyStr), res); err != nil {
		return "", err
	}
	return res.ID, nil
}

func (s *ssoApplication) UpdateOIDCApplication(ctx context.Context, appRequest *descope.OIDCApplicationRequest) error {
	if appRequest == nil {
		return utils.NewInvalidArgumentError("appRequest")
	}
	if appRequest.ID == "" {
		return utils.NewInvalidArgumentError("appRequest.id")
	}
	if appRequest.Name == "" {
		return utils.NewInvalidArgumentError("appRequest.Name")
	}

	req := makeCreateUpdateOIDCApplicationRequest(appRequest)
	_, err := s.client.DoPostRequest(ctx, api.Routes.ManagementSSOApplicationOIDCUpdate(), req, nil, s.conf.ManagementKey)
	return err
}

func (s *ssoApplication) UpdateSAMLApplication(ctx context.Context, appRequest *descope.SAMLApplicationRequest) error {
	if appRequest == nil {
		return utils.NewInvalidArgumentError("appRequest")
	}
	if appRequest.ID == "" {
		return utils.NewInvalidArgumentError("appRequest.id")
	}
	if appRequest.Name == "" {
		return utils.NewInvalidArgumentError("appRequest.Name")
	}

	req := makeCreateUpdateSAMLApplicationRequest(appRequest)
	_, err := s.client.DoPostRequest(ctx, api.Routes.ManagementSSOApplicationSAMLUpdate(), req, nil, s.conf.ManagementKey)
	return err
}

func (s *ssoApplication) Delete(ctx context.Context, id string) error {
	if id == "" {
		return utils.NewInvalidArgumentError("id")
	}
	req := map[string]any{"id": id}
	_, err := s.client.DoPostRequest(ctx, api.Routes.ManagementSSOApplicationDelete(), req, nil, s.conf.ManagementKey)
	return err
}

func (s *ssoApplication) Load(ctx context.Context, id string) (*descope.SSOApplication, error) {
	if id == "" {
		return nil, utils.NewInvalidArgumentError("id")
	}
	req := &api.HTTPRequest{
		QueryParams: map[string]string{"id": id},
	}
	res, err := s.client.DoGetRequest(ctx, api.Routes.ManagementSSOApplicationLoad(), req, s.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalLoadSSOApplicationResponse(res)
}

func (s *ssoApplication) LoadAll(ctx context.Context) ([]*descope.SSOApplication, error) {
	res, err := s.client.DoGetRequest(ctx, api.Routes.ManagementSSOApplicationLoadAll(), nil, s.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalLoadAllSSOApplicationsResponse(res)
}

func makeCreateUpdateOIDCApplicationRequest(appRequest *descope.OIDCApplicationRequest) map[string]any {
	return map[string]any{
		"id":                   appRequest.ID,
		"name":                 appRequest.Name,
		"description":          appRequest.Description,
		"enabled":              appRequest.Enabled,
		"logo":                 appRequest.Logo,
		"loginPageUrl":         appRequest.LoginPageURL,
		"forceAuthentication":  appRequest.ForceAuthentication,
		"jwtBearerSettings":    appRequest.JWTBearerSettings,
		"backChannelLogoutUrl": appRequest.BackChannelLogoutURL,
	}
}

func makeCreateUpdateSAMLApplicationRequest(appRequest *descope.SAMLApplicationRequest) map[string]any {
	return map[string]any{
		"id":                  appRequest.ID,
		"name":                appRequest.Name,
		"description":         appRequest.Description,
		"enabled":             appRequest.Enabled,
		"logo":                appRequest.Logo,
		"loginPageUrl":        appRequest.LoginPageURL,
		"useMetadataInfo":     appRequest.UseMetadataInfo,
		"metadataUrl":         appRequest.MetadataURL,
		"entityId":            appRequest.EntityID,
		"acsUrl":              appRequest.AcsURL,
		"certificate":         appRequest.Certificate,
		"attributeMapping":    appRequest.AttributeMapping,
		"groupsMapping":       appRequest.GroupsMapping,
		"acsAllowedCallbacks": appRequest.AcsAllowedCallbacks,
		"defaultRelayState":   appRequest.DefaultRelayState,
		"subjectNameIdType":   appRequest.SubjectNameIDType,
		"subjectNameIdFormat": appRequest.SubjectNameIDFormat,
		"forceAuthentication": appRequest.ForceAuthentication,
		"logoutRedirectUrl":   appRequest.LogoutRedirectURL,
	}
}

func unmarshalLoadSSOApplicationResponse(res *api.HTTPResponse) (*descope.SSOApplication, error) {
	var appRes *descope.SSOApplication
	err := utils.Unmarshal([]byte(res.BodyStr), &appRes)
	if err != nil {
		return nil, err
	}
	return appRes, nil
}

func unmarshalLoadAllSSOApplicationsResponse(res *api.HTTPResponse) ([]*descope.SSOApplication, error) {
	appsRes := struct {
		Apps []*descope.SSOApplication
	}{}
	err := utils.Unmarshal([]byte(res.BodyStr), &appsRes)
	if err != nil {
		return nil, err
	}
	return appsRes.Apps, nil
}
