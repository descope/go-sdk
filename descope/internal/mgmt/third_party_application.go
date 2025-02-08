package mgmt

import (
	"context"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/sdk"
)

type thirdPartyApplication struct {
	managementBase
}

var _ sdk.ThirdPartyApplication = &thirdPartyApplication{}

func (s *thirdPartyApplication) CreateApplication(ctx context.Context, appRequest *descope.ThirdPartyApplicationRequest) (id string, secret string, err error) {
	if appRequest == nil {
		return "", "", utils.NewInvalidArgumentError("appRequest")
	}
	if appRequest.Name == "" {
		return "", "", utils.NewInvalidArgumentError("appRequest.Name")
	}

	req := makeCreateUpdateThirdPartyApplicationRequest(appRequest)
	httpRes, err := s.client.DoPostRequest(ctx, api.Routes.ManagementThirdPartyApplicationCreate(), req, nil, s.conf.ManagementKey)
	if err != nil {
		return "", "", err
	}
	res := &struct {
		ID        string `json:"id"`
		Cleartext string `json:"cleartext"`
	}{}
	if err = utils.Unmarshal([]byte(httpRes.BodyStr), res); err != nil {
		return "", "", err
	}
	return res.ID, res.Cleartext, nil
}

func (s *thirdPartyApplication) UpdateApplication(ctx context.Context, appRequest *descope.ThirdPartyApplicationRequest) error {
	if appRequest == nil {
		return utils.NewInvalidArgumentError("appRequest")
	}
	if appRequest.ID == "" {
		return utils.NewInvalidArgumentError("appRequest.id")
	}
	if appRequest.Name == "" {
		return utils.NewInvalidArgumentError("appRequest.Name")
	}

	req := makeCreateUpdateThirdPartyApplicationRequest(appRequest)
	_, err := s.client.DoPostRequest(ctx, api.Routes.ManagementThirdPartyApplicationUpdate(), req, nil, s.conf.ManagementKey)
	return err
}

func (s *thirdPartyApplication) PatchApplication(ctx context.Context, appRequest *descope.ThirdPartyApplicationRequest) error {
	if appRequest == nil {
		return utils.NewInvalidArgumentError("appRequest")
	}
	if appRequest.ID == "" {
		return utils.NewInvalidArgumentError("appRequest.id")
	}

	req := makeCreateUpdateThirdPartyApplicationRequest(appRequest)
	_, err := s.client.DoPostRequest(ctx, api.Routes.ManagementThirdPartyApplicationPatch(), req, nil, s.conf.ManagementKey)
	return err
}

func (s *thirdPartyApplication) DeleteApplication(ctx context.Context, id string) error {
	if id == "" {
		return utils.NewInvalidArgumentError("id")
	}
	req := map[string]any{"id": id}
	_, err := s.client.DoPostRequest(ctx, api.Routes.ManagementThirdPartyApplicationDelete(), req, nil, s.conf.ManagementKey)
	return err
}

func (s *thirdPartyApplication) LoadApplication(ctx context.Context, id string) (*descope.ThirdPartyApplication, error) {
	if id == "" {
		return nil, utils.NewInvalidArgumentError("id")
	}
	req := &api.HTTPRequest{
		QueryParams: map[string]string{"id": id},
	}
	res, err := s.client.DoGetRequest(ctx, api.Routes.ManagementThirdPartyApplicationLoad(), req, s.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalLoadThirdPartyApplicationResponse(res)
}

func (s *thirdPartyApplication) LoadAllApplications(ctx context.Context) ([]*descope.ThirdPartyApplication, error) {
	res, err := s.client.DoGetRequest(ctx, api.Routes.ManagementThirdPartyApplicationLoadAll(), nil, s.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalLoadAllThirdPartyApplicationsResponse(res)
}

func (s *thirdPartyApplication) GetApplicationSecret(ctx context.Context, id string) (string, error) {
	if id == "" {
		return "", utils.NewInvalidArgumentError("id")
	}
	req := &api.HTTPRequest{
		QueryParams: map[string]string{"id": id},
	}
	httpRes, err := s.client.DoGetRequest(ctx, api.Routes.ManagementThirdPartyApplicationSecret(), req, s.conf.ManagementKey)
	if err != nil {
		return "", err
	}
	res := struct {
		Cleartext string `json:"cleartext"`
	}{}
	if err = utils.Unmarshal([]byte(httpRes.BodyStr), &res); err != nil {
		return "", err
	}
	return res.Cleartext, nil
}

func (s *thirdPartyApplication) RotateApplicationSecret(ctx context.Context, id string) (string, error) {
	if id == "" {
		return "", utils.NewInvalidArgumentError("id")
	}
	req := map[string]any{"id": id}
	httpRes, err := s.client.DoPostRequest(ctx, api.Routes.ManagementThirdPartyApplicationRotate(), req, nil, s.conf.ManagementKey)
	if err != nil {
		return "", err
	}
	res := struct {
		Cleartext string `json:"cleartext"`
	}{}
	if err = utils.Unmarshal([]byte(httpRes.BodyStr), &res); err != nil {
		return "", err
	}
	return res.Cleartext, nil
}

func (s *thirdPartyApplication) DeleteConsents(ctx context.Context, consentRequest *descope.ThirdPartyApplicationConsentDeleteOptions) error {
	if consentRequest == nil {
		return utils.NewInvalidArgumentError("consentRequest")
	}

	req := map[string]any{
		"consentIds": consentRequest.ConsentIDs,
		"appId":      consentRequest.AppID,
		"userIds":    consentRequest.UserIDs,
		"tenantId":   consentRequest.TenantID,
	}
	_, err := s.client.DoPostRequest(ctx, api.Routes.ManagementThirdPartyApplicationDeleteConsent(), req, nil, s.conf.ManagementKey)
	if err != nil {
		return err
	}
	return nil
}

func (s *thirdPartyApplication) DeleteTenantConsents(ctx context.Context, consentRequest *descope.ThirdPartyApplicationTenantConsentDeleteOptions) error {
	if consentRequest == nil {
		return utils.NewInvalidArgumentError("consentRequest")
	}

	req := map[string]any{
		"consentIds": consentRequest.ConsentIDs,
		"appId":      consentRequest.AppID,
		"tenantId":   consentRequest.TenantID,
	}
	_, err := s.client.DoPostRequest(ctx, api.Routes.ManagementThirdPartyApplicationDeleteTenantConsent(), req, nil, s.conf.ManagementKey)
	if err != nil {
		return err
	}
	return nil
}

func (s *thirdPartyApplication) SearchConsents(ctx context.Context, consentRequest *descope.ThirdPartyApplicationConsentSearchOptions) ([]*descope.ThirdPartyApplicationConsent, int, error) {
	if consentRequest == nil {
		return nil, 0, utils.NewInvalidArgumentError("consentRequest")
	}

	req := map[string]any{
		"consentId": consentRequest.ConsentID,
		"appId":     consentRequest.AppID,
		"userId":    consentRequest.UserID,
		"page":      consentRequest.Page,
		"tenantId":  consentRequest.TenantID,
	}
	res, err := s.client.DoPostRequest(ctx, api.Routes.ManagementThirdPartyApplicationSearchConsents(), req, nil, s.conf.ManagementKey)
	if err != nil {
		return nil, 0, err
	}
	return unmarshalApplicationConsentsResponse(res)
}

func makeCreateUpdateThirdPartyApplicationRequest(appRequest *descope.ThirdPartyApplicationRequest) map[string]any {
	return map[string]any{
		"id":                   appRequest.ID,
		"name":                 appRequest.Name,
		"description":          appRequest.Description,
		"logo":                 appRequest.Logo,
		"loginPageUrl":         appRequest.LoginPageURL,
		"approvedCallbackUrls": appRequest.ApprovedCallbackUrls,
		"permissionsScopes":    appRequest.PermissionsScopes,
		"attributesScopes":     appRequest.AttributesScopes,
	}
}

func unmarshalLoadThirdPartyApplicationResponse(res *api.HTTPResponse) (*descope.ThirdPartyApplication, error) {
	var appRes *descope.ThirdPartyApplication
	err := utils.Unmarshal([]byte(res.BodyStr), &appRes)
	if err != nil {
		return nil, err
	}
	return appRes, nil
}

func unmarshalLoadAllThirdPartyApplicationsResponse(res *api.HTTPResponse) ([]*descope.ThirdPartyApplication, error) {
	appsRes := struct {
		Apps []*descope.ThirdPartyApplication
	}{}
	err := utils.Unmarshal([]byte(res.BodyStr), &appsRes)
	if err != nil {
		return nil, err
	}
	return appsRes.Apps, nil
}

func unmarshalApplicationConsentsResponse(res *api.HTTPResponse) ([]*descope.ThirdPartyApplicationConsent, int, error) {
	appsRes := struct {
		Consents []*descope.ThirdPartyApplicationConsent
		Total    int
	}{}
	err := utils.Unmarshal([]byte(res.BodyStr), &appsRes)
	if err != nil {
		return nil, 0, err
	}
	return appsRes.Consents, appsRes.Total, nil
}
