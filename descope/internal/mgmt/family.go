package mgmt

import (
	"context"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/sdk"
)

type family struct {
	managementBase
}

var _ sdk.Family = &family{}

func (f *family) Create(ctx context.Context, familyRequest *descope.FamilyRequest) (*descope.Family, error) {
	return f.createWithID(ctx, "", familyRequest)
}

func (f *family) CreateWithID(ctx context.Context, id string, familyRequest *descope.FamilyRequest) (*descope.Family, error) {
	if id == "" {
		return nil, utils.NewInvalidArgumentError("id")
	}
	return f.createWithID(ctx, id, familyRequest)
}

func (f *family) createWithID(ctx context.Context, id string, familyRequest *descope.FamilyRequest) (*descope.Family, error) {
	if familyRequest == nil || familyRequest.Name == "" {
		return nil, utils.NewInvalidArgumentError("name")
	}
	req := map[string]any{
		"name":     familyRequest.Name,
		"disabled": familyRequest.Disabled,
	}
	if id != "" {
		req["familyId"] = id
	}
	if familyRequest.CustomAttributes != nil {
		req["customAttributes"] = familyRequest.CustomAttributes
	}
	if familyRequest.Photo != "" {
		req["photo"] = familyRequest.Photo
	}
	res, err := f.client.DoPostRequest(ctx, api.Routes.ManagementFamilyCreate(), req, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalFamilyResponse(res)
}

func (f *family) Update(ctx context.Context, id string, familyRequest *descope.UpdateFamilyRequest) (*descope.Family, error) {
	if id == "" {
		return nil, utils.NewInvalidArgumentError("id")
	}
	if familyRequest == nil {
		familyRequest = &descope.UpdateFamilyRequest{}
	}
	req := map[string]any{"id": id}
	if familyRequest.Name != nil {
		req["name"] = *familyRequest.Name
	}
	if familyRequest.CustomAttributes != nil {
		req["customAttributes"] = familyRequest.CustomAttributes
	}
	if familyRequest.Photo != nil {
		req["photo"] = *familyRequest.Photo
	}
	if familyRequest.Disabled != nil {
		req["disabled"] = *familyRequest.Disabled
	}
	res, err := f.client.DoPostRequest(ctx, api.Routes.ManagementFamilyUpdate(), req, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalFamilyResponse(res)
}

func (f *family) Delete(ctx context.Context, id string) error {
	if id == "" {
		return utils.NewInvalidArgumentError("id")
	}
	req := map[string]any{"id": id}
	_, err := f.client.DoPostRequest(ctx, api.Routes.ManagementFamilyDelete(), req, nil, "")
	return err
}

func (f *family) SearchAll(ctx context.Context, options *descope.FamilySearchOptions) ([]*descope.Family, error) {
	if options == nil {
		options = &descope.FamilySearchOptions{}
	}
	if options.Page < 0 {
		return nil, utils.NewInvalidArgumentError("page")
	}
	if options.Size < 0 {
		return nil, utils.NewInvalidArgumentError("size")
	}
	req := map[string]any{
		"familyIds":        options.IDs,
		"familyNames":      options.Names,
		"freeText":         options.Text,
		"customAttributes": options.CustomAttributes,
		"page":             options.Page,
		"size":             options.Size,
	}
	res, err := f.client.DoPostRequest(ctx, api.Routes.ManagementFamilySearch(), req, nil, "")
	if err != nil {
		return nil, err
	}
	fres := struct {
		Families []*descope.Family `json:"families"`
	}{}
	if err := utils.Unmarshal([]byte(res.BodyStr), &fres); err != nil {
		return nil, err // notest
	}
	return fres.Families, nil
}

func (f *family) CreateDependent(ctx context.Context, familyID string, dependent *descope.FamilyDependentRequest) (*descope.UserResponse, error) {
	if familyID == "" {
		return nil, utils.NewInvalidArgumentError("familyID")
	}
	if dependent == nil {
		dependent = &descope.FamilyDependentRequest{}
	}
	req := map[string]any{"familyId": familyID}
	setIfNotEmpty := func(key, value string) {
		if value != "" {
			req[key] = value
		}
	}
	setIfNotEmpty("loginId", dependent.LoginID)
	setIfNotEmpty("name", dependent.Name)
	setIfNotEmpty("email", dependent.Email)
	setIfNotEmpty("phone", dependent.Phone)
	setIfNotEmpty("givenName", dependent.GivenName)
	setIfNotEmpty("middleName", dependent.MiddleName)
	setIfNotEmpty("familyName", dependent.FamilyName)
	setIfNotEmpty("picture", dependent.Picture)
	if dependent.CustomAttributes != nil {
		req["customAttributes"] = dependent.CustomAttributes
	}
	if dependent.FamilyScopedAttributes != nil {
		req["familyScopedAttributes"] = dependent.FamilyScopedAttributes
	}
	res, err := f.client.DoPostRequest(ctx, api.Routes.ManagementFamilyDependentCreate(), req, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalUserResponse(res)
}

func (f *family) DeleteDependent(ctx context.Context, userID string) error {
	if userID == "" {
		return utils.NewInvalidArgumentError("userID")
	}
	req := map[string]any{"userId": userID}
	_, err := f.client.DoPostRequest(ctx, api.Routes.ManagementFamilyDependentDelete(), req, nil, "")
	return err
}

func (f *family) ImpersonateDependent(ctx context.Context, impersonatorUserIDOrLoginID string, dependentLoginID string, selectedFamily string) (string, error) {
	if impersonatorUserIDOrLoginID == "" {
		return "", utils.NewInvalidArgumentError("impersonatorUserIDOrLoginID")
	}
	if dependentLoginID == "" {
		return "", utils.NewInvalidArgumentError("dependentLoginID")
	}
	req := map[string]any{
		"impersonatorUserIdOrLoginId": impersonatorUserIDOrLoginID,
		"dependentLoginId":            dependentLoginID,
	}
	if selectedFamily != "" {
		req["selectedFamily"] = selectedFamily
	}
	res, err := f.client.DoPostRequest(ctx, api.Routes.ManagementFamilyImpersonate(), req, nil, "")
	if err != nil {
		return "", err
	}
	return unmarshalFamilyJWTResponse(res)
}

func (f *family) StopImpersonation(ctx context.Context, jwt string, customClaims map[string]any, refreshDuration int32) (string, error) {
	if jwt == "" {
		return "", utils.NewInvalidArgumentError("jwt")
	}
	req := map[string]any{
		"jwt":             jwt,
		"customClaims":    customClaims,
		"refreshDuration": refreshDuration,
	}
	res, err := f.client.DoPostRequest(ctx, api.Routes.ManagementFamilyStopImpersonation(), req, nil, "")
	if err != nil {
		return "", err
	}
	return unmarshalFamilyJWTResponse(res)
}

func (f *family) GetSettings(ctx context.Context) (*descope.FamilySettings, error) {
	res, err := f.client.DoGetRequest(ctx, api.Routes.ManagementFamilySettings(), nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalFamilySettingsResponse(res)
}

func (f *family) ConfigureSettings(ctx context.Context, settings *descope.FamilySettingsRequest) (*descope.FamilySettings, error) {
	if settings == nil {
		return nil, utils.NewInvalidArgumentError("settings")
	}
	req := map[string]any{}
	if settings.Enabled != nil {
		req["enabled"] = *settings.Enabled
	}
	if settings.MaxFamilyMembers != nil {
		req["maxFamilyMembers"] = *settings.MaxFamilyMembers
	}
	if settings.AllowMultipleFamiliesUsers != nil {
		req["allowMultipleFamiliesUsers"] = *settings.AllowMultipleFamiliesUsers
	}
	res, err := f.client.DoPostRequest(ctx, api.Routes.ManagementFamilySettings(), req, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalFamilySettingsResponse(res)
}

func (f *family) GetCustomAttributes(ctx context.Context) ([]*descope.CustomAttribute, error) {
	res, err := f.client.DoGetRequest(ctx, api.Routes.ManagementFamilyCustomAttributes(), nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalCustomAttributesResponse(res)
}

func (f *family) CreateCustomAttributes(ctx context.Context, attributes []*descope.CustomAttribute) ([]*descope.CustomAttribute, error) {
	if len(attributes) == 0 {
		return nil, utils.NewInvalidArgumentError("attributes")
	}
	body := map[string]any{"attributes": attributes}
	res, err := f.client.DoPostRequest(ctx, api.Routes.ManagementFamilyCustomAttributeCreate(), body, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalCustomAttributesResponse(res)
}

func (f *family) DeleteCustomAttributes(ctx context.Context, names []string) ([]*descope.CustomAttribute, error) {
	if len(names) == 0 {
		return nil, utils.NewInvalidArgumentError("names")
	}
	body := map[string]any{"names": names}
	res, err := f.client.DoPostRequest(ctx, api.Routes.ManagementFamilyCustomAttributeDelete(), body, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalCustomAttributesResponse(res)
}

func unmarshalFamilyResponse(res *api.HTTPResponse) (*descope.Family, error) {
	fres := struct {
		Family *descope.Family `json:"family"`
	}{}
	if err := utils.Unmarshal([]byte(res.BodyStr), &fres); err != nil {
		return nil, err // notest
	}
	return fres.Family, nil
}

func unmarshalFamilySettingsResponse(res *api.HTTPResponse) (*descope.FamilySettings, error) {
	settings := &descope.FamilySettings{}
	if err := utils.Unmarshal([]byte(res.BodyStr), settings); err != nil {
		return nil, err // notest
	}
	return settings, nil
}

func unmarshalFamilyJWTResponse(res *api.HTTPResponse) (string, error) {
	jRes := &jwtRes{}
	if err := utils.Unmarshal([]byte(res.BodyStr), jRes); err != nil {
		return "", err // notest
	}
	return jRes.JWT, nil
}
