package mgmt

import (
	"context"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/sdk"
)

type jwtTemplate struct {
	managementBase
}

var _ sdk.JWTTemplate = &jwtTemplate{}

func (t *jwtTemplate) Create(ctx context.Context, template *descope.JWTTemplate) (*descope.JWTTemplate, error) {
	if template == nil {
		return nil, utils.NewInvalidArgumentError("template")
	}
	body := map[string]any{"template": template}
	res, err := t.client.DoPostRequest(ctx, api.Routes.ManagementJWTTemplateCreate(), body, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalJWTTemplateResponse(res)
}

func (t *jwtTemplate) Update(ctx context.Context, template *descope.JWTTemplate) (*descope.JWTTemplate, error) {
	if template == nil {
		return nil, utils.NewInvalidArgumentError("template")
	}
	if template.ID == "" {
		return nil, utils.NewInvalidArgumentError("template.ID")
	}
	body := map[string]any{"template": template}
	res, err := t.client.DoPostRequest(ctx, api.Routes.ManagementJWTTemplateUpdate(), body, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalJWTTemplateResponse(res)
}

func (t *jwtTemplate) Delete(ctx context.Context, id string) error {
	if id == "" {
		return utils.NewInvalidArgumentError("id")
	}
	body := map[string]any{"id": id}
	_, err := t.client.DoPostRequest(ctx, api.Routes.ManagementJWTTemplateDelete(), body, nil, "")
	return err
}

func (t *jwtTemplate) List(ctx context.Context) ([]*descope.JWTTemplate, error) {
	res, err := t.client.DoPostRequest(ctx, api.Routes.ManagementJWTTemplateList(), map[string]any{}, nil, "")
	if err != nil {
		return nil, err
	}
	lres := struct {
		Templates []*descope.JWTTemplate
	}{}
	if err := utils.Unmarshal([]byte(res.BodyStr), &lres); err != nil {
		return nil, err
	}
	return lres.Templates, nil
}

func (t *jwtTemplate) Load(ctx context.Context, id string) (*descope.JWTTemplate, error) {
	if id == "" {
		return nil, utils.NewInvalidArgumentError("id")
	}
	body := map[string]any{"id": id}
	res, err := t.client.DoPostRequest(ctx, api.Routes.ManagementJWTTemplateLoad(), body, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalJWTTemplateResponse(res)
}

func (t *jwtTemplate) Validate(ctx context.Context, id string, template *descope.JWTTemplate) (*descope.JWTTemplateValidationResult, error) {
	if id == "" && template == nil {
		return nil, utils.NewInvalidArgumentError("template")
	}
	body := map[string]any{"id": id, "template": template}
	res, err := t.client.DoPostRequest(ctx, api.Routes.ManagementJWTTemplateValidate(), body, nil, "")
	if err != nil {
		return nil, err
	}
	result := &descope.JWTTemplateValidationResult{}
	if err := utils.Unmarshal([]byte(res.BodyStr), result); err != nil {
		return nil, err
	}
	return result, nil
}

func (t *jwtTemplate) ListLibrary(ctx context.Context) ([]*descope.JWTTemplateLibraryEntry, error) {
	res, err := t.client.DoPostRequest(ctx, api.Routes.ManagementJWTTemplateLibraryList(), map[string]any{}, nil, "")
	if err != nil {
		return nil, err
	}
	lres := struct {
		Entries []*descope.JWTTemplateLibraryEntry
	}{}
	if err := utils.Unmarshal([]byte(res.BodyStr), &lres); err != nil {
		return nil, err
	}
	return lres.Entries, nil
}

func (t *jwtTemplate) LoadLibraryEntry(ctx context.Context, id string) (*descope.JWTTemplateLibraryEntry, error) {
	if id == "" {
		return nil, utils.NewInvalidArgumentError("id")
	}
	body := map[string]any{"id": id}
	res, err := t.client.DoPostRequest(ctx, api.Routes.ManagementJWTTemplateLibraryLoad(), body, nil, "")
	if err != nil {
		return nil, err
	}
	eres := struct {
		Entry *descope.JWTTemplateLibraryEntry
	}{}
	if err := utils.Unmarshal([]byte(res.BodyStr), &eres); err != nil {
		return nil, err
	}
	return eres.Entry, nil
}

func (t *jwtTemplate) ApplyFromLibrary(ctx context.Context, request *descope.ApplyJWTTemplateFromLibraryRequest) (*descope.JWTTemplate, error) {
	if request == nil {
		return nil, utils.NewInvalidArgumentError("request")
	}
	if request.LibraryEntryID == "" {
		return nil, utils.NewInvalidArgumentError("request.LibraryEntryID")
	}
	res, err := t.client.DoPostRequest(ctx, api.Routes.ManagementJWTTemplateLibraryApply(), request, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalJWTTemplateResponse(res)
}

func unmarshalJWTTemplateResponse(res *api.HTTPResponse) (*descope.JWTTemplate, error) {
	tres := struct {
		Template *descope.JWTTemplate
	}{}
	if err := utils.Unmarshal([]byte(res.BodyStr), &tres); err != nil {
		return nil, err
	}
	return tres.Template, nil
}
