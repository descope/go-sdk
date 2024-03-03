package mgmt

import (
	"context"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
)

type project struct {
	managementBase
}

type projectBody struct {
	Files   map[string]any   `json:"files"`
	Secrets []map[string]any `json:"secrets"`
}

type updateProjectBody struct {
	Name string `json:"name"`
}

type cloneProjectBody struct {
	Name string `json:"name"`
	Tag  string `json:"tag"`
}

type projectValidationResponse struct {
	Secrets []map[string]any `json:"secrets"`
}

func (p *project) Export(ctx context.Context) (map[string]any, error) {
	body := map[string]any{}
	res, err := p.client.DoPostRequest(ctx, api.Routes.ManagementProjectExport(), body, nil, p.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	var export projectBody
	if err := utils.Unmarshal([]byte(res.BodyStr), &export); err != nil {
		return nil, err // notest
	}
	return export.Files, nil
}

func (p *project) Import(ctx context.Context, files map[string]any, secrets []map[string]any) error {
	body := projectBody{Files: files, Secrets: secrets}
	_, err := p.client.DoPostRequest(ctx, api.Routes.ManagementProjectImport(), body, nil, p.conf.ManagementKey)
	return err
}

func (p *project) ValidateImport(ctx context.Context, files map[string]any, secrets []map[string]any) ([]map[string]any, error) {
	body := projectBody{Files: files, Secrets: secrets}
	res, err := p.client.DoPostRequest(ctx, api.Routes.ManagementProjectImportValidate(), body, nil, p.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	var validation projectValidationResponse
	if err := utils.Unmarshal([]byte(res.BodyStr), &validation); err != nil {
		return nil, err // notest
	}
	return validation.Secrets, nil
}

func (p *project) UpdateName(ctx context.Context, name string) error {
	body := updateProjectBody{Name: name}
	_, err := p.client.DoPostRequest(ctx, api.Routes.ManagementProjectUpdateName(), body, nil, p.conf.ManagementKey)
	return err
}

func (p *project) Clone(ctx context.Context, name string, tag descope.ProjectTag) (*descope.CloneProjectResponse, error) {
	body := cloneProjectBody{Name: name, Tag: string(tag)}
	res, err := p.client.DoPostRequest(ctx, api.Routes.ManagementProjectClone(), body, nil, p.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalNewProjectResponseResponse(res)
}

func (p *project) Delete(ctx context.Context) error {
	_, err := p.client.DoPostRequest(ctx, api.Routes.ManagementProjectDelete(), nil, nil, p.conf.ManagementKey)
	return err
}

func unmarshalNewProjectResponseResponse(res *api.HTTPResponse) (*descope.CloneProjectResponse, error) {
	var newProjectRes *descope.CloneProjectResponse
	err := utils.Unmarshal([]byte(res.BodyStr), &newProjectRes)
	if err != nil {
		return nil, err
	}
	return newProjectRes, err
}
