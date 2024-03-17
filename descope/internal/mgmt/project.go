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

type updateProjectBody struct {
	Name string `json:"name"`
}

type cloneProjectBody struct {
	Name string `json:"name"`
	Tag  string `json:"tag"`
}

func (p *project) Export(ctx context.Context) (*descope.ExportProjectResponse, error) {
	body := map[string]any{}
	res, err := p.client.DoPostRequest(ctx, api.Routes.ManagementProjectExport(), body, nil, p.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	var export descope.ExportProjectResponse
	if err := utils.Unmarshal([]byte(res.BodyStr), &export); err != nil {
		return nil, err // notest
	}
	return &export, nil
}

func (p *project) Import(ctx context.Context, req *descope.ImportProjectRequest) error {
	_, err := p.client.DoPostRequest(ctx, api.Routes.ManagementProjectImport(), req, nil, p.conf.ManagementKey)
	return err
}

func (p *project) ValidateImport(ctx context.Context, req *descope.ImportProjectRequest) (*descope.ValidateImportProjectResponse, error) {
	res, err := p.client.DoPostRequest(ctx, api.Routes.ManagementProjectImportValidate(), req, nil, p.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	var validation descope.ValidateImportProjectResponse
	if err := utils.Unmarshal([]byte(res.BodyStr), &validation); err != nil {
		return nil, err // notest
	}
	return &validation, nil
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
