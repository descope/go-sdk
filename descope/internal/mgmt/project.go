package mgmt

import (
	"context"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/sdk"
)

type project struct {
	managementBase
}

var _ sdk.Project = &project{}

type updateProjectBody struct {
	Name string `json:"name"`
}

type setProjectTagsBody struct {
	Tags []string `json:"tags"`
}

type cloneProjectBody struct {
	Name        string   `json:"name"`
	Environment string   `json:"environment"`
	Tags        []string `json:"tags"`
}

func (p *project) Clone(ctx context.Context, name string, environment descope.ProjectEnvironment, tags []string) (*descope.CloneProjectResponse, error) {
	body := cloneProjectBody{Name: name, Environment: string(environment), Tags: tags}
	res, err := p.client.DoPostRequest(ctx, api.Routes.ManagementProjectClone(), body, nil, p.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalNewProjectResponseResponse(res)
}

func (p *project) UpdateName(ctx context.Context, name string) error {
	body := updateProjectBody{Name: name}
	_, err := p.client.DoPostRequest(ctx, api.Routes.ManagementProjectUpdateName(), body, nil, p.conf.ManagementKey)
	return err
}

func (p *project) UpdateTags(ctx context.Context, tags []string) error {
	body := setProjectTagsBody{Tags: tags}
	_, err := p.client.DoPostRequest(ctx, api.Routes.ManagementProjectUpdateTags(), body, nil, p.conf.ManagementKey)
	return err
}

func (p *project) Delete(ctx context.Context) error {
	_, err := p.client.DoPostRequest(ctx, api.Routes.ManagementProjectDelete(), nil, nil, p.conf.ManagementKey)
	return err
}

func (p *project) ListProjects(ctx context.Context) ([]*descope.Project, error) {
	res, err := p.client.DoPostRequest(ctx, api.Routes.ManagementProjectsList(), nil, nil, p.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	var response struct {
		Projects []*descope.Project `json:"projects"`
	}
	if err := utils.Unmarshal([]byte(res.BodyStr), &response); err != nil {
		return nil, err // notest
	}
	return response.Projects, nil
}

func (p *project) ExportSnapshot(ctx context.Context) (*descope.ExportSnapshotResponse, error) {
	body := map[string]any{}
	res, err := p.client.DoPostRequest(ctx, api.Routes.ManagementProjectExportSnapshot(), body, nil, p.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	var export descope.ExportSnapshotResponse
	if err := utils.Unmarshal([]byte(res.BodyStr), &export); err != nil {
		return nil, err // notest
	}
	return &export, nil
}

func (p *project) ImportSnapshot(ctx context.Context, req *descope.ImportSnapshotRequest) error {
	_, err := p.client.DoPostRequest(ctx, api.Routes.ManagementProjectImportSnapshot(), req, nil, p.conf.ManagementKey)
	return err
}

func (p *project) ValidateSnapshot(ctx context.Context, req *descope.ValidateSnapshotRequest) (*descope.ValidateSnapshotResponse, error) {
	res, err := p.client.DoPostRequest(ctx, api.Routes.ManagementProjectValidateSnapshot(), req, nil, p.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	var validation descope.ValidateSnapshotResponse
	if err := utils.Unmarshal([]byte(res.BodyStr), &validation); err != nil {
		return nil, err // notest
	}
	return &validation, nil
}

func unmarshalNewProjectResponseResponse(res *api.HTTPResponse) (*descope.CloneProjectResponse, error) {
	var newProjectRes *descope.CloneProjectResponse
	err := utils.Unmarshal([]byte(res.BodyStr), &newProjectRes)
	if err != nil {
		return nil, err
	}
	return newProjectRes, err
}
