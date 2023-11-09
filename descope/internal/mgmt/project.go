package mgmt

import (
	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
)

type projectBody struct {
	Files map[string]any `json:"files"`
}

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

func (p *project) ExportRaw() (map[string]any, error) {
	body := map[string]any{}
	res, err := p.client.DoPostRequest(api.Routes.ManagementProjectExport(), body, nil, p.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	var export projectBody
	if err := utils.Unmarshal([]byte(res.BodyStr), &export); err != nil {
		return nil, err // notest
	}
	return export.Files, nil
}

func (p *project) ImportRaw(files map[string]any) error {
	body := projectBody{Files: files}
	_, err := p.client.DoPostRequest(api.Routes.ManagementProjectImport(), body, nil, p.conf.ManagementKey)
	return err
}

func (p *project) UpdateName(name string) error {
	body := updateProjectBody{Name: name}
	_, err := p.client.DoPostRequest(api.Routes.ManagementProjectUpdateName(), body, nil, p.conf.ManagementKey)
	return err
}

func (p *project) Clone(name string, tag descope.ProjectTag) (*descope.NewProjectResponse, error) {
	body := cloneProjectBody{Name: name, Tag: string(tag)}
	res, err := p.client.DoPostRequest(api.Routes.ManagementProjectClone(), body, nil, p.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalNewProjectResponseResponse(res)
}

func unmarshalNewProjectResponseResponse(res *api.HTTPResponse) (*descope.NewProjectResponse, error) {
	var newProjectRes *descope.NewProjectResponse
	err := utils.Unmarshal([]byte(res.BodyStr), &newProjectRes)
	if err != nil {
		return nil, err
	}
	return newProjectRes, err
}
