package mgmt

import (
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
)

type projectBody struct {
	Files map[string]any `json:"files"`
}

type project struct {
	managementBase
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
