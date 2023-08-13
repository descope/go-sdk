package mgmt

import (
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
)

type environmentBody struct {
	Files map[string]any `json:"files"`
}

type environment struct {
	managementBase
}

func (e *environment) ExportRaw() (map[string]any, error) {
	body := map[string]any{}
	res, err := e.client.DoPostRequest(api.Routes.ManagementEnvironmentExport(), body, nil, e.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	var export environmentBody
	if err := utils.Unmarshal([]byte(res.BodyStr), &export); err != nil {
		return nil, err // notest
	}
	return export.Files, nil
}

func (e *environment) ImportRaw(files map[string]any) error {
	body := environmentBody{Files: files}
	_, err := e.client.DoPostRequest(api.Routes.ManagementEnvironmentImport(), body, nil, e.conf.ManagementKey)
	return err
}
