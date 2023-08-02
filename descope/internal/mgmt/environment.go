package mgmt

import (
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
)

type environment struct {
	managementBase
}

func (e *environment) ExportRaw() (map[string]any, error) {
	body := map[string]any{}
	res, err := e.client.DoPostRequest(api.Routes.ManagementEnvironmentExport(), body, nil, e.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := utils.Unmarshal([]byte(res.BodyStr), &m); err != nil {
		return nil, err // notest
	}
	return m, nil
}

func (e *environment) ImportRaw(body map[string]any) error {
	_, err := e.client.DoPostRequest(api.Routes.ManagementEnvironmentImport(), body, nil, e.conf.ManagementKey)
	return err
}
