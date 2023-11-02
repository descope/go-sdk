package mgmt

import (
	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
)

type authz struct {
	managementBase
}

func (a *authz) SaveSchema(schema *descope.AuthzSchema, upgrade bool) error {
	if schema == nil {
		return utils.NewInvalidArgumentError("schema")
	}
	body := map[string]any{
		"schema":  schema,
		"upgrade": upgrade,
	}
	_, err := a.client.DoPostRequest(api.Routes.ManagementAuthzSchemaSave(), body, nil, a.conf.ManagementKey)
	return err
}

func (a *authz) DeleteSchema() error {
	_, err := a.client.DoPostRequest(api.Routes.ManagementAuthzSchemaDelete(), nil, nil, a.conf.ManagementKey)
	return err
}

type loadSchemaResponse struct {
	Schema *descope.AuthzSchema `json:"schema"`
}

func (a *authz) LoadSchema() (*descope.AuthzSchema, error) {
	res, err := a.client.DoPostRequest(api.Routes.ManagementAuthzSchemaLoad(), nil, nil, a.conf.ManagementKey)
	if err != nil {
		// notest
		return nil, err
	}
	var schema *loadSchemaResponse
	err = utils.Unmarshal([]byte(res.BodyStr), &schema)
	if err != nil {
		// notest
		return nil, err
	}
	return schema.Schema, nil
}

func (a *authz) SaveNamespace(namespace *descope.AuthzNamespace, oldName, schemaName string) error {
	if namespace == nil {
		return utils.NewInvalidArgumentError("namespace")
	}
	body := map[string]any{
		"namespace": namespace,
	}
	if oldName != "" {
		body["oldName"] = oldName
	}
	if schemaName != "" {
		body["schemaName"] = schemaName
	}
	_, err := a.client.DoPostRequest(api.Routes.ManagementAuthzNSSave(), body, nil, a.conf.ManagementKey)
	return err
}

func (a *authz) DeleteNamespace(name, schemaName string) error {
	if name == "" {
		return utils.NewInvalidArgumentError("name")
	}
	body := map[string]any{
		"name": name,
	}
	if schemaName != "" {
		body["schemaName"] = schemaName
	}
	_, err := a.client.DoPostRequest(api.Routes.ManagementAuthzNSDelete(), body, nil, a.conf.ManagementKey)
	return err
}

func (a *authz) SaveRelationDefinition(relationDefinition *descope.AuthzRelationDefinition, namespace, oldName, schemaName string) error {
	if relationDefinition == nil {
		return utils.NewInvalidArgumentError("relationDefinition")
	}
	if namespace == "" {
		return utils.NewInvalidArgumentError("namespace")
	}
	body := map[string]any{
		"relationDefinition": relationDefinition,
		"namespace":          namespace,
	}
	if oldName != "" {
		body["oldName"] = oldName
	}
	if schemaName != "" {
		body["schemaName"] = schemaName
	}
	_, err := a.client.DoPostRequest(api.Routes.ManagementAuthzRDSave(), body, nil, a.conf.ManagementKey)
	return err
}

func (a *authz) DeleteRelationDefinition(name, namespace, schemaName string) error {
	if name == "" {
		return utils.NewInvalidArgumentError("name")
	}
	if namespace == "" {
		return utils.NewInvalidArgumentError("namespace")
	}
	body := map[string]any{
		"name":      name,
		"namespace": namespace,
	}
	if schemaName != "" {
		body["schemaName"] = schemaName
	}
	_, err := a.client.DoPostRequest(api.Routes.ManagementAuthzRDDelete(), body, nil, a.conf.ManagementKey)
	return err
}

func (a *authz) CreateRelations(relations []*descope.AuthzRelation) error {
	if len(relations) == 0 {
		return utils.NewInvalidArgumentError("relations")
	}
	body := map[string]any{
		"relations": relations,
	}
	_, err := a.client.DoPostRequest(api.Routes.ManagementAuthzRECreate(), body, nil, a.conf.ManagementKey)
	return err
}

func (a *authz) DeleteRelations(relations []*descope.AuthzRelation) error {
	if len(relations) == 0 {
		return utils.NewInvalidArgumentError("relations")
	}
	body := map[string]any{
		"relations": relations,
	}
	_, err := a.client.DoPostRequest(api.Routes.ManagementAuthzREDelete(), body, nil, a.conf.ManagementKey)
	return err
}

func (a *authz) DeleteRelationsForResources(resources []string) error {
	if len(resources) == 0 {
		return utils.NewInvalidArgumentError("resources")
	}
	body := map[string]any{
		"resources": resources,
	}
	_, err := a.client.DoPostRequest(api.Routes.ManagementAuthzREDeleteResources(), body, nil, a.conf.ManagementKey)
	return err
}

type relationQueriesResponse struct {
	RelationQueries []*descope.AuthzRelationQuery `json:"relationQueries"`
}

func (a *authz) HasRelations(relationQueries []*descope.AuthzRelationQuery) ([]*descope.AuthzRelationQuery, error) {
	if len(relationQueries) == 0 {
		return nil, utils.NewInvalidArgumentError("relationQueries")
	}
	body := map[string]any{
		"relationQueries": relationQueries,
	}
	res, err := a.client.DoPostRequest(api.Routes.ManagementAuthzREHasRelations(), body, nil, a.conf.ManagementKey)
	if err != nil {
		// notest
		return nil, err
	}
	var response *relationQueriesResponse
	err = utils.Unmarshal([]byte(res.BodyStr), &response)
	if err != nil {
		// notest
		return nil, err
	}
	return response.RelationQueries, nil
}

type whoResponse struct {
	Targets []string `json:"targets"`
}

func (a *authz) WhoCanAccess(resource, relationDefinition, namespace string) ([]string, error) {
	if resource == "" {
		return nil, utils.NewInvalidArgumentError("resource")
	}
	if relationDefinition == "" {
		return nil, utils.NewInvalidArgumentError("relationDefinition")
	}
	if namespace == "" {
		return nil, utils.NewInvalidArgumentError("namespace")
	}
	body := map[string]any{
		"resource":           resource,
		"relationDefinition": relationDefinition,
		"namespace":          namespace,
	}
	res, err := a.client.DoPostRequest(api.Routes.ManagementAuthzREWho(), body, nil, a.conf.ManagementKey)
	if err != nil {
		// notest
		return nil, err
	}
	var response *whoResponse
	err = utils.Unmarshal([]byte(res.BodyStr), &response)
	if err != nil {
		// notest
		return nil, err
	}
	return response.Targets, nil
}

type relationsResponse struct {
	Relations []*descope.AuthzRelation `json:"relations"`
}

func (a *authz) ResourceRelations(resource string) ([]*descope.AuthzRelation, error) {
	if resource == "" {
		return nil, utils.NewInvalidArgumentError("resource")
	}
	body := map[string]any{
		"resource": resource,
	}
	res, err := a.client.DoPostRequest(api.Routes.ManagementAuthzREResource(), body, nil, a.conf.ManagementKey)
	if err != nil {
		// notest
		return nil, err
	}
	var response *relationsResponse
	err = utils.Unmarshal([]byte(res.BodyStr), &response)
	if err != nil {
		// notest
		return nil, err
	}
	return response.Relations, nil
}

func (a *authz) TargetsRelations(targets []string) ([]*descope.AuthzRelation, error) {
	if len(targets) == 0 {
		return nil, utils.NewInvalidArgumentError("targets")
	}
	body := map[string]any{
		"targets": targets,
	}
	res, err := a.client.DoPostRequest(api.Routes.ManagementAuthzRETargets(), body, nil, a.conf.ManagementKey)
	if err != nil {
		// notest
		return nil, err
	}
	var response *relationsResponse
	err = utils.Unmarshal([]byte(res.BodyStr), &response)
	if err != nil {
		// notest
		return nil, err
	}
	return response.Relations, nil
}

func (a *authz) WhatCanTargetAccess(target string) ([]*descope.AuthzRelation, error) {
	if target == "" {
		return nil, utils.NewInvalidArgumentError("target")
	}
	body := map[string]any{
		"target": target,
	}
	res, err := a.client.DoPostRequest(api.Routes.ManagementAuthzRETargetAll(), body, nil, a.conf.ManagementKey)
	if err != nil {
		// notest
		return nil, err
	}
	var response *relationsResponse
	err = utils.Unmarshal([]byte(res.BodyStr), &response)
	if err != nil {
		// notest
		return nil, err
	}
	return response.Relations, nil
}
