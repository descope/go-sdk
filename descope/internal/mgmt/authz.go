package mgmt

import (
	"context"
	"time"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/sdk"
)

type authz struct {
	managementBase
}

var _ sdk.Authz = &authz{}

func (a *authz) SaveSchema(ctx context.Context, schema *descope.AuthzSchema, upgrade bool) error {
	if schema == nil {
		return utils.NewInvalidArgumentError("schema")
	}
	body := map[string]any{
		"schema":  schema,
		"upgrade": upgrade,
	}
	_, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAuthzSchemaSave(), body, nil, "")
	return err
}

func (a *authz) DeleteSchema(ctx context.Context) error {
	_, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAuthzSchemaDelete(), nil, nil, "")
	return err
}

type loadSchemaResponse struct {
	Schema *descope.AuthzSchema `json:"schema"`
}

func (a *authz) LoadSchema(ctx context.Context) (*descope.AuthzSchema, error) {
	res, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAuthzSchemaLoad(), nil, nil, "")
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

func (a *authz) SaveNamespace(ctx context.Context, namespace *descope.AuthzNamespace, oldName, schemaName string) error {
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
	_, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAuthzNSSave(), body, nil, "")
	return err
}

func (a *authz) DeleteNamespace(ctx context.Context, name, schemaName string) error {
	if name == "" {
		return utils.NewInvalidArgumentError("name")
	}
	body := map[string]any{
		"name": name,
	}
	if schemaName != "" {
		body["schemaName"] = schemaName
	}
	_, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAuthzNSDelete(), body, nil, "")
	return err
}

func (a *authz) SaveRelationDefinition(ctx context.Context, relationDefinition *descope.AuthzRelationDefinition, namespace, oldName, schemaName string) error {
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
	_, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAuthzRDSave(), body, nil, "")
	return err
}

func (a *authz) DeleteRelationDefinition(ctx context.Context, name, namespace, schemaName string) error {
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
	_, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAuthzRDDelete(), body, nil, "")
	return err
}

func (a *authz) CreateRelations(ctx context.Context, relations []*descope.AuthzRelation) error {
	if len(relations) == 0 {
		return utils.NewInvalidArgumentError("relations")
	}
	body := map[string]any{
		"relations": relations,
	}
	_, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAuthzRECreate(), body, nil, "")
	return err
}

func (a *authz) DeleteRelations(ctx context.Context, relations []*descope.AuthzRelation) error {
	if len(relations) == 0 {
		return utils.NewInvalidArgumentError("relations")
	}
	body := map[string]any{
		"relations": relations,
	}
	_, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAuthzREDelete(), body, nil, "")
	return err
}

func (a *authz) DeleteRelationsForResources(ctx context.Context, resources []string) error {
	if len(resources) == 0 {
		return utils.NewInvalidArgumentError("resources")
	}
	body := map[string]any{
		"resources": resources,
	}
	_, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAuthzREDeleteResources(), body, nil, "")
	return err
}

type relationQueriesResponse struct {
	RelationQueries []*descope.AuthzRelationQuery `json:"relationQueries"`
}

func (a *authz) HasRelations(ctx context.Context, relationQueries []*descope.AuthzRelationQuery) ([]*descope.AuthzRelationQuery, error) {
	if len(relationQueries) == 0 {
		return nil, utils.NewInvalidArgumentError("relationQueries")
	}
	body := map[string]any{
		"relationQueries": relationQueries,
	}
	res, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAuthzREHasRelations(), body, nil, "")
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

func (a *authz) WhoCanAccess(ctx context.Context, resource, relationDefinition, namespace string) ([]string, error) {
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
	res, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAuthzREWho(), body, nil, "")
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

type resourcesResponse struct {
	Resources []string `json:"resources"`
}

func (a *authz) ResourceRelations(ctx context.Context, resource string) ([]*descope.AuthzRelation, error) {
	return a.ResourceRelationsWithTargetSetsFilter(ctx, resource, true)
}

func (a *authz) ResourceRelationsWithTargetSetsFilter(ctx context.Context, resource string, includeTargetSetRelations bool) ([]*descope.AuthzRelation, error) {
	if resource == "" {
		return nil, utils.NewInvalidArgumentError("resource")
	}
	body := map[string]any{
		"resource":                 resource,
		"ignoreTargetSetRelations": !includeTargetSetRelations,
	}
	res, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAuthzREResource(), body, nil, "")
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

func (a *authz) TargetsRelations(ctx context.Context, targets []string) ([]*descope.AuthzRelation, error) {
	return a.TargetsRelationsWithTargetSetsFilter(ctx, targets, false)
}

func (a *authz) TargetsRelationsWithTargetSetsFilter(ctx context.Context, targets []string, includeTargetSetRelations bool) ([]*descope.AuthzRelation, error) {
	if len(targets) == 0 {
		return nil, utils.NewInvalidArgumentError("targets")
	}
	body := map[string]any{
		"targets":                   targets,
		"includeTargetSetRelations": includeTargetSetRelations,
	}
	res, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAuthzRETargets(), body, nil, "")
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

func (a *authz) WhatCanTargetAccess(ctx context.Context, target string) ([]*descope.AuthzRelation, error) {
	if target == "" {
		return nil, utils.NewInvalidArgumentError("target")
	}
	body := map[string]any{
		"target": target,
	}
	res, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAuthzRETargetAll(), body, nil, "")
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

func (a *authz) WhatCanTargetAccessWithRelation(ctx context.Context, target, relationDefinition, namespace string) ([]*descope.AuthzRelation, error) {
	if target == "" {
		return nil, utils.NewInvalidArgumentError("target")
	}
	if relationDefinition == "" {
		return nil, utils.NewInvalidArgumentError("relationDefinition")
	}
	if namespace == "" {
		return nil, utils.NewInvalidArgumentError("namespace")
	}
	body := map[string]any{
		"target":             target,
		"relationDefinition": relationDefinition,
		"namespace":          namespace,
	}
	res, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAuthzRETargetWithRelation(), body, nil, "")
	if err != nil {
		// notest
		return nil, err
	}
	var response *resourcesResponse
	err = utils.Unmarshal([]byte(res.BodyStr), &response)
	if err != nil {
		// notest
		return nil, err
	}

	var resp []*descope.AuthzRelation
	for _, resource := range response.Resources {
		resp = append(resp, &descope.AuthzRelation{
			Resource:           resource,
			Target:             target,
			RelationDefinition: relationDefinition,
			Namespace:          namespace,
		})
	}
	return resp, nil
}

func (a *authz) GetModified(ctx context.Context, since time.Time) (*descope.AuthzModified, error) {
	body := map[string]any{}
	if !since.IsZero() {
		now := time.Now()
		if since.After(now) || since.Before(now.AddDate(0, 0, -1)) {
			return nil, utils.NewInvalidArgumentError("since")
		}
		body["since"] = since.UnixMilli()
	}
	res, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAuthzGetModified(), body, nil, "")
	if err != nil {
		// notest
		return nil, err
	}
	var response *descope.AuthzModified
	err = utils.Unmarshal([]byte(res.BodyStr), &response)
	if err != nil {
		// notest
		return nil, err
	}
	return response, nil
}
