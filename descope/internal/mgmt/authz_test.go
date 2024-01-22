package mgmt

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/tests/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSaveSchemaSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.NotNil(t, req["schema"])
		require.Equal(t, "kuku", req["schema"].(map[string]any)["name"])
		require.Equal(t, true, req["upgrade"])
	}))
	err := mgmt.Authz().SaveSchema(context.Background(), &descope.AuthzSchema{Name: "kuku"}, true)
	require.NoError(t, err)
}

func TestSaveSchemaMissingArgument(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.Authz().SaveSchema(context.Background(), nil, false)
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("schema").Message)
}

func TestDeleteSchemaSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
	}))
	err := mgmt.Authz().DeleteSchema(context.Background())
	require.NoError(t, err)
}

func TestSaveNamespaceSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.NotNil(t, req["namespace"])
		require.Equal(t, "kuku", req["namespace"].(map[string]any)["name"])
		require.Len(t, req["namespace"].(map[string]any)["relationDefinitions"], 1)
		require.Equal(t, "keke", req["oldName"])
		require.Equal(t, "kaka", req["schemaName"])
	}))
	err := mgmt.Authz().SaveNamespace(context.Background(), &descope.AuthzNamespace{
		Name: "kuku",
		RelationDefinitions: []*descope.AuthzRelationDefinition{
			{
				Name: "kiki",
			},
		},
	}, "keke", "kaka")
	require.NoError(t, err)
}

func TestSaveNamespaceMissingArgument(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.Authz().SaveNamespace(context.Background(), nil, "", "")
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("namespace").Message)
}

func TestSaveRelationDefinitionSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.NotNil(t, req["relationDefinition"])
		require.Equal(t, "kiki", req["relationDefinition"].(map[string]any)["name"])
		require.Equal(t, "kuku", req["namespace"])
		require.Equal(t, "keke", req["oldName"])
		require.Equal(t, "kaka", req["schemaName"])
	}))
	err := mgmt.Authz().SaveRelationDefinition(context.Background(), &descope.AuthzRelationDefinition{Name: "kiki"}, "kuku", "keke", "kaka")
	require.NoError(t, err)
}

func TestSaveRelationDefinitionMissingArgument(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.Authz().SaveRelationDefinition(context.Background(), nil, "", "", "")
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("relationDefinition").Message)
	err = mgmt.Authz().SaveRelationDefinition(context.Background(), &descope.AuthzRelationDefinition{Name: "kiki"}, "", "", "")
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("namespace").Message)
}

func TestLoadSchema(t *testing.T) {
	response := &descope.AuthzSchema{
		Name: "kuku",
		Namespaces: []*descope.AuthzNamespace{
			{
				Name: "ns1",
				RelationDefinitions: []*descope.AuthzRelationDefinition{
					{
						Name: "rd1",
					},
					{
						Name: "rd2",
						ComplexDefinition: &descope.AuthzNode{
							NType: descope.AuthzNodeTypeChild,
							Expression: &descope.AuthzNodeExpression{
								NEType:                            descope.AuthzNodeExpressionTypeRelationLeft,
								RelationDefinition:                "rd3",
								RelationDefinitionNamespace:       "ns3",
								TargetRelationDefinition:          "rd4",
								TargetRelationDefinitionNamespace: "ns4",
							},
						},
					},
				},
			},
		},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
	}, map[string]any{"schema": response}))
	res, err := mgmt.Authz().LoadSchema(context.Background())
	require.NoError(t, err)
	assert.EqualValues(t, response, res)
}

func TestCreateRelationsSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.NotNil(t, req["relations"])
		require.Equal(t, "r", req["relations"].([]any)[0].(map[string]any)["resource"])
		require.Equal(t, "rd", req["relations"].([]any)[0].(map[string]any)["relationDefinition"])
		require.Equal(t, "ns", req["relations"].([]any)[0].(map[string]any)["namespace"])
		require.Equal(t, "t", req["relations"].([]any)[0].(map[string]any)["target"])
	}))
	err := mgmt.Authz().CreateRelations(context.Background(), []*descope.AuthzRelation{{Resource: "r", RelationDefinition: "rd", Namespace: "ns", Target: "t"}})
	require.NoError(t, err)
}

func TestCreateRelationsMissingArgument(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.Authz().CreateRelations(context.Background(), nil)
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("relations").Message)
}

func TestDeleteRelationsSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.NotNil(t, req["relations"])
		require.Equal(t, "r", req["relations"].([]any)[0].(map[string]any)["resource"])
		require.Equal(t, "rd", req["relations"].([]any)[0].(map[string]any)["relationDefinition"])
		require.Equal(t, "ns", req["relations"].([]any)[0].(map[string]any)["namespace"])
		require.Equal(t, "t", req["relations"].([]any)[0].(map[string]any)["target"])
	}))
	err := mgmt.Authz().DeleteRelations(context.Background(), []*descope.AuthzRelation{{Resource: "r", RelationDefinition: "rd", Namespace: "ns", Target: "t"}})
	require.NoError(t, err)
}

func TestDeleteRelationsMissingArgument(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.Authz().DeleteRelations(context.Background(), nil)
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("relations").Message)
}

func TestDeleteRelationsForResourcesSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.NotNil(t, req["resources"])
		require.Equal(t, "1", req["resources"].([]any)[0])
	}))
	err := mgmt.Authz().DeleteRelationsForResources(context.Background(), []string{"1"})
	require.NoError(t, err)
}

func TestDeleteRelationsForResourcesMissingArgument(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.Authz().DeleteRelationsForResources(context.Background(), nil)
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("resources").Message)
}

func TestHasRelationsSuccess(t *testing.T) {
	response := []*descope.AuthzRelationQuery{
		{
			Resource:           "r",
			RelationDefinition: "rd",
			Namespace:          "ns",
			Target:             "t",
			HasRelation:        true,
		},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.NotNil(t, req["relationQueries"])
		require.Equal(t, "r", req["relationQueries"].([]any)[0].(map[string]any)["resource"])
		require.Equal(t, "rd", req["relationQueries"].([]any)[0].(map[string]any)["relationDefinition"])
		require.Equal(t, "ns", req["relationQueries"].([]any)[0].(map[string]any)["namespace"])
		require.Equal(t, "t", req["relationQueries"].([]any)[0].(map[string]any)["target"])
	}, map[string]any{"relationQueries": response}))
	res, err := mgmt.Authz().HasRelations(context.Background(), response)
	require.NoError(t, err)
	assert.EqualValues(t, response, res)
}

func TestHasRelationsMissingArgument(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, err := mgmt.Authz().HasRelations(context.Background(), nil)
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("relationQueries").Message)
}

func TestWhoCanAccessSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "r", req["resource"])
		require.Equal(t, "rd", req["relationDefinition"])
		require.Equal(t, "ns", req["namespace"])
	}, map[string]any{"targets": []string{"u1"}}))
	res, err := mgmt.Authz().WhoCanAccess(context.Background(), "r", "rd", "ns")
	require.NoError(t, err)
	assert.EqualValues(t, []string{"u1"}, res)
}

func TestWhoCanAccessMissingArgument(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, err := mgmt.Authz().WhoCanAccess(context.Background(), "", "", "")
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("resource").Message)
	_, err = mgmt.Authz().WhoCanAccess(context.Background(), "r", "", "")
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("relationDefinition").Message)
	_, err = mgmt.Authz().WhoCanAccess(context.Background(), "r", "rd", "")
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("namespace").Message)
}

func TestResourceRelationsSuccess(t *testing.T) {
	response := []*descope.AuthzRelation{
		{
			Resource:           "r",
			RelationDefinition: "rd",
			Namespace:          "n",
			Target:             "t",
		},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "r", req["resource"])
	}, map[string]any{"relations": response}))
	res, err := mgmt.Authz().ResourceRelations(context.Background(), "r")
	require.NoError(t, err)
	assert.EqualValues(t, response, res)
}

func TestResourceRelationsMissingArgument(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, err := mgmt.Authz().ResourceRelations(context.Background(), "")
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("resource").Message)
}

func TestTargetsRelationsSuccess(t *testing.T) {
	response := []*descope.AuthzRelation{
		{
			Resource:           "r",
			RelationDefinition: "rd",
			Namespace:          "n",
			Target:             "t",
		},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "u1", req["targets"].([]any)[0])
	}, map[string]any{"relations": response}))
	res, err := mgmt.Authz().TargetsRelations(context.Background(), []string{"u1"})
	require.NoError(t, err)
	assert.EqualValues(t, response, res)
}

func TestTargetsRelationsMissingArgument(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, err := mgmt.Authz().TargetsRelations(context.Background(), nil)
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("targets").Message)
}

func TestWhatCanTargetAccessSuccess(t *testing.T) {
	response := []*descope.AuthzRelation{
		{
			Resource:           "r",
			RelationDefinition: "rd",
			Namespace:          "n",
			Target:             "t",
		},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "u1", req["target"])
	}, map[string]any{"relations": response}))
	res, err := mgmt.Authz().WhatCanTargetAccess(context.Background(), "u1")
	require.NoError(t, err)
	assert.EqualValues(t, response, res)
}

func TestWhatCanTargetAccessMissingArgument(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, err := mgmt.Authz().WhatCanTargetAccess(context.Background(), "")
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("target").Message)
}

func TestGetModifiedWrongArgument(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, err := mgmt.Authz().GetModified(context.Background(), time.Now().Add(10*time.Second))
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("since").Message)
	_, err = mgmt.Authz().GetModified(context.Background(), time.Now().AddDate(0, 0, -2))
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("since").Message)
}
