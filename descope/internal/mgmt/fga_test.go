package mgmt

import (
	"context"
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/tests/helpers"
	"github.com/stretchr/testify/require"
)

func TestSaveFGASchemaSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.NotNil(t, req["dsl"])
		require.Equal(t, "some schema", req["dsl"])
	}))
	err := mgmt.FGA().SaveSchema(context.Background(), &descope.FGASchema{Schema: "some schema"})
	require.NoError(t, err)
}

func TestSaveFGASchemaMissingSchema(t *testing.T) {
	mgmt := newTestMgmt(nil, nil)
	err := mgmt.FGA().SaveSchema(context.Background(), nil)
	require.Error(t, err)
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("schema").Message)
}

func TestCreateFGARelationsSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.NotNil(t, req["tuples"])
		require.Equal(t, "g1", req["tuples"].([]any)[0].(map[string]any)["resource"])
		require.Equal(t, "group", req["tuples"].([]any)[0].(map[string]any)["resourceType"])
		require.Equal(t, "member", req["tuples"].([]any)[0].(map[string]any)["relation"])
		require.Equal(t, "u1", req["tuples"].([]any)[0].(map[string]any)["target"])
		require.Equal(t, "user", req["tuples"].([]any)[0].(map[string]any)["targetType"])
	}))
	err := mgmt.FGA().CreateRelations(context.Background(), []*descope.FGARelation{{Resource: "g1", ResourceType: "group", Relation: "member", Target: "u1", TargetType: "user"}})
	require.NoError(t, err)
}

func TestCreateFGARelationsMissingTuples(t *testing.T) {
	mgmt := newTestMgmt(nil, nil)
	err := mgmt.FGA().CreateRelations(context.Background(), nil)
	require.Error(t, err)
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("relations").Message)
}

func TestDeleteFGARelationsSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.NotNil(t, req["tuples"])
		require.Equal(t, "g1", req["tuples"].([]any)[0].(map[string]any)["resource"])
		require.Equal(t, "group", req["tuples"].([]any)[0].(map[string]any)["resourceType"])
		require.Equal(t, "member", req["tuples"].([]any)[0].(map[string]any)["relation"])
		require.Equal(t, "u1", req["tuples"].([]any)[0].(map[string]any)["target"])
		require.Equal(t, "user", req["tuples"].([]any)[0].(map[string]any)["targetType"])
	}))
	err := mgmt.FGA().DeleteRelations(context.Background(), []*descope.FGARelation{{Resource: "g1", ResourceType: "group", Relation: "member", Target: "u1", TargetType: "user"}})
	require.NoError(t, err)
}

func TestDeleteFGARelationsMissingTuples(t *testing.T) {
	mgmt := newTestMgmt(nil, nil)
	err := mgmt.FGA().DeleteRelations(context.Background(), nil)
	require.Error(t, err)
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("relations").Message)
}

func TestCheckFGARelationsSuccess(t *testing.T) {
	response := map[string]any{
		"tuples": []*descope.FGACheck{
			{
				Allowed:  true,
				Relation: &descope.FGARelation{Resource: "g1", ResourceType: "group", Relation: "member", Target: "u1", TargetType: "user"},
			},
		}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.NotNil(t, req["tuples"])
		relation := req["tuples"].([]any)[0].(map[string]any)
		require.NotNil(t, relation)
		require.Equal(t, "g1", relation["resource"])
		require.Equal(t, "group", relation["resourceType"])
		require.Equal(t, "member", relation["relation"])
		require.Equal(t, "u1", relation["target"])
		require.Equal(t, "user", relation["targetType"])
	}, response))
	checks, err := mgmt.FGA().Check(context.Background(), []*descope.FGARelation{
		{Resource: "g1", ResourceType: "group", Relation: "member", Target: "u1", TargetType: "user"},
	})
	require.NoError(t, err)
	require.Len(t, checks, 1)
	require.True(t, checks[0].Allowed)
}

func TestCheckFGARelationsMissingTuples(t *testing.T) {
	mgmt := newTestMgmt(nil, nil)
	_, err := mgmt.FGA().Check(context.Background(), nil)
	require.Error(t, err)
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("relations").Message)
}
