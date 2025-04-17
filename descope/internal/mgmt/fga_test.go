package mgmt

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/tests/helpers"
	"github.com/stretchr/testify/require"
)

func TestFGACacheURL(t *testing.T) {
	mgmtWithFGACache := newTestMgmtConf(&ManagementParams{FGACacheURL: "https://my.auth"}, nil, helpers.DoOk(func(r *http.Request) {
		require.True(t, strings.HasPrefix(r.URL.String(), "https://my.auth"))
	}))
	mgmtWithoutFGACache := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.True(t, strings.HasPrefix(r.URL.String(), "https://api.descope.co"))
	}))

	tt := []struct {
		name string
		mgmt *managementService
	}{
		{"WithFGACacheURL", mgmtWithFGACache},
		{"WithoutFGACacheURL", mgmtWithoutFGACache},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.mgmt.FGA().SaveSchema(context.Background(), &descope.FGASchema{Schema: "some schema"})
			require.NoError(t, err)
			err = tc.mgmt.FGA().CreateRelations(context.Background(), []*descope.FGARelation{{Resource: "g1", ResourceType: "group", Relation: "member", Target: "u1", TargetType: "user"}})
			require.NoError(t, err)
			err = tc.mgmt.FGA().DeleteRelations(context.Background(), []*descope.FGARelation{{Resource: "g1", ResourceType: "group", Relation: "member", Target: "u1", TargetType: "user"}})
			require.NoError(t, err)
			_, err = tc.mgmt.FGA().Check(context.Background(), []*descope.FGARelation{
				{Resource: "g1", ResourceType: "group", Relation: "member", Target: "u1", TargetType: "user"},
			})
			require.NoError(t, err)
		})
	}

}

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

func TestLoadFGASchemaSuccess(t *testing.T) {
	response := map[string]any{"dsl": "some schema"}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
	}, response))
	schema, err := mgmt.FGA().LoadSchema(context.Background())
	require.NoError(t, err)
	require.Equal(t, "some schema", schema.Schema)
}

func TestLoadFGASchemaError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	_, err := mgmt.FGA().LoadSchema(context.Background())
	require.Error(t, err)
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
	// init table test
	tt := []struct {
		name string
		info *descope.FGACheckInfo
	}{
		{"WithInfo", &descope.FGACheckInfo{Direct: true}},
		{"WithoutInfo", nil},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			response := map[string]any{
				"tuples": []*descope.FGACheck{
					{
						Allowed:  true,
						Relation: &descope.FGARelation{Resource: "g1", ResourceType: "group", Relation: "member", Target: "u1", TargetType: "user"},
						Info:     tc.info,
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
			if tc.info != nil {
				require.True(t, checks[0].Info.Direct)
			} else {
				require.False(t, checks[0].Info.Direct) // backwards compatibility - should be false if not present, and not panic
			}
		})
	}
}

func TestCheckFGARelationsMissingTuples(t *testing.T) {
	mgmt := newTestMgmt(nil, nil)
	_, err := mgmt.FGA().Check(context.Background(), nil)
	require.Error(t, err)
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("relations").Message)
}

func TestLoadMappableSchemaSuccess(t *testing.T) {
	response := &descope.FGAMappableSchema{
		Schema: &descope.AuthzSchema{
			Name: "testSchema",
		},
		MappableResources: []*descope.FGAMappableResources{
			{
				Type: "type1",
				Resources: []*descope.FGAMappableResource{
					{Resource: "res1"},
					{Resource: "res2"},
				},
			},
			{
				Type: "type2",
				Resources: []*descope.FGAMappableResource{
					{Resource: "res3"},
				},
			},
		},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		require.Equal(t, "t1", r.URL.Query().Get("tenantId"))
		require.Empty(t, r.URL.Query().Get("resourcesLimit"))
	}, response))
	schema, err := mgmt.FGA().LoadMappableSchema(context.Background(), "t1", nil)
	require.NoError(t, err)
	require.NotNil(t, schema.Schema)
	require.Equal(t, response.Schema.Name, schema.Schema.Name)
	require.Len(t, schema.MappableResources, 2)
	require.Equal(t, "type1", schema.MappableResources[0].Type)
	require.Len(t, schema.MappableResources[0].Resources, 2)
	require.Equal(t, "res1", schema.MappableResources[0].Resources[0].Resource)
	require.Equal(t, "res2", schema.MappableResources[0].Resources[1].Resource)
	require.Equal(t, "type2", schema.MappableResources[1].Type)
	require.Len(t, schema.MappableResources[1].Resources, 1)
	require.Equal(t, "res3", schema.MappableResources[1].Resources[0].Resource)
}

func TestLoadMappableSchemaSuccessWithOptions(t *testing.T) {
	response := &descope.FGAMappableSchema{
		Schema: &descope.AuthzSchema{
			Name: "testSchema",
		},
		MappableResources: []*descope.FGAMappableResources{
			{
				Type: "type1",
				Resources: []*descope.FGAMappableResource{
					{Resource: "res1"},
				},
			},
		},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		require.Equal(t, "t1", r.URL.Query().Get("tenantId"))
		require.Equal(t, "10", r.URL.Query().Get("resourcesLimit"))
	}, response))
	options := &descope.FGAMappableResourcesOptions{ResourcesLimit: 10}
	schema, err := mgmt.FGA().LoadMappableSchema(context.Background(), "t1", options)
	require.NoError(t, err)
	require.NotNil(t, schema.Schema)
	require.Equal(t, response.Schema.Name, schema.Schema.Name)
	require.Len(t, schema.MappableResources, 1)
	require.Equal(t, "type1", schema.MappableResources[0].Type)
	require.Len(t, schema.MappableResources[0].Resources, 1)
	require.Equal(t, "res1", schema.MappableResources[0].Resources[0].Resource)
}

func TestLoadMappableSchemaMissingTenantID(t *testing.T) {
	mgmt := newTestMgmt(nil, nil)
	_, err := mgmt.FGA().LoadMappableSchema(context.Background(), "", nil)
	require.Error(t, err)
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("tenantID").Message)
}

func TestLoadMappableSchemaError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	_, err := mgmt.FGA().LoadMappableSchema(context.Background(), "t1", nil)
	require.Error(t, err)
}

func TestSearchMappableResourcesSuccess(t *testing.T) {
	response := &mappableResourcesResponse{
		FGAMappableResources: []*descope.FGAMappableResources{
			{
				Type: "type1",
				Resources: []*descope.FGAMappableResource{
					{Resource: "id1"},
					{Resource: "id2"},
				},
			},
		},
	}
	queries := []*descope.FGAMappableResourcesQuery{
		{Type: "type1", Queries: []string{"id1", "id2"}},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "t1", req["tenantId"])
		require.Len(t, req["resourcesQueries"], 1)
		query := req["resourcesQueries"].([]any)[0].(map[string]any)
		require.Equal(t, "type1", query["type"])
		require.EqualValues(t, []interface{}{"id1", "id2"}, query["queries"])
		_, hasLimit := req["resourcesLimit"]
		require.False(t, hasLimit)
	}, response))
	resources, err := mgmt.FGA().SearchMappableResources(context.Background(), "t1", queries, nil)
	require.NoError(t, err)
	require.Len(t, resources, 1)
	require.Equal(t, "type1", resources[0].Type)
	require.Len(t, resources[0].Resources, 2)
	require.Equal(t, "id1", resources[0].Resources[0].Resource)
	require.Equal(t, "id2", resources[0].Resources[1].Resource)
}

func TestSearchMappableResourcesSuccessWithOptions(t *testing.T) {
	response := &mappableResourcesResponse{
		FGAMappableResources: []*descope.FGAMappableResources{
			{
				Type: "type1",
				Resources: []*descope.FGAMappableResource{
					{Resource: "id1"},
					{Resource: "id2"},
				},
			},
		},
	}
	queries := []*descope.FGAMappableResourcesQuery{
		{Type: "type1", Queries: []string{"id"}},
	}
	options := &descope.FGAMappableResourcesOptions{ResourcesLimit: 5}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "t1", req["tenantId"])
		require.Len(t, req["resourcesQueries"], 1)
		query := req["resourcesQueries"].([]any)[0].(map[string]any)
		require.Equal(t, "type1", query["type"])
		require.EqualValues(t, []interface{}{"id"}, query["queries"])
		require.Equal(t, "5", req["resourcesLimit"])
	}, response))
	resources, err := mgmt.FGA().SearchMappableResources(context.Background(), "t1", queries, options)
	require.NoError(t, err)
	require.Len(t, resources, 1)
	require.Equal(t, "type1", resources[0].Type)
	require.Len(t, resources[0].Resources, 2)
	require.Equal(t, "id1", resources[0].Resources[0].Resource)
	require.Equal(t, "id2", resources[0].Resources[1].Resource)
}

func TestSearchMappableResourcesMissingTenantID(t *testing.T) {
	mgmt := newTestMgmt(nil, nil)
	queries := []*descope.FGAMappableResourcesQuery{{Type: "type1"}}
	_, err := mgmt.FGA().SearchMappableResources(context.Background(), "", queries, nil)
	require.Error(t, err)
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("tenantID").Message)
}

func TestSearchMappableResourcesMissingQueries(t *testing.T) {
	mgmt := newTestMgmt(nil, nil)
	_, err := mgmt.FGA().SearchMappableResources(context.Background(), "t1", nil, nil)
	require.Error(t, err)
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("resourcesQueries").Message)

	_, err = mgmt.FGA().SearchMappableResources(context.Background(), "t1", []*descope.FGAMappableResourcesQuery{}, nil)
	require.Error(t, err)
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("resourcesQueries").Message)
}

func TestSearchMappableResourcesError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	queries := []*descope.FGAMappableResourcesQuery{{Type: "type1"}}
	_, err := mgmt.FGA().SearchMappableResources(context.Background(), "t1", queries, nil)
	require.Error(t, err)
}
