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
	response := map[string]any{
		"dsl": "some schema",
		"schema": map[string]any{
			"conditions": []map[string]any{
				{"name": "DuringShift", "expression": "now >= begin", "checkedExpr": []byte("checked-program-bytes"), "params": []map[string]any{{"name": "now", "type": "int"}, {"name": "begin", "type": "int"}}},
			},
		},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
	}, response))
	schema, err := mgmt.FGA().LoadSchema(context.Background())
	require.NoError(t, err)
	require.Equal(t, "some schema", schema.Schema)
	require.Len(t, schema.Conditions, 1)
	require.Equal(t, "DuringShift", schema.Conditions[0].Name)
	require.Equal(t, "now >= begin", schema.Conditions[0].Expression)
	require.Equal(t, []byte("checked-program-bytes"), schema.Conditions[0].CheckedExpr, "checkedExpr must round-trip (base64 over JSON)")
	require.Len(t, schema.Conditions[0].Params, 2)
	require.Equal(t, "now", schema.Conditions[0].Params[0].Name)
	require.Equal(t, "int", schema.Conditions[0].Params[0].Type)
}

func TestLoadFGASchemaError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	_, err := mgmt.FGA().LoadSchema(context.Background())
	require.Error(t, err)
}

func TestDryRunFGASchemaSuccess(t *testing.T) {
	response := &descope.FGASchemaDryRunResponse{
		DeletesPreview: &descope.FGASchemaDryDeletes{
			HasDeletes: true,
			Relations:  []string{"group#member"},
			Types:      []string{"group"},
		},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.NotNil(t, req["dsl"])
		require.Equal(t, "some schema", req["dsl"])
	}, response))
	dryRunResponse, err := mgmt.FGA().DryRunSchema(context.Background(), &descope.FGASchema{Schema: "some schema"})
	require.NoError(t, err)
	require.NotNil(t, dryRunResponse)
	require.NotNil(t, dryRunResponse.DeletesPreview)
	require.True(t, dryRunResponse.DeletesPreview.HasDeletes)
	require.Equal(t, []string{"group#member"}, dryRunResponse.DeletesPreview.Relations)
	require.Equal(t, []string{"group"}, dryRunResponse.DeletesPreview.Types)
}

func TestDryRunFGASchemaMissingSchema(t *testing.T) {
	mgmt := newTestMgmt(nil, nil)
	_, err := mgmt.FGA().DryRunSchema(context.Background(), nil)
	require.Error(t, err)
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("schema").Message)
}

func TestDryRunFGASchemaError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	_, err := mgmt.FGA().DryRunSchema(context.Background(), &descope.FGASchema{Schema: "some schema"})
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

func TestCheckFGARelationsEvaluatedConditions(t *testing.T) {
	response := map[string]any{
		"schemaVersion": "v-abc",
		"tuples": []*descope.FGACheck{
			{
				Allowed:  true,
				Relation: &descope.FGARelation{Resource: "doc1", ResourceType: "doc", Relation: "viewer", Target: "u1", TargetType: "user"},
				Info:     &descope.FGACheckInfo{Conditional: true, TrueConditions: []int32{1}, FalseConditions: []int32{2}},
			},
		}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(nil, response))
	checks, err := mgmt.FGA().Check(context.Background(), []*descope.FGARelation{
		{Resource: "doc1", ResourceType: "doc", Relation: "viewer", Target: "u1", TargetType: "user"},
	})
	require.NoError(t, err)
	require.Len(t, checks, 1)
	require.True(t, checks[0].Info.Conditional)
	require.Equal(t, []int32{1}, checks[0].Info.TrueConditions)
	require.Equal(t, []int32{2}, checks[0].Info.FalseConditions)
	// the response-level schema version is surfaced on each check's info
	require.Equal(t, "v-abc", checks[0].Info.SchemaVersion)
}

func TestCheckFGARelationsMissingTuples(t *testing.T) {
	mgmt := newTestMgmt(nil, nil)
	_, err := mgmt.FGA().Check(context.Background(), nil)
	require.Error(t, err)
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("relations").Message)
}

func TestCheckFGAWithContextPassthrough(t *testing.T) {
	response := map[string]any{
		"tuples": []*descope.FGACheck{
			{
				Allowed:  true,
				Relation: &descope.FGARelation{Resource: "g1", ResourceType: "group", Relation: "member", Target: "u1", TargetType: "user"},
				Info:     &descope.FGACheckInfo{Direct: true},
			},
		}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.NotNil(t, req["tuples"])
		ctx, ok := req["context"].(map[string]any)
		require.True(t, ok)
		require.Equal(t, "1.2.3.4", ctx["ip"])
		require.Equal(t, "admin", ctx["role"])
	}, response))
	checks, err := mgmt.FGA().CheckWithContext(context.Background(),
		[]*descope.FGARelation{{Resource: "g1", ResourceType: "group", Relation: "member", Target: "u1", TargetType: "user"}},
		map[string]any{"ip": "1.2.3.4", "role": "admin"},
	)
	require.NoError(t, err)
	require.Len(t, checks, 1)
	require.True(t, checks[0].Allowed)
	require.True(t, checks[0].Info.Direct)
}

func TestCheckFGAIncludeEvaluatedConditions(t *testing.T) {
	response := map[string]any{
		"tuples": []*descope.FGACheck{
			{Allowed: true, Relation: &descope.FGARelation{Resource: "doc1", ResourceType: "doc", Relation: "viewer", Target: "u1", TargetType: "user"}, Info: &descope.FGACheckInfo{Conditional: true}},
		}}
	rel := []*descope.FGARelation{{Resource: "doc1", ResourceType: "doc", Relation: "viewer", Target: "u1", TargetType: "user"}}

	t.Run("enabled - flag sent", func(t *testing.T) {
		mgmt := newTestMgmtConf(&ManagementParams{FGAIncludeEvaluatedConditions: true}, nil, helpers.DoOkWithBody(func(r *http.Request) {
			req := map[string]any{}
			require.NoError(t, helpers.ReadBody(r, &req))
			require.Equal(t, true, req["includeEvaluatedConditions"])
		}, response))
		_, err := mgmt.FGA().Check(context.Background(), rel)
		require.NoError(t, err)
	})

	t.Run("default off - flag omitted", func(t *testing.T) {
		mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
			req := map[string]any{}
			require.NoError(t, helpers.ReadBody(r, &req))
			_, present := req["includeEvaluatedConditions"]
			require.False(t, present, "flag must be omitted unless opted in")
		}, response))
		_, err := mgmt.FGA().Check(context.Background(), rel)
		require.NoError(t, err)
	})
}

func TestCheckFGAWithContextNil(t *testing.T) {
	response := map[string]any{
		"tuples": []*descope.FGACheck{
			{
				Allowed:  true,
				Relation: &descope.FGARelation{Resource: "g1", ResourceType: "group", Relation: "member", Target: "u1", TargetType: "user"},
			},
		}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.NotNil(t, req["tuples"])
		_, hasContext := req["context"]
		require.False(t, hasContext)
	}, response))
	checks, err := mgmt.FGA().CheckWithContext(context.Background(),
		[]*descope.FGARelation{{Resource: "g1", ResourceType: "group", Relation: "member", Target: "u1", TargetType: "user"}},
		nil,
	)
	require.NoError(t, err)
	require.Len(t, checks, 1)
}

func TestCheckFGAWithContextEmpty(t *testing.T) {
	response := map[string]any{
		"tuples": []*descope.FGACheck{
			{
				Allowed:  true,
				Relation: &descope.FGARelation{Resource: "g1", ResourceType: "group", Relation: "member", Target: "u1", TargetType: "user"},
			},
		}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		_, hasContext := req["context"]
		require.False(t, hasContext)
	}, response))
	checks, err := mgmt.FGA().CheckWithContext(context.Background(),
		[]*descope.FGARelation{{Resource: "g1", ResourceType: "group", Relation: "member", Target: "u1", TargetType: "user"}},
		map[string]any{},
	)
	require.NoError(t, err)
	require.Len(t, checks, 1)
}

func TestCheckFGAWithContextMissingTuples(t *testing.T) {
	mgmt := newTestMgmt(nil, nil)
	_, err := mgmt.FGA().CheckWithContext(context.Background(), nil, map[string]any{"k": "v"})
	require.Error(t, err)
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("relations").Message)
}

func TestCheckFGAConditionalResult(t *testing.T) {
	response := map[string]any{
		"tuples": []*descope.FGACheck{
			{
				Allowed:  true,
				Relation: &descope.FGARelation{Resource: "g1", ResourceType: "group", Relation: "member", Target: "u1", TargetType: "user"},
				Info:     &descope.FGACheckInfo{Conditional: true, MissingContext: []string{"user.dept"}},
			},
		}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(nil, response))
	checks, err := mgmt.FGA().CheckWithContext(context.Background(),
		[]*descope.FGARelation{{Resource: "g1", ResourceType: "group", Relation: "member", Target: "u1", TargetType: "user"}},
		map[string]any{"ip": "1.2.3.4"},
	)
	require.NoError(t, err)
	require.Len(t, checks, 1)
	require.True(t, checks[0].Allowed)
	require.True(t, checks[0].Info.Conditional)
	require.Equal(t, []string{"user.dept"}, checks[0].Info.MissingContext)
}

func TestCheckFGAConditionalErr(t *testing.T) {
	response := map[string]any{
		"tuples": []*descope.FGACheck{
			{
				Allowed:  false,
				Relation: &descope.FGARelation{Resource: "g1", ResourceType: "group", Relation: "member", Target: "u1", TargetType: "user"},
				Info:     &descope.FGACheckInfo{ConditionalErr: "no such attribute"},
			},
		}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(nil, response))
	checks, err := mgmt.FGA().CheckWithContext(context.Background(),
		[]*descope.FGARelation{{Resource: "g1", ResourceType: "group", Relation: "member", Target: "u1", TargetType: "user"}},
		nil,
	)
	require.NoError(t, err)
	require.Len(t, checks, 1)
	require.False(t, checks[0].Allowed)
	require.Equal(t, "no such attribute", checks[0].Info.ConditionalErr)
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
		require.EqualValues(t, []any{"id1", "id2"}, query["queries"])
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
		require.EqualValues(t, []any{"id"}, query["queries"])
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

func TestLoadResourcesDetailsMissingResourceIdentifiers(t *testing.T) {
	mgmt := newTestMgmt(nil, nil)
	_, err := mgmt.FGA().LoadResourcesDetails(context.Background(), nil)
	require.Error(t, err)
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("resourceIdentifiers").Message)
}

func TestLoadResourcesDetailsSuccess(t *testing.T) {
	response := resourcesDetailsResponse{
		ResourcesDetails: []*descope.ResourceDetails{
			{ResourceID: "r1", ResourceType: "type1", DisplayName: "Name1"},
			{ResourceID: "r2", ResourceType: "type2", DisplayName: "Name2"},
		},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Len(t, req["resourceIdentifiers"].([]any), 2)
		first := req["resourceIdentifiers"].([]any)[0].(map[string]any)
		require.Equal(t, "r1", first["resourceId"])
		require.Equal(t, "type1", first["resourceType"])
	}, response))
	ids := []*descope.ResourceIdentifier{
		{ResourceID: "r1", ResourceType: "type1"},
		{ResourceID: "r2", ResourceType: "type2"},
	}
	details, err := mgmt.FGA().LoadResourcesDetails(context.Background(), ids)
	require.NoError(t, err)
	require.Len(t, details, 2)
	require.Equal(t, "r1", details[0].ResourceID)
	require.Equal(t, "Name1", details[0].DisplayName)
	require.Equal(t, "type1", details[0].ResourceType)
	require.Equal(t, "r2", details[1].ResourceID)
	require.Equal(t, "Name2", details[1].DisplayName)
	require.Equal(t, "type2", details[1].ResourceType)
}

func TestLoadResourcesDetailsError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	_, err := mgmt.FGA().LoadResourcesDetails(context.Background(), []*descope.ResourceIdentifier{
		{ResourceID: "r1", ResourceType: "type1"},
	})
	require.Error(t, err)
}

func TestSaveResourcesDetailsMissingResourcesDetails(t *testing.T) {
	mgmt := newTestMgmt(nil, nil)
	err := mgmt.FGA().SaveResourcesDetails(context.Background(), nil)
	require.Error(t, err)
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("resourcesDetails").Message)
}

func TestSaveResourcesDetailsSuccess(t *testing.T) {
	details := []*descope.ResourceDetails{
		{ResourceID: "r1", ResourceType: "type1", DisplayName: "Name1"},
	}
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		arr := req["resourcesDetails"].([]any)
		m := arr[0].(map[string]any)
		require.Equal(t, "r1", m["resourceId"])
		require.Equal(t, "type1", m["resourceType"])
		require.Equal(t, "Name1", m["displayName"])
	}))
	err := mgmt.FGA().SaveResourcesDetails(context.Background(), details)
	require.NoError(t, err)
}

func TestSaveResourcesDetailsError(t *testing.T) {
	details := []*descope.ResourceDetails{
		{ResourceID: "r1", ResourceType: "type1", DisplayName: "Name1"},
	}
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	err := mgmt.FGA().SaveResourcesDetails(context.Background(), details)
	require.Error(t, err)
}
