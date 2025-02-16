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
