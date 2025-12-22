package mgmt

import (
	"context"
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/tests/helpers"
	"github.com/stretchr/testify/require"
)

func TestDescoperCreate_Success(t *testing.T) {
	response := map[string]any{
		"descopers": []map[string]any{
			{
				"id": "U2111111111111111111111111",
				"attributes": map[string]any{
					"displayName": "Test User 2",
					"email":       "user2@example.com",
					"phone":       "+123456",
				},
				"rbac": map[string]any{
					"isCompanyAdmin": false,
					"tags":           []any{},
					"projects": []map[string]any{
						{
							"projectIds": []string{"P2111111111111111111111111"},
							"role":       "admin",
						},
					},
				},
				"status": "invited",
			},
		},
		"total": 1,
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		descopers := req["descopers"].([]any)
		require.Len(t, descopers, 1)
		d := descopers[0].(map[string]any)
		require.Equal(t, "user1@example.com", d["loginId"])
		attrs := d["attributes"].(map[string]any)
		require.Equal(t, "Test User 2", attrs["displayName"])
		require.Equal(t, "+123456", attrs["phone"])
		require.Equal(t, "user2@example.com", attrs["email"])
	}, response))

	descopers, total, err := mgmt.Descoper().Create(context.Background(), []*descope.DescoperCreate{
		{
			LoginID: "user1@example.com",
			Attributes: &descope.DescoperAttributes{
				DisplayName: "Test User 2",
				Phone:       "+123456",
				Email:       "user2@example.com",
			},
			ReBac: &descope.DescoperRBAC{
				Projects: []*descope.DescoperProjectRole{
					{
						ProjectIDs: []string{"P2111111111111111111111111"},
						Role:       descope.DescoperRoleAdmin,
					},
				},
			},
		},
	})
	require.NoError(t, err)
	require.Len(t, descopers, 1)
	require.Equal(t, 1, total)
	require.Equal(t, "U2111111111111111111111111", descopers[0].ID)
	require.Equal(t, "Test User 2", descopers[0].Attributes.DisplayName)
	require.Equal(t, "user2@example.com", descopers[0].Attributes.Email)
	require.Equal(t, "+123456", descopers[0].Attributes.Phone)
	require.Equal(t, "invited", descopers[0].Status)
	require.NotNil(t, descopers[0].ReBac)
	require.False(t, descopers[0].ReBac.IsCompanyAdmin)
	require.Len(t, descopers[0].ReBac.Projects, 1)
	require.Equal(t, descope.DescoperRoleAdmin, descopers[0].ReBac.Projects[0].Role)
}

func TestDescoperGet_Success(t *testing.T) {
	response := map[string]any{
		"descoper": map[string]any{
			"id": "U2222222222222222222222222",
			"attributes": map[string]any{
				"displayName": "Test User 2",
				"email":       "user2@example.com",
				"phone":       "+123456",
			},
			"rbac": map[string]any{
				"isCompanyAdmin": false,
				"tags":           []any{},
				"projects": []map[string]any{
					{
						"projectIds": []string{"P2111111111111111111111111"},
						"role":       "admin",
					},
				},
			},
			"status": "invited",
		},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		params := helpers.ReadParams(r)
		require.Equal(t, "U2222222222222222222222222", params["id"])
	}, response))

	res, err := mgmt.Descoper().Get(context.Background(), "U2222222222222222222222222")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "U2222222222222222222222222", res.ID)
	require.Equal(t, "Test User 2", res.Attributes.DisplayName)
	require.Equal(t, "user2@example.com", res.Attributes.Email)
	require.Equal(t, "+123456", res.Attributes.Phone)
	require.Equal(t, "invited", res.Status)
	require.NotNil(t, res.ReBac)
	require.False(t, res.ReBac.IsCompanyAdmin)
	require.Len(t, res.ReBac.Projects, 1)
	require.Equal(t, descope.DescoperRoleAdmin, res.ReBac.Projects[0].Role)
}

func TestDescoperUpdate_Success(t *testing.T) {
	response := map[string]any{
		"descoper": map[string]any{
			"id": "U2333333333333333333333333",
			"attributes": map[string]any{
				"displayName": "Updated User",
				"email":       "user4@example.com",
				"phone":       "+1234358730",
			},
			"rbac": map[string]any{
				"isCompanyAdmin": true,
				"tags":           []any{},
				"projects":       []any{},
			},
			"status": "invited",
		},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "U2333333333333333333333333", req["id"])
		rbac := req["rbac"].(map[string]any)
		require.True(t, rbac["isCompanyAdmin"].(bool))
	}, response))

	res, err := mgmt.Descoper().Update(context.Background(), "U2333333333333333333333333", nil, &descope.DescoperRBAC{
		IsCompanyAdmin: true,
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "U2333333333333333333333333", res.ID)
	require.Equal(t, "Updated User", res.Attributes.DisplayName)
	require.Equal(t, "user4@example.com", res.Attributes.Email)
	require.True(t, res.ReBac.IsCompanyAdmin)
	require.Equal(t, "invited", res.Status)
}

func TestDescoperDelete_Success(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		params := helpers.ReadParams(r)
		require.Equal(t, "U2111111111111111111111111", params["id"])
	}, map[string]any{}))

	err := mgmt.Descoper().Delete(context.Background(), "U2111111111111111111111111")
	require.NoError(t, err)
}

func TestDescoperList_Success(t *testing.T) {
	response := map[string]any{
		"descopers": []map[string]any{
			{
				"id": "U2444444444444444444444444",
				"attributes": map[string]any{
					"displayName": "Admin User",
					"email":       "admin@example.com",
					"phone":       "",
				},
				"rbac": map[string]any{
					"isCompanyAdmin": true,
					"tags":           []any{},
					"projects":       []any{},
				},
				"status": "enabled",
			},
			{
				"id": "U2555555555555555555555555",
				"attributes": map[string]any{
					"displayName": "Another User",
					"email":       "user3@example.com",
					"phone":       "+123456",
				},
				"rbac": map[string]any{
					"isCompanyAdmin": false,
					"tags":           []any{},
					"projects":       []any{},
				},
				"status": "invited",
			},
			{
				"id": "U2666666666666666666666666",
				"attributes": map[string]any{
					"displayName": "Test User 1",
					"email":       "user2@example.com",
					"phone":       "+123456",
				},
				"rbac": map[string]any{
					"isCompanyAdmin": false,
					"tags":           []any{},
					"projects": []map[string]any{
						{
							"projectIds": []string{"P2222222222222222222222222"},
							"role":       "admin",
						},
					},
				},
				"status": "invited",
			},
		},
		"total": 3,
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
	}, response))

	res, total, err := mgmt.Descoper().List(context.Background(), nil)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Len(t, res, 3)
	require.Equal(t, 3, total)

	// First descoper - company admin
	require.Equal(t, "U2444444444444444444444444", res[0].ID)
	require.Equal(t, "Admin User", res[0].Attributes.DisplayName)
	require.Equal(t, "admin@example.com", res[0].Attributes.Email)
	require.True(t, res[0].ReBac.IsCompanyAdmin)
	require.Equal(t, "enabled", res[0].Status)

	// Second descoper
	require.Equal(t, "U2555555555555555555555555", res[1].ID)
	require.Equal(t, "Another User", res[1].Attributes.DisplayName)
	require.False(t, res[1].ReBac.IsCompanyAdmin)
	require.Equal(t, "invited", res[1].Status)

	// Third descoper - with project role
	require.Equal(t, "U2666666666666666666666666", res[2].ID)
	require.Equal(t, "Test User 1", res[2].Attributes.DisplayName)
	require.Len(t, res[2].ReBac.Projects, 1)
	require.Equal(t, descope.DescoperRoleAdmin, res[2].ReBac.Projects[0].Role)
}
