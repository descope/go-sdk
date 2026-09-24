package mgmt

import (
	"context"
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/tests/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var familyResponse = map[string]any{
	"family": map[string]any{
		"id":               "fam1",
		"name":             "Demo Family",
		"customAttributes": map[string]any{"plan": "free"},
		"disabled":         true,
		"photo":            "https://example.com/photo.png",
		"createdTime":      1700000000,
	},
}

func assertFamilyResponse(t *testing.T, family *descope.Family) {
	require.NotNil(t, family)
	assert.Equal(t, "fam1", family.ID)
	assert.Equal(t, "Demo Family", family.Name)
	assert.EqualValues(t, map[string]any{"plan": "free"}, family.CustomAttributes)
	assert.True(t, family.Disabled)
	assert.Equal(t, "https://example.com/photo.png", family.Photo)
	assert.EqualValues(t, 1700000000, family.CreatedTime)
}

func TestFamilyCreateSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, "/v1/mgmt/family/create", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "Demo Family", req["name"])
		assert.EqualValues(t, map[string]any{"plan": "free"}, req["customAttributes"])
		assert.Equal(t, "https://example.com/photo.png", req["photo"])
		assert.Equal(t, true, req["disabled"])
		assert.NotContains(t, req, "familyId")
	}, familyResponse))
	res, err := mgmt.Family().Create(context.Background(), &descope.FamilyRequest{
		Name:             "Demo Family",
		CustomAttributes: map[string]any{"plan": "free"},
		Photo:            "https://example.com/photo.png",
		Disabled:         true,
	})
	require.NoError(t, err)
	assertFamilyResponse(t, res)
}

func TestFamilyCreateMinimalSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "Demo Family", req["name"])
		assert.Equal(t, false, req["disabled"])
		assert.NotContains(t, req, "customAttributes")
		assert.NotContains(t, req, "photo")
		assert.NotContains(t, req, "familyId")
	}, familyResponse))
	res, err := mgmt.Family().Create(context.Background(), &descope.FamilyRequest{Name: "Demo Family"})
	require.NoError(t, err)
	assertFamilyResponse(t, res)
}

func TestFamilyCreateError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.Family().Create(context.Background(), nil)
	require.Error(t, err)
	require.Nil(t, res)
	res, err = mgmt.Family().Create(context.Background(), &descope.FamilyRequest{})
	require.Error(t, err)
	require.Nil(t, res)

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err = mgmt.Family().Create(context.Background(), &descope.FamilyRequest{Name: "Demo Family"})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestFamilyCreateWithIDSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, "/v1/mgmt/family/create", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "fam1", req["familyId"])
		assert.Equal(t, "Demo Family", req["name"])
	}, familyResponse))
	res, err := mgmt.Family().CreateWithID(context.Background(), "fam1", &descope.FamilyRequest{Name: "Demo Family"})
	require.NoError(t, err)
	assertFamilyResponse(t, res)
}

func TestFamilyCreateWithIDError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.Family().CreateWithID(context.Background(), "", &descope.FamilyRequest{Name: "Demo Family"})
	require.Error(t, err)
	require.Nil(t, res)
	res, err = mgmt.Family().CreateWithID(context.Background(), "fam1", &descope.FamilyRequest{})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestFamilyUpdateSuccess(t *testing.T) {
	name := "Demo Family (renamed)"
	photo := ""
	disabled := false
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, "/v1/mgmt/family/update", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "fam1", req["id"])
		assert.Equal(t, name, req["name"])
		assert.EqualValues(t, map[string]any{"plan": "premium"}, req["customAttributes"])
		assert.Contains(t, req, "photo")
		assert.Equal(t, "", req["photo"])
		assert.Contains(t, req, "disabled")
		assert.Equal(t, false, req["disabled"])
	}, familyResponse))
	res, err := mgmt.Family().Update(context.Background(), "fam1", &descope.UpdateFamilyRequest{
		Name:             &name,
		CustomAttributes: map[string]any{"plan": "premium"},
		Photo:            &photo,
		Disabled:         &disabled,
	})
	require.NoError(t, err)
	assertFamilyResponse(t, res)
}

func TestFamilyUpdateOmitsUnsetFields(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{"id": "fam1"}, req)
	}, familyResponse))
	res, err := mgmt.Family().Update(context.Background(), "fam1", nil)
	require.NoError(t, err)
	assertFamilyResponse(t, res)
}

func TestFamilyUpdateError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.Family().Update(context.Background(), "", &descope.UpdateFamilyRequest{})
	require.Error(t, err)
	require.Nil(t, res)

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err = mgmt.Family().Update(context.Background(), "fam1", &descope.UpdateFamilyRequest{})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestFamilyDeleteSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, "/v1/mgmt/family/delete", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{"id": "fam1"}, req)
	}))
	err := mgmt.Family().Delete(context.Background(), "fam1")
	require.NoError(t, err)
}

func TestFamilyDeleteError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.Family().Delete(context.Background(), "")
	require.Error(t, err)
}

func TestFamilySearchAllSuccess(t *testing.T) {
	response := map[string]any{"families": []map[string]any{
		{"id": "fam1", "name": "Demo Family"},
		{"id": "fam2", "name": "Other Demo Family"},
	}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, "/v1/mgmt/family/search", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, []any{"fam1", "fam2"}, req["familyIds"])
		assert.EqualValues(t, []any{"Demo Family"}, req["familyNames"])
		assert.Equal(t, "demo", req["freeText"])
		assert.EqualValues(t, map[string]any{"plan": "free"}, req["customAttributes"])
		assert.EqualValues(t, 1, req["page"])
		assert.EqualValues(t, 20, req["size"])
	}, response))
	res, err := mgmt.Family().SearchAll(context.Background(), &descope.FamilySearchOptions{
		IDs:              []string{"fam1", "fam2"},
		Names:            []string{"Demo Family"},
		Text:             "demo",
		CustomAttributes: map[string]any{"plan": "free"},
		Page:             1,
		Size:             20,
	})
	require.NoError(t, err)
	require.Len(t, res, 2)
	assert.Equal(t, "fam1", res[0].ID)
	assert.Equal(t, "Other Demo Family", res[1].Name)
}

func TestFamilySearchAllNoOptionsSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, "/v1/mgmt/family/search", r.URL.Path)
	}, map[string]any{"families": []map[string]any{{"id": "fam1"}}}))
	res, err := mgmt.Family().SearchAll(context.Background(), nil)
	require.NoError(t, err)
	require.Len(t, res, 1)
}

func TestFamilySearchAllError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.Family().SearchAll(context.Background(), &descope.FamilySearchOptions{Page: -1})
	require.Error(t, err)
	require.Nil(t, res)
	res, err = mgmt.Family().SearchAll(context.Background(), &descope.FamilySearchOptions{Size: -1})
	require.Error(t, err)
	require.Nil(t, res)

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err = mgmt.Family().SearchAll(context.Background(), nil)
	require.Error(t, err)
	require.Nil(t, res)
}

func TestFamilyCreateDependentSuccess(t *testing.T) {
	response := map[string]any{"user": map[string]any{
		"userId":    "U1",
		"loginIds":  []string{"demo-kid"},
		"name":      "Demo Kid",
		"dependent": true,
		"userFamilies": []map[string]any{{
			"familyId":               "fam1",
			"roleNames":              []string{"Family Member"},
			"permissions":            []string{"perm1"},
			"familyScopedAttributes": map[string]any{"nickname": "Kiddo"},
		}},
	}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, "/v1/mgmt/family/dependent/create", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "fam1", req["familyId"])
		assert.Equal(t, "demo-kid", req["loginId"])
		assert.Equal(t, "Demo Kid", req["name"])
		assert.Equal(t, "guardian@example.com", req["email"])
		assert.Equal(t, "+12025550123", req["phone"])
		assert.Equal(t, "Demo", req["givenName"])
		assert.Equal(t, "M", req["middleName"])
		assert.Equal(t, "Kid", req["familyName"])
		assert.Equal(t, "https://example.com/kid.png", req["picture"])
		assert.EqualValues(t, map[string]any{"grade": "3"}, req["customAttributes"])
		assert.EqualValues(t, map[string]any{"fam1": map[string]any{"nickname": "Kiddo"}}, req["familyScopedAttributes"])
	}, response))
	res, err := mgmt.Family().CreateDependent(context.Background(), "fam1", &descope.FamilyDependentRequest{
		User: descope.User{
			Name:       "Demo Kid",
			GivenName:  "Demo",
			MiddleName: "M",
			FamilyName: "Kid",
			Email:      "guardian@example.com",
			Phone:      "+12025550123",
		},
		LoginID:                "demo-kid",
		Picture:                "https://example.com/kid.png",
		CustomAttributes:       map[string]any{"grade": "3"},
		FamilyScopedAttributes: map[string]map[string]any{"fam1": {"nickname": "Kiddo"}},
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, "U1", res.UserID)
	assert.True(t, res.Dependent)
	require.Len(t, res.UserFamilies, 1)
	assert.Equal(t, "fam1", res.UserFamilies[0].FamilyID)
	assert.EqualValues(t, []string{"Family Member"}, res.UserFamilies[0].Roles)
	assert.EqualValues(t, []string{"perm1"}, res.UserFamilies[0].Permissions)
	assert.EqualValues(t, map[string]any{"nickname": "Kiddo"}, res.UserFamilies[0].FamilyScopedAttributes)
}

func TestFamilyCreateDependentMinimalSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{"familyId": "fam1"}, req)
	}, map[string]any{"user": map[string]any{"userId": "U1"}}))
	res, err := mgmt.Family().CreateDependent(context.Background(), "fam1", nil)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, "U1", res.UserID)
}

func TestFamilyCreateDependentError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.Family().CreateDependent(context.Background(), "", &descope.FamilyDependentRequest{})
	require.Error(t, err)
	require.Nil(t, res)

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err = mgmt.Family().CreateDependent(context.Background(), "fam1", nil)
	require.Error(t, err)
	require.Nil(t, res)
}

func TestFamilyDeleteDependentSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, "/v1/mgmt/family/dependent/delete", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{"userId": "U1"}, req)
	}))
	err := mgmt.Family().DeleteDependent(context.Background(), "U1")
	require.NoError(t, err)
}

func TestFamilyDeleteDependentError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.Family().DeleteDependent(context.Background(), "")
	require.Error(t, err)
}

func TestFamilyImpersonateDependentSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, "/v1/mgmt/family/impersonate", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "guardian@example.com", req["impersonatorUserIdOrLoginId"])
		assert.Equal(t, "demo-kid", req["dependentLoginId"])
		assert.Equal(t, "fam1", req["selectedFamily"])
	}, map[string]any{"jwt": "impersonated-jwt"}))
	jwt, err := mgmt.Family().ImpersonateDependent(context.Background(), "guardian@example.com", "demo-kid", "fam1")
	require.NoError(t, err)
	assert.Equal(t, "impersonated-jwt", jwt)
}

func TestFamilyImpersonateDependentNoSelectedFamilySuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.NotContains(t, req, "selectedFamily")
	}, map[string]any{"jwt": "impersonated-jwt"}))
	jwt, err := mgmt.Family().ImpersonateDependent(context.Background(), "guardian@example.com", "demo-kid", "")
	require.NoError(t, err)
	assert.Equal(t, "impersonated-jwt", jwt)
}

func TestFamilyImpersonateDependentError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	jwt, err := mgmt.Family().ImpersonateDependent(context.Background(), "", "demo-kid", "")
	require.Error(t, err)
	require.Empty(t, jwt)
	jwt, err = mgmt.Family().ImpersonateDependent(context.Background(), "guardian@example.com", "", "")
	require.Error(t, err)
	require.Empty(t, jwt)

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	jwt, err = mgmt.Family().ImpersonateDependent(context.Background(), "guardian@example.com", "demo-kid", "")
	require.Error(t, err)
	require.Empty(t, jwt)
}

func TestFamilyStopImpersonationSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, "/v1/mgmt/family/impersonate/stop", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "impersonated-jwt", req["jwt"])
		assert.EqualValues(t, map[string]any{"k1": "v1"}, req["customClaims"])
		assert.EqualValues(t, 30, req["refreshDuration"])
	}, map[string]any{"jwt": "own-jwt"}))
	jwt, err := mgmt.Family().StopImpersonation(context.Background(), "impersonated-jwt", map[string]any{"k1": "v1"}, 30)
	require.NoError(t, err)
	assert.Equal(t, "own-jwt", jwt)
}

func TestFamilyStopImpersonationError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	jwt, err := mgmt.Family().StopImpersonation(context.Background(), "", nil, 0)
	require.Error(t, err)
	require.Empty(t, jwt)

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	jwt, err = mgmt.Family().StopImpersonation(context.Background(), "impersonated-jwt", nil, 0)
	require.Error(t, err)
	require.Empty(t, jwt)
}

func TestFamilyGetSettingsSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/v1/mgmt/family/settings", r.URL.Path)
	}, map[string]any{"enabled": true, "maxFamilyMembers": 6, "allowMultipleFamiliesUsers": true}))
	res, err := mgmt.Family().GetSettings(context.Background())
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.True(t, res.Enabled)
	assert.EqualValues(t, 6, res.MaxFamilyMembers)
	assert.True(t, res.AllowMultipleFamiliesUsers)
}

func TestFamilyGetSettingsError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.Family().GetSettings(context.Background())
	require.Error(t, err)
	require.Nil(t, res)
}

func TestFamilyConfigureSettingsSuccess(t *testing.T) {
	enabled := true
	maxMembers := int32(4)
	allowMultiple := false
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/v1/mgmt/family/settings", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{"enabled": true, "maxFamilyMembers": float64(4), "allowMultipleFamiliesUsers": false}, req)
	}, map[string]any{"enabled": true, "maxFamilyMembers": 4}))
	res, err := mgmt.Family().ConfigureSettings(context.Background(), &descope.FamilySettingsRequest{
		Enabled:                    &enabled,
		MaxFamilyMembers:           &maxMembers,
		AllowMultipleFamiliesUsers: &allowMultiple,
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.True(t, res.Enabled)
	assert.EqualValues(t, 4, res.MaxFamilyMembers)
	assert.False(t, res.AllowMultipleFamiliesUsers)
}

func TestFamilyConfigureSettingsPartialSuccess(t *testing.T) {
	enabled := true
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, map[string]any{"enabled": true}, req)
	}, map[string]any{"enabled": true}))
	res, err := mgmt.Family().ConfigureSettings(context.Background(), &descope.FamilySettingsRequest{Enabled: &enabled})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.True(t, res.Enabled)
}

func TestFamilyConfigureSettingsError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.Family().ConfigureSettings(context.Background(), nil)
	require.Error(t, err)
	require.Nil(t, res)

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err = mgmt.Family().ConfigureSettings(context.Background(), &descope.FamilySettingsRequest{})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestFamilyGetCustomAttributesSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/v1/mgmt/family/customattributes", r.URL.Path)
	}, map[string]any{"data": []map[string]any{
		{"name": "plan", "type": 1, "displayName": "Plan"},
	}}))
	res, err := mgmt.Family().GetCustomAttributes(context.Background())
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, "plan", res[0].Name)
	assert.EqualValues(t, 1, res[0].Type)
	assert.Equal(t, "Plan", res[0].DisplayName)
}

func TestFamilyGetCustomAttributesError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.Family().GetCustomAttributes(context.Background())
	require.Error(t, err)
	require.Nil(t, res)
}

func TestFamilyCreateCustomAttributesSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, "/v1/mgmt/family/customattribute/create", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		attrs, ok := req["attributes"].([]any)
		require.True(t, ok)
		require.Len(t, attrs, 1)
		attr := attrs[0].(map[string]any)
		assert.Equal(t, "plan", attr["name"])
		assert.EqualValues(t, 1, attr["type"])
		assert.Equal(t, "Plan", attr["displayName"])
	}, map[string]any{"data": []map[string]any{{"name": "plan"}}}))
	res, err := mgmt.Family().CreateCustomAttributes(context.Background(), []*descope.CustomAttribute{
		{Name: "plan", Type: 1, DisplayName: "Plan"},
	})
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, "plan", res[0].Name)
}

func TestFamilyCreateCustomAttributesError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.Family().CreateCustomAttributes(context.Background(), nil)
	require.Error(t, err)
	require.Nil(t, res)

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err = mgmt.Family().CreateCustomAttributes(context.Background(), []*descope.CustomAttribute{{Name: "plan", Type: 1}})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestFamilyDeleteCustomAttributesSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, "/v1/mgmt/family/customattribute/delete", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, []any{"plan"}, req["names"])
	}, map[string]any{"data": []map[string]any{}}))
	res, err := mgmt.Family().DeleteCustomAttributes(context.Background(), []string{"plan"})
	require.NoError(t, err)
	require.Len(t, res, 0)
}

func TestFamilyDeleteCustomAttributesError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.Family().DeleteCustomAttributes(context.Background(), nil)
	require.Error(t, err)
	require.Nil(t, res)

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err = mgmt.Family().DeleteCustomAttributes(context.Background(), []string{"plan"})
	require.Error(t, err)
	require.Nil(t, res)
}
