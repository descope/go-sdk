package mgmt

import (
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope/tests/helpers"
	"github.com/stretchr/testify/require"
)

func TestUserCreateSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"email": "a@b.c",
		}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, "foo@bar.com", req["email"])
		roleNames := req["roleNames"].([]any)
		require.Len(t, roleNames, 1)
		require.Equal(t, "foo", roleNames[0])
	}, response))
	res, err := mgmt.User().Create("abc", "foo@bar.com", "", "", []string{"foo"}, nil)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "a@b.c", res.Email)
}

func TestUserCreateError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, err := mgmt.User().Create("", "foo@bar.com", "", "", nil, nil)
	require.Error(t, err)
}

func TestUserUpdateSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"email": "a@b.c",
		}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, "foo@bar.com", req["email"])
		userTenants := req["userTenants"].([]any)
		require.Len(t, userTenants, 2)
		for i := range userTenants {
			tenant := userTenants[i].(map[string]any)
			roleNames := tenant["roleNames"].([]any)
			require.Len(t, roleNames, 1)
			if i == 0 {
				require.Equal(t, "x", tenant["tenantId"])
				require.Equal(t, "foo", roleNames[0])
			} else {
				require.Equal(t, "y", tenant["tenantId"])
				require.Equal(t, "bar", roleNames[0])
			}
		}
	}, response))
	res, err := mgmt.User().Update("abc", "foo@bar.com", "", "", nil, []*AssociatedTenant{{TenantID: "x", Roles: []string{"foo"}}, {TenantID: "y", Roles: []string{"bar"}}})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "a@b.c", res.Email)
}

func TestUserUpdateError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	_, err := mgmt.User().Update("", "foo@bar.com", "", "", nil, nil)
	require.Error(t, err)
}

func TestUserDeleteSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
	}))
	err := mgmt.User().Delete("abc")
	require.NoError(t, err)
}

func TestUserDeleteError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.User().Delete("")
	require.Error(t, err)
}

func TestUserLoadSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"email": "a@b.c",
		}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		params := helpers.ReadParams(r)
		require.Equal(t, "abc", params["loginId"])
	}, response))
	res, err := mgmt.User().Load("abc")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "a@b.c", res.Email)
}

func TestUserLoadBadInput(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.User().Load("")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserLoadError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.User().Load("abc")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserLoadByUserIDSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"email": "a@b.c",
		}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		params := helpers.ReadParams(r)
		require.Equal(t, "abc", params["userId"])
	}, response))
	res, err := mgmt.User().LoadByUserID("abc")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "a@b.c", res.Email)
}

func TestUserLoadByUserIDBadInput(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.User().LoadByUserID("")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserLoadByUserIDError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.User().LoadByUserID("abc")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestSearchAllUsersSuccess(t *testing.T) {
	response := map[string]any{
		"users": []map[string]any{{
			"email": "a@b.c",
		}},
	}
	tenantIDs := []string{"t1"}
	roleNames := []string{"role1"}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.EqualValues(t, tenantIDs[0], req["tenantIds"].([]any)[0])
		require.EqualValues(t, roleNames[0], req["roleNames"].([]any)[0])
		require.EqualValues(t, 100, req["limit"])
	}, response))
	res, err := mgmt.User().SearchAll(tenantIDs, roleNames, 100)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Len(t, res, 1)
	require.Equal(t, "a@b.c", res[0].Email)
}

func TestSearchAllUsersError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.User().SearchAll(nil, nil, 100)
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserActivateSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"status": "enabled",
		}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, "enabled", req["status"])
	}, response))
	res, err := mgmt.User().Activate("abc")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "enabled", res.Status)
}

func TestUserActivateBadInput(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.User().Activate("")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserActivateError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.User().Activate("abc")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserDeactivateSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"status": "disabled",
		}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, "disabled", req["status"])
	}, response))
	res, err := mgmt.User().Deactivate("abc")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "disabled", res.Status)
}

func TestUserDeactivateBadInput(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.User().Deactivate("")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserDeactivateError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.User().Deactivate("abc")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserUpdateEmailSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"email":         "a@b.c",
			"verifiedEmail": true,
		}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, "a@b.c", req["email"])
		require.Equal(t, true, req["verified"])
	}, response))
	res, err := mgmt.User().UpdateEmail("abc", "a@b.c", true)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "a@b.c", res.Email)
	require.Equal(t, true, res.VerifiedEmail)
}

func TestUserUpdateEmailBadInput(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.User().UpdateEmail("", "a@b.c", true)
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserUpdateEmailError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.User().UpdateEmail("abc", "a@b.c", true)
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserUpdatePhoneSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"phone":         "+18005551234",
			"verifiedPhone": false,
		}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, "+18005551234", req["phone"])
		require.Equal(t, false, req["verified"])
	}, response))
	res, err := mgmt.User().UpdatePhone("abc", "+18005551234", false)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "+18005551234", res.Phone)
	require.Equal(t, false, res.VerifiedPhone)
}

func TestUserUpdatePhoneBadInput(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.User().UpdatePhone("", "+18005551234", true)
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserUpdatePhoneError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.User().UpdatePhone("abc", "+18005551234", true)
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserUpdateNameSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"name": "foo",
		}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, "foo", req["displayName"])
	}, response))
	res, err := mgmt.User().UpdateDisplayName("abc", "foo")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "foo", res.Name)
}

func TestUserUpdateNameBadInput(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.User().UpdateDisplayName("", "foo")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserUpdateNameError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.User().UpdateDisplayName("abc", "foo")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserAddRoleSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"roleNames": []string{"foo"},
		}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, []any{"foo"}, req["roleNames"])
	}, response))
	res, err := mgmt.User().AddRoles("abc", []string{"foo"})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, []string{"foo"}, res.RoleNames)
}

func TestUserAddRoleBadInput(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.User().AddRoles("", []string{"foo"})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserAddRoleError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.User().AddRoles("abc", []string{"foo"})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserRemoveRoleSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"roleNames": []string{"qux", "zut"},
		}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, []any{"foo", "bar"}, req["roleNames"])
	}, response))
	res, err := mgmt.User().RemoveRoles("abc", []string{"foo", "bar"})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, []string{"qux", "zut"}, res.RoleNames)
}

func TestUserRemoveRoleBadInput(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.User().RemoveRoles("", []string{"foo", "bar"})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserRemoveRoleError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.User().RemoveRoles("abc", []string{"foo", "bar"})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserAddTenantSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"userTenants": []map[string]any{
				{"tenantId": "123"},
				{"tenantId": "456"},
			},
		}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, "456", req["tenantId"])
	}, response))
	res, err := mgmt.User().AddTenant("abc", "456")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Len(t, res.UserTenants, 2)
	require.Equal(t, "123", res.UserTenants[0].TenantID)
	require.Equal(t, "456", res.UserTenants[1].TenantID)
}

func TestUserAddTenantBadInput(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.User().AddTenant("", "123")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserAddTenantError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.User().AddTenant("abc", "123")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserRemoveTenantSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"userTenants": []map[string]any{
				{"tenantId": "123"},
			},
		}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, "456", req["tenantId"])
	}, response))
	res, err := mgmt.User().RemoveTenant("abc", "456")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Len(t, res.UserTenants, 1)
	require.Equal(t, "123", res.UserTenants[0].TenantID)
}

func TestUserRemoveTenantBadInput(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.User().RemoveTenant("", "123")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserRemoveTenantError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.User().RemoveTenant("abc", "123")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserAddTenantRoleSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"userTenants": []map[string]any{
				{
					"tenantId":  "123",
					"roleNames": []string{"foo"},
				},
			},
		}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, "123", req["tenantId"])
		require.Equal(t, []any{"foo"}, req["roleNames"])
	}, response))
	res, err := mgmt.User().AddTenantRoles("abc", "123", []string{"foo"})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Len(t, res.UserTenants, 1)
	require.Equal(t, "123", res.UserTenants[0].TenantID)
	require.Equal(t, []string{"foo"}, res.UserTenants[0].RoleNames)
}

func TestUserAddTenantRoleBadInput(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.User().AddTenantRoles("", "123", []string{"foo"})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserAddTenantRoleError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.User().AddTenantRoles("abc", "123", []string{"foo"})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserRemoveTenantRoleSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"userTenants": []map[string]any{
				{
					"tenantId":  "123",
					"roleNames": []string{"qux", "zut"},
				},
			},
		}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, "123", req["tenantId"])
		require.Equal(t, []any{"foo", "bar"}, req["roleNames"])
	}, response))
	res, err := mgmt.User().RemoveTenantRoles("abc", "123", []string{"foo", "bar"})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Len(t, res.UserTenants, 1)
	require.Equal(t, "123", res.UserTenants[0].TenantID)
	require.Equal(t, []string{"qux", "zut"}, res.UserTenants[0].RoleNames)
}

func TestUserRemoveTenantRoleBadInput(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.User().RemoveTenantRoles("", "123", []string{"foo", "bar"})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserRemoveTenantRoleError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.User().RemoveTenantRoles("abc", "123", []string{"foo", "bar"})
	require.Error(t, err)
	require.Nil(t, res)
}
