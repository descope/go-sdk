package mgmt

import (
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/tests/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserCreateSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"email": "a@b.c",
		}}
	ca := map[string]any{"ak": "av"}
	i := 0
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, "foo@bar.com", req["email"])
		roleNames := req["roleNames"].([]any)
		require.Len(t, roleNames, 1)
		require.Equal(t, "foo", roleNames[0])
		require.Nil(t, req["test"])
		assert.EqualValues(t, ca, req["customAttributes"])

		if i == 2 {
			assert.True(t, true, req["sendSMS"])
			assert.EqualValues(t, false, req["sendMail"])
		} else {
			assert.Nil(t, req["sendSMS"])
			assert.Nil(t, req["sendMail"])
		}
		i++
	}, response))
	user := &descope.UserRequest{}
	user.Email = "foo@bar.com"
	user.Roles = []string{"foo"}
	user.CustomAttributes = ca
	res, err := m.User().Create("abc", user)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "a@b.c", res.Email)

	res, err = m.User().Invite("abc", user, nil)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "a@b.c", res.Email)

	sendSMS := true
	sendMail := false
	res, err = m.User().Invite("abc", user, &descope.InviteOptions{InviteURL: "https://some.domain.com", SendSMS: &sendSMS, SendMail: &sendMail})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "a@b.c", res.Email)
}

func TestUserCreateSuccessWithOptions(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"email": "a@b.c",
		}}
	ca := map[string]any{"ak": "av"}
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, "foo@bar.com", req["email"])
		roleNames := req["roleNames"].([]any)
		require.Len(t, roleNames, 1)
		require.Equal(t, "foo", roleNames[0])
		require.Nil(t, req["test"])
		assert.EqualValues(t, ca, req["customAttributes"])
		assert.EqualValues(t, "https://some.domain.com", req["inviteUrl"])
		assert.Nil(t, req["sendMail"])
		assert.Nil(t, req["sendSMS"])
	}, response))
	user := &descope.UserRequest{}
	user.Email = "foo@bar.com"
	user.Roles = []string{"foo"}
	user.CustomAttributes = ca

	res, err := m.User().Invite("abc", user, &descope.InviteOptions{InviteURL: "https://some.domain.com"})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "a@b.c", res.Email)
}

func TestUserCreateTestUserSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"email": "a@b.c",
		}}
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, "foo@bar.com", req["email"])
		roleNames := req["roleNames"].([]any)
		require.Len(t, roleNames, 1)
		require.Equal(t, "foo", roleNames[0])
		require.EqualValues(t, true, req["test"])
	}, response))
	user := &descope.UserRequest{}
	user.Email = "foo@bar.com"
	user.Roles = []string{"foo"}
	res, err := m.User().CreateTestUser("abc", user)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "a@b.c", res.Email)
}

func TestUserCreateError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	user := &descope.UserRequest{}
	user.Email = "foo@bar.com"
	_, err := m.User().Create("", user)
	require.Error(t, err)
}

func TestUserCreateUpdateOrInviteWithNoUser(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	_, err := m.User().Create("abc", nil)
	require.NoError(t, err)
	_, err = m.User().CreateTestUser("abc", nil)
	require.NoError(t, err)
	_, err = m.User().Invite("abc", nil, nil)
	require.NoError(t, err)
	_, err = m.User().Update("abc", nil)
	require.NoError(t, err)
}

func TestUserUpdateSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"email": "a@b.c",
		}}
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		_, ok := req["verifiedEmail"]
		assert.False(t, ok)
		_, ok = req["verifiedPhone"]
		assert.False(t, ok)
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
	user := &descope.UserRequest{}
	user.Email = "foo@bar.com"
	user.Tenants = []*descope.AssociatedTenant{{TenantID: "x", Roles: []string{"foo"}}, {TenantID: "y", Roles: []string{"bar"}}}
	res, err := m.User().Update("abc", user)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "a@b.c", res.Email)
}

func TestUserUpdateVerifiedAttributes(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"email": "a@b.c",
		}}
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		_, ok := req["verifiedEmail"]
		assert.True(t, ok)
		_, ok = req["verifiedPhone"]
		assert.True(t, ok)
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, "foo@bar.com", req["email"])
	}, response))
	user := &descope.UserRequest{}
	user.Email = "foo@bar.com"
	tr := true
	user.VerifiedEmail = &tr
	user.VerifiedPhone = &tr
	res, err := m.User().Update("abc", user)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "a@b.c", res.Email)
}

func TestUserUpdateError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	user := &descope.UserRequest{}
	user.Email = "foo@bar.com"
	_, err := m.User().Update("", user)
	require.Error(t, err)
}

func TestUserDeleteSuccess(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
	}))
	err := m.User().Delete("abc")
	require.NoError(t, err)
}

func TestDeleteAllTestUsersSuccess(t *testing.T) {
	visited := false
	m := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		visited = true
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
	}))
	err := m.User().DeleteAllTestUsers()
	require.NoError(t, err)
	assert.True(t, visited)
}

func TestUserDeleteError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	err := m.User().Delete("")
	require.Error(t, err)
}

func TestUserLoadSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"email": "a@b.c",
		}}
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		params := helpers.ReadParams(r)
		require.Equal(t, "abc", params["loginId"])
	}, response))
	res, err := m.User().Load("abc")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "a@b.c", res.Email)
}

func TestUserLoadBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().Load("")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserLoadError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().Load("abc")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserLoadByUserIDSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"email": "a@b.c",
		}}
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		params := helpers.ReadParams(r)
		require.Equal(t, "abc", params["userId"])
	}, response))
	res, err := m.User().LoadByUserID("abc")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "a@b.c", res.Email)
}

func TestUserLoadByUserIDBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().LoadByUserID("")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserLoadByUserIDError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().LoadByUserID("abc")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserLogoutUserByUserIDSuccess(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, "abc", req["userId"])
		assert.EqualValues(t, "", req["loginId"])
	}, nil))
	err := m.User().LogoutUserByUserID("abc")
	require.NoError(t, err)
}

func TestUserLogoutUserByLoginIDSuccess(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.EqualValues(t, "", req["userId"])
		assert.EqualValues(t, "abc", req["loginId"])
	}, nil))
	err := m.User().LogoutUser("abc")
	require.NoError(t, err)
}

func TestUserLogoutUserByUserIdErr(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Fail(t, "shouldn't get here")
	}, nil))
	err := m.User().LogoutUserByUserID("")
	require.Error(t, err)
}

func TestUserLogoutUserByLoginIdErr(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Fail(t, "shouldn't get here")
	}, nil))
	err := m.User().LogoutUser("")
	require.Error(t, err)
}

func TestSearchAllUsersSuccess(t *testing.T) {
	response := map[string]any{
		"users": []map[string]any{{
			"email": "a@b.c",
		}},
	}
	tenantIDs := []string{"t1"}
	roleNames := []string{"role1"}
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.EqualValues(t, tenantIDs[0], req["tenantIds"].([]any)[0])
		require.EqualValues(t, roleNames[0], req["roleNames"].([]any)[0])
		require.EqualValues(t, descope.UserStatusDisabled, req["statuses"].([]any)[0])
		require.EqualValues(t, 100, req["limit"])
		require.EqualValues(t, 0, req["page"])
		require.EqualValues(t, map[string]any{"a": "b"}, req["customAttributes"])
		require.EqualValues(t, []any{"a@b.com"}, req["emails"])
		require.EqualValues(t, []any{"+11111111"}, req["phones"])
	}, response))
	res, err := m.User().SearchAll(&descope.UserSearchOptions{
		Statuses:         []descope.UserStatus{descope.UserStatusDisabled},
		TenantIDs:        tenantIDs,
		Roles:            roleNames,
		Limit:            100,
		CustomAttributes: map[string]any{"a": "b"},
		Emails:           []string{"a@b.com"},
		Phones:           []string{"+11111111"},
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Len(t, res, 1)
	require.Equal(t, "a@b.c", res[0].Email)
}

func TestSearchAllUsersError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().SearchAll(nil)
	require.Error(t, err)
	require.Nil(t, res)
}

func TestSearchAllUsersBadRequest(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().SearchAll(&descope.UserSearchOptions{Limit: -1})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	require.Contains(t, err.Error(), "limit")
	require.Nil(t, res)

	res, err = m.User().SearchAll(&descope.UserSearchOptions{Page: -1})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	require.Contains(t, err.Error(), "page")
	require.Nil(t, res)
}

func TestUserActivateSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"status": "enabled",
		}}
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, "enabled", req["status"])
	}, response))
	res, err := m.User().Activate("abc")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "enabled", res.Status)
}

func TestUserActivateBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().Activate("")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserActivateError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().Activate("abc")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserDeactivateSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"status": "disabled",
		}}
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, "disabled", req["status"])
	}, response))
	res, err := m.User().Deactivate("abc")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "disabled", res.Status)
}

func TestUserDeactivateBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().Deactivate("")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserDeactivateError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().Deactivate("abc")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserUpdateLoginIDSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"email":         "a@b.c",
			"verifiedEmail": true,
		}}
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, "a@b.c", req["newLoginId"])
	}, response))
	res, err := m.User().UpdateLoginID("abc", "a@b.c")
	require.NoError(t, err)
	require.NotNil(t, res)
}

func TestUserUpdateLoginIDBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().UpdateLoginID("", "a@b.c")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserUpdateEmailSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"email":         "a@b.c",
			"verifiedEmail": true,
		}}
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, "a@b.c", req["email"])
		require.Equal(t, true, req["verified"])
	}, response))
	res, err := m.User().UpdateEmail("abc", "a@b.c", true)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "a@b.c", res.Email)
	require.Equal(t, true, res.VerifiedEmail)
}

func TestUserUpdateEmailBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().UpdateEmail("", "a@b.c", true)
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserUpdateEmailError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().UpdateEmail("abc", "a@b.c", true)
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserUpdatePhoneSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"phone":         "+18005551234",
			"verifiedPhone": false,
		}}
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, "+18005551234", req["phone"])
		require.Equal(t, false, req["verified"])
	}, response))
	res, err := m.User().UpdatePhone("abc", "+18005551234", false)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "+18005551234", res.Phone)
	require.Equal(t, false, res.VerifiedPhone)
}

func TestUserUpdatePhoneBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().UpdatePhone("", "+18005551234", true)
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserUpdatePhoneError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().UpdatePhone("abc", "+18005551234", true)
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserUpdateNameSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"name": "foo",
		}}
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, "foo", req["displayName"])
	}, response))
	res, err := m.User().UpdateDisplayName("abc", "foo")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "foo", res.Name)
}

func TestUserUpdateNameBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().UpdateDisplayName("", "foo")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserUpdateNameError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().UpdateDisplayName("abc", "foo")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserUpdatePictureSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"name": "foo",
		}}
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, "foo", req["picture"])
	}, response))
	res, err := m.User().UpdatePicture("abc", "foo")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "foo", res.Name)
}

func TestUserUpdatePictureBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().UpdatePicture("", "foo")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserUpdatePictureError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().UpdatePicture("abc", "foo")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserUpdateCustomAttributeSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"name": "foo",
		}}
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, "foo", req["attributeKey"])
		require.Equal(t, "bar", req["attributeValue"])
	}, response))
	res, err := m.User().UpdateCustomAttribute("abc", "foo", "bar")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "foo", res.Name)
}

func TestUserUpdateCustomAttributeBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().UpdateCustomAttribute("", "foo", "bar")
	require.Error(t, err)
	require.Nil(t, res)
	res, err = m.User().UpdateCustomAttribute("id", "", "bar")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserUpdateCustomAttributeError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().UpdateCustomAttribute("abc", "foo", "bar")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserAddRoleSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"roleNames": []string{"foo"},
		}}
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, []any{"foo"}, req["roleNames"])
	}, response))
	res, err := m.User().AddRoles("abc", []string{"foo"})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, []string{"foo"}, res.RoleNames)
}

func TestUserAddRoleBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().AddRoles("", []string{"foo"})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserAddRoleError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().AddRoles("abc", []string{"foo"})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserRemoveRoleSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"roleNames": []string{"qux", "zut"},
		}}
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, []any{"foo", "bar"}, req["roleNames"])
	}, response))
	res, err := m.User().RemoveRoles("abc", []string{"foo", "bar"})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, []string{"qux", "zut"}, res.RoleNames)
}

func TestUserRemoveRoleBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().RemoveRoles("", []string{"foo", "bar"})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserRemoveRoleError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().RemoveRoles("abc", []string{"foo", "bar"})
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
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, "456", req["tenantId"])
	}, response))
	res, err := m.User().AddTenant("abc", "456")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Len(t, res.UserTenants, 2)
	require.Equal(t, "123", res.UserTenants[0].TenantID)
	require.Equal(t, "456", res.UserTenants[1].TenantID)
}

func TestUserAddTenantBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().AddTenant("", "123")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserAddTenantError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().AddTenant("abc", "123")
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
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, "456", req["tenantId"])
	}, response))
	res, err := m.User().RemoveTenant("abc", "456")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Len(t, res.UserTenants, 1)
	require.Equal(t, "123", res.UserTenants[0].TenantID)
}

func TestUserRemoveTenantBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().RemoveTenant("", "123")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserRemoveTenantError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().RemoveTenant("abc", "123")
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
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, "123", req["tenantId"])
		require.Equal(t, []any{"foo"}, req["roleNames"])
	}, response))
	res, err := m.User().AddTenantRoles("abc", "123", []string{"foo"})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Len(t, res.UserTenants, 1)
	require.Equal(t, "123", res.UserTenants[0].TenantID)
	require.Equal(t, []string{"foo"}, res.UserTenants[0].Roles)
}

func TestUserAddTenantRoleBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().AddTenantRoles("", "123", []string{"foo"})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserAddTenantRoleError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().AddTenantRoles("abc", "123", []string{"foo"})
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
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, "123", req["tenantId"])
		require.Equal(t, []any{"foo", "bar"}, req["roleNames"])
	}, response))
	res, err := m.User().RemoveTenantRoles("abc", "123", []string{"foo", "bar"})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Len(t, res.UserTenants, 1)
	require.Equal(t, "123", res.UserTenants[0].TenantID)
	require.Equal(t, []string{"qux", "zut"}, res.UserTenants[0].Roles)
}

func TestUserRemoveTenantRoleBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().RemoveTenantRoles("", "123", []string{"foo", "bar"})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserRemoveTenantRoleError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().RemoveTenantRoles("abc", "123", []string{"foo", "bar"})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserSetPasswordSuccess(t *testing.T) {
	response := map[string]any{}
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, "123", req["password"])
	}, response))
	err := m.User().SetPassword("abc", "123")
	require.NoError(t, err)
}

func TestUserSetPasswordBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	err := m.User().SetPassword("", "123")
	require.Error(t, err)
	err = m.User().SetPassword("abc", "")
	require.Error(t, err)
}

func TestSetUserPasswordError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	err := m.User().SetPassword("abc", "123")
	require.Error(t, err)
}

func TestUserExpirePasswordSuccess(t *testing.T) {
	response := map[string]any{}
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
	}, response))
	err := m.User().ExpirePassword("abc")
	require.NoError(t, err)
}

func TestUserExpirePasswordBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	err := m.User().ExpirePassword("")
	require.Error(t, err)
}

func TestExpireUserPasswordError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	err := m.User().ExpirePassword("abc")
	require.Error(t, err)
}

func TestUserProviderTokenSuccess(t *testing.T) {
	response := map[string]any{
		"provider": "pro",
	}
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		params := helpers.ReadParams(r)
		require.Equal(t, "abc", params["loginId"])
		require.Equal(t, "pro", params["provider"])
	}, response))
	res, err := m.User().GetProviderToken("abc", "pro")
	require.NoError(t, err)
	require.NotEmpty(t, res)
	assert.EqualValues(t, "pro", res.Provider)
}

func TestUserProviderTokenBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().GetProviderToken("", "pro")
	require.Error(t, err)
	require.Empty(t, res)

	res, err = m.User().GetProviderToken("abc", "")
	require.Error(t, err)
	require.Empty(t, res)
}

func TestUserProviderTokenError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().GetProviderToken("abc", "pro")
	require.Error(t, err)
	require.Empty(t, res)
}

func TestGenerateOTPForTestUserSuccess(t *testing.T) {
	loginID := "some-id"
	code := "123456"
	response := map[string]any{
		"loginId": loginID,
		"code":    code,
	}
	visited := false
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		visited = true
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, loginID, req["loginId"])
		require.Equal(t, string(descope.MethodSMS), req["deliveryMethod"])
	}, response))
	resCode, err := m.User().GenerateOTPForTestUser(descope.MethodSMS, loginID)
	require.NoError(t, err)
	require.NotEmpty(t, resCode)
	require.True(t, visited)
	assert.EqualValues(t, code, resCode)
}

func TestGenerateOTPForTestUserNoLoginID(t *testing.T) {
	loginID := "some-id"
	code := "123456"
	response := map[string]any{
		"loginId": loginID,
		"code":    code,
	}
	visited := false
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		visited = true
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, loginID, req["loginId"])
		require.Equal(t, string(descope.MethodSMS), req["deliveryMethod"])
	}, response))
	resCode, err := m.User().GenerateOTPForTestUser(descope.MethodSMS, "")
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	require.Contains(t, err.Error(), "loginID")
	require.Empty(t, resCode)
	require.False(t, visited)
}

func TestGenerateMagicLinkForTestUserSuccess(t *testing.T) {
	loginID := "some-id"
	URI := "uri"
	link := "https://link.com?t=123"
	pendingRef := "pend"
	response := map[string]any{
		"loginId":    loginID,
		"link":       link,
		"pendingRef": pendingRef,
	}
	visited := false
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		visited = true
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, loginID, req["loginId"])
		require.Equal(t, string(descope.MethodSMS), req["deliveryMethod"])
		require.Equal(t, URI, req["URI"])
	}, response))
	resLink, err := m.User().GenerateMagicLinkForTestUser(descope.MethodSMS, loginID, URI)
	require.NoError(t, err)
	require.NotEmpty(t, resLink)
	require.True(t, visited)
	assert.EqualValues(t, link, resLink)
}

func TestGenerateMagicLinkForTestUserNoLoginID(t *testing.T) {
	loginID := "some-id"
	URI := "uri"
	link := "https://link.com?t=123"
	pendingRef := "pend"
	response := map[string]any{
		"loginId":    loginID,
		"link":       link,
		"pendingRef": pendingRef,
	}
	visited := false
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		visited = true
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, loginID, req["loginId"])
		require.Equal(t, string(descope.MethodSMS), req["deliveryMethod"])
		require.Equal(t, URI, req["URI"])
		require.Equal(t, true, req["crossDevice"])
	}, response))
	resLink, err := m.User().GenerateMagicLinkForTestUser(descope.MethodSMS, "", URI)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	require.Contains(t, err.Error(), "loginID")
	require.Empty(t, resLink)
	require.False(t, visited)
}

func TestGenerateEnchantedLinkForTestUserSuccess(t *testing.T) {
	loginID := "some-id"
	URI := "uri"
	link := "https://link.com?t=123"
	pendingRef := "pend"
	response := map[string]any{
		"loginId":    loginID,
		"link":       link,
		"pendingRef": pendingRef,
	}
	visited := false
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		visited = true
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, loginID, req["loginId"])
		require.Equal(t, URI, req["URI"])
	}, response))
	resLink, resPendingRef, err := m.User().GenerateEnchantedLinkForTestUser(loginID, URI)
	require.NoError(t, err)
	require.NotEmpty(t, resLink)
	require.NotEmpty(t, resPendingRef)
	require.True(t, visited)
	assert.EqualValues(t, link, resLink)
	assert.EqualValues(t, pendingRef, resPendingRef)
}

func TestGenerateEnchantedLinkForTestUserNoLoginID(t *testing.T) {
	loginID := "some-id"
	URI := "uri"
	link := "https://link.com?t=123"
	pendingRef := "pend"
	response := map[string]any{
		"loginId":    loginID,
		"link":       link,
		"pendingRef": pendingRef,
	}
	visited := false
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		visited = true
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, loginID, req["loginId"])
		require.Equal(t, URI, req["URI"])
	}, response))
	resLink, resPendingRef, err := m.User().GenerateEnchantedLinkForTestUser("", URI)
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	require.Contains(t, err.Error(), "loginID")
	require.Empty(t, resLink)
	require.Empty(t, resPendingRef)
	require.False(t, visited)
}
func TestGenerateEmbeddedLink(t *testing.T) {
	readyToken := "orgjwt"
	loginID := "sometext"
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.EqualValues(t, loginID, req["loginId"])
		require.NotEmpty(t, req["customClaims"])

	}, map[string]interface{}{"token": readyToken}))
	token, err := mgmt.User().GenerateEmbeddedLink(loginID, map[string]any{"ak": "av"})
	require.NoError(t, err)
	require.EqualValues(t, readyToken, token)
}

func TestGenerateEmbeddedLinkMissingLoginID(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		called = true

	}))
	token, err := mgmt.User().GenerateEmbeddedLink("", map[string]any{"ak": "av"})
	require.Error(t, err)
	require.False(t, called)
	require.Empty(t, token)
}

func TestGenerateEmbeddedLinkHTTPError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(func(r *http.Request) {
		called = true
	}))
	token, err := mgmt.User().GenerateEmbeddedLink("test", map[string]any{"ak": "av"})
	require.Error(t, err)
	require.True(t, called)
	require.Empty(t, token)
}

func TestUserCreateWithVerifiedEmailUserSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"email": "a@b.c",
		}}
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, "foo@bar.com", req["email"])
		roleNames := req["roleNames"].([]any)
		require.Len(t, roleNames, 1)
		require.Equal(t, "foo", roleNames[0])
		require.EqualValues(t, true, req["test"])
		require.EqualValues(t, true, req["verifiedEmail"])
	}, response))
	user := &descope.UserRequest{}
	user.Email = "foo@bar.com"
	tr := true
	user.VerifiedEmail = &tr
	user.Roles = []string{"foo"}
	res, err := m.User().CreateTestUser("abc", user)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "a@b.c", res.Email)
}

func TestUserCreateWithVerifiedPhoneUserSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"email": "a@b.c",
		}}
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, "foo@bar.com", req["email"])
		roleNames := req["roleNames"].([]any)
		require.Len(t, roleNames, 1)
		require.Equal(t, "foo", roleNames[0])
		require.EqualValues(t, true, req["test"])
		require.EqualValues(t, false, req["verifiedPhone"])
	}, response))
	user := &descope.UserRequest{}
	user.Email = "foo@bar.com"
	tr := false
	user.VerifiedPhone = &tr
	user.Roles = []string{"foo"}
	res, err := m.User().CreateTestUser("abc", user)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "a@b.c", res.Email)
}
