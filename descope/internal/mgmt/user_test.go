package mgmt

import (
	"context"
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/tests/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserCreateSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"email":     "a@b.c",
			"ssoAppIds": []string{"app1"},
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
		assert.EqualValues(t, []any{"app1"}, req["ssoAppIDs"])
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
	user.SSOAppIDs = append(user.SSOAppIDs, "app1")
	res, err := m.User().Create(context.Background(), "abc", user)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "a@b.c", res.Email)
	require.Equal(t, []string{"app1"}, res.SSOAppIDs)

	res, err = m.User().Invite(context.Background(), "abc", user, nil)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "a@b.c", res.Email)
	require.Equal(t, []string{"app1"}, res.SSOAppIDs)

	sendSMS := true
	sendMail := false
	res, err = m.User().Invite(context.Background(), "abc", user, &descope.InviteOptions{InviteURL: "https://some.domain.com", SendSMS: &sendSMS, SendMail: &sendMail})
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
		assert.EqualValues(t, map[string]any{"k1": "v1"}, req["templateOptions"])
		assert.Nil(t, req["sendMail"])
		assert.Nil(t, req["sendSMS"])
	}, response))
	user := &descope.UserRequest{}
	user.Email = "foo@bar.com"
	user.Roles = []string{"foo"}
	user.CustomAttributes = ca

	res, err := m.User().Invite(context.Background(), "abc", user, &descope.InviteOptions{
		InviteURL:       "https://some.domain.com",
		TemplateOptions: map[string]string{"k1": "v1"},
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "a@b.c", res.Email)
}

func TestUsersInviteBatchSuccess(t *testing.T) {
	response := map[string]any{
		"createdUsers": []map[string]any{
			{"email": "one@one.com"},
		},
		"failedUsers": []map[string]any{
			{
				"user": map[string]any{
					"email": "two@two.com",
				},
				"failure": "some failure",
			},
		},
	}
	ca := map[string]any{"ak": "av"}

	users := []*descope.BatchUser{}

	u1 := &descope.BatchUser{}
	u1.LoginID = "one"
	u1.Email = "one@one.com"
	u1.Roles = []string{"one"}
	u1.CustomAttributes = ca
	u1.Password = &descope.BatchUserPassword{Cleartext: "foo"}

	u2 := &descope.BatchUser{}
	u2.LoginID = "two"
	u2.Email = "two@two.com"
	u2.Roles = []string{"two"}
	u2.Password = &descope.BatchUserPassword{Hashed: &descope.BatchUserPasswordHashed{
		Pbkdf2: &descope.BatchUserPasswordPbkdf2{
			Hash:       []byte("1"),
			Salt:       []byte("2"),
			Iterations: 100,
			Type:       "sha256",
		},
	}}

	users = append(users, u1, u2)

	sendSMS := true

	called := false
	invite := true
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		called = true
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		if invite {
			assert.EqualValues(t, true, req["invite"])
			assert.EqualValues(t, "https://some.domain.com", req["inviteUrl"])
			assert.Nil(t, req["sendMail"])
			assert.EqualValues(t, true, req["sendSMS"])
		} else {
			assert.Nil(t, req["invite"])
		}
		usersRes := req["users"].([]any)
		userRes1 := usersRes[0].(map[string]any)
		userRes2 := usersRes[1].(map[string]any)
		require.Equal(t, u1.LoginID, userRes1["loginId"])
		require.Equal(t, u1.Email, userRes1["email"])
		assert.EqualValues(t, ca, userRes1["customAttributes"])
		require.Equal(t, "foo", userRes1["password"])
		roleNames := userRes1["roleNames"].([]any)
		require.Len(t, roleNames, 1)
		require.Equal(t, u1.Roles[0], roleNames[0])

		require.Equal(t, u2.LoginID, userRes2["loginId"])
		require.Equal(t, u2.Email, userRes2["email"])
		assert.Nil(t, userRes2["customAttributes"])
		pass2, _ := userRes2["hashedPassword"].(map[string]any)
		require.NotNil(t, pass2)
		pbkdf2, _ := pass2["pbkdf2"].(map[string]any)
		require.NotNil(t, pbkdf2)
		require.Equal(t, "MQ==", pbkdf2["hash"])
		require.Equal(t, "Mg==", pbkdf2["salt"])
		require.EqualValues(t, 100, pbkdf2["iterations"])
		require.Equal(t, "sha256", pbkdf2["type"])
		roleNames = userRes2["roleNames"].([]any)
		require.Len(t, roleNames, 1)
		require.Equal(t, u2.Roles[0], roleNames[0])
	}, response))

	res, err := m.User().InviteBatch(context.Background(), users, &descope.InviteOptions{
		InviteURL: "https://some.domain.com",
		SendSMS:   &sendSMS,
	})
	require.True(t, called)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Len(t, res.CreatedUsers, 1)
	require.Len(t, res.FailedUsers, 1)
	assert.EqualValues(t, u1.Email, res.CreatedUsers[0].Email)
	assert.EqualValues(t, u2.Email, res.FailedUsers[0].User.Email)
	assert.EqualValues(t, "some failure", res.FailedUsers[0].Failure)

	invite = false
	res, err = m.User().CreateBatch(context.Background(), users)
	require.True(t, called)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Len(t, res.CreatedUsers, 1)
	require.Len(t, res.FailedUsers, 1)
	assert.EqualValues(t, u1.Email, res.CreatedUsers[0].Email)
	assert.EqualValues(t, u2.Email, res.FailedUsers[0].User.Email)
	assert.EqualValues(t, "some failure", res.FailedUsers[0].Failure)
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
	res, err := m.User().CreateTestUser(context.Background(), "abc", user)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "a@b.c", res.Email)
}

func TestUserCreateError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	user := &descope.UserRequest{}
	user.Email = "foo@bar.com"
	_, err := m.User().Create(context.Background(), "", user)
	require.Error(t, err)
}

func TestUserCreateUpdateOrInviteWithNoUser(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	_, err := m.User().Create(context.Background(), "abc", nil)
	require.NoError(t, err)
	_, err = m.User().CreateTestUser(context.Background(), "abc", nil)
	require.NoError(t, err)
	_, err = m.User().Invite(context.Background(), "abc", nil, nil)
	require.NoError(t, err)
	_, err = m.User().Update(context.Background(), "abc", nil)
	require.NoError(t, err)
}

func TestUserUpdateSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"email":     "a@b.c",
			"ssoAppIds": []string{"app1"},
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
		require.Equal(t, []any{"app1"}, req["ssoAppIDs"])
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
	user.SSOAppIDs = append(user.SSOAppIDs, "app1")
	user.Tenants = []*descope.AssociatedTenant{{TenantID: "x", Roles: []string{"foo"}}, {TenantID: "y", Roles: []string{"bar"}}}
	res, err := m.User().Update(context.Background(), "abc", user)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "a@b.c", res.Email)
	require.Equal(t, []string{"app1"}, res.SSOAppIDs)
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
	res, err := m.User().Update(context.Background(), "abc", user)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "a@b.c", res.Email)
}

func TestUserUpdateError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	user := &descope.UserRequest{}
	user.Email = "foo@bar.com"
	_, err := m.User().Update(context.Background(), "", user)
	require.Error(t, err)
}

func TestUserDeleteSuccess(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
	}))
	err := m.User().Delete(context.Background(), "abc")
	require.NoError(t, err)
}

func TestUserDeleteByUserIDSuccess(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["userId"])
	}))
	err := m.User().DeleteByUserID(context.Background(), "abc")
	require.NoError(t, err)
}

func TestDeleteAllTestUsersSuccess(t *testing.T) {
	visited := false
	m := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		visited = true
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
	}))
	err := m.User().DeleteAllTestUsers(context.Background())
	require.NoError(t, err)
	assert.True(t, visited)
}

func TestUserDeleteError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	err := m.User().Delete(context.Background(), "")
	require.Error(t, err)
}

func TestUserDeleteByUserIDError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	err := m.User().DeleteByUserID(context.Background(), "")
	require.Error(t, err)
}

func TestUserImportSuccess(t *testing.T) {
	response := map[string]any{
		"users": []any{
			map[string]any{
				"email": "a@b.c",
			},
		},
		"failures": []any{
			map[string]any{
				"user":   "foo",
				"reason": "bar",
			},
		},
	}
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		body := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &body))
		require.Equal(t, "src", body["source"])
		require.Equal(t, "ZGVm", body["hashes"])
		require.Equal(t, "YWJj", body["users"])
		require.Equal(t, true, body["dryrun"])
	}, response))
	res, err := m.User().Import(context.Background(), "src", []byte("abc"), []byte("def"), true)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NotEmpty(t, res.Users)
	require.NotEmpty(t, res.Failures)
	require.Equal(t, "a@b.c", res.Users[0].Email)
	require.Equal(t, "foo", res.Failures[0].User)
	require.Equal(t, "bar", res.Failures[0].Reason)
}

func TestUserImportBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().Import(context.Background(), "", []byte("abc"), []byte("def"), true)
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserImportError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().Import(context.Background(), "src", []byte("abc"), []byte("def"), true)
	require.Error(t, err)
	require.Nil(t, res)
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
	res, err := m.User().Load(context.Background(), "abc")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "a@b.c", res.Email)
}

func TestUserLoadBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().Load(context.Background(), "")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserLoadError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().Load(context.Background(), "abc")
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
	res, err := m.User().LoadByUserID(context.Background(), "abc")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "a@b.c", res.Email)
}

func TestUserLoadByUserIDBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().LoadByUserID(context.Background(), "")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserLoadByUserIDError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().LoadByUserID(context.Background(), "abc")
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
	err := m.User().LogoutUserByUserID(context.Background(), "abc")
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
	err := m.User().LogoutUser(context.Background(), "abc")
	require.NoError(t, err)
}

func TestUserLogoutUserByUserIdErr(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Fail(t, "shouldn't get here")
	}, nil))
	err := m.User().LogoutUserByUserID(context.Background(), "")
	require.Error(t, err)
}

func TestUserLogoutUserByLoginIdErr(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Fail(t, "shouldn't get here")
	}, nil))
	err := m.User().LogoutUser(context.Background(), "")
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
		require.EqualValues(t, "blue", req["text"])
		require.EqualValues(t, []interface{}([]interface{}{map[string]interface{}{"Desc": true, "Field": "nono"}, map[string]interface{}{"Desc": false, "Field": "lolo"}}), req["sort"])
	}, response))
	res, err := m.User().SearchAll(context.Background(), &descope.UserSearchOptions{
		Statuses:         []descope.UserStatus{descope.UserStatusDisabled},
		TenantIDs:        tenantIDs,
		Roles:            roleNames,
		Limit:            100,
		CustomAttributes: map[string]any{"a": "b"},
		Emails:           []string{"a@b.com"},
		Phones:           []string{"+11111111"},
		Text:             "blue",
		Sort: []descope.UserSearchSort{
			{Field: "nono", Desc: true},
			{Field: "lolo", Desc: false},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Len(t, res, 1)
	require.Equal(t, "a@b.c", res[0].Email)
}

func TestSearchAllUsersError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().SearchAll(context.Background(), nil)
	require.Error(t, err)
	require.Nil(t, res)
}

func TestSearchAllUsersBadRequest(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().SearchAll(context.Background(), &descope.UserSearchOptions{Limit: -1})
	require.ErrorIs(t, err, descope.ErrInvalidArguments)
	require.Contains(t, err.Error(), "limit")
	require.Nil(t, res)

	res, err = m.User().SearchAll(context.Background(), &descope.UserSearchOptions{Page: -1})
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
	res, err := m.User().Activate(context.Background(), "abc")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "enabled", res.Status)
}

func TestUserActivateBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().Activate(context.Background(), "")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserActivateError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().Activate(context.Background(), "abc")
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
	res, err := m.User().Deactivate(context.Background(), "abc")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "disabled", res.Status)
}

func TestUserDeactivateBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().Deactivate(context.Background(), "")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserDeactivateError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().Deactivate(context.Background(), "abc")
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
	res, err := m.User().UpdateLoginID(context.Background(), "abc", "a@b.c")
	require.NoError(t, err)
	require.NotNil(t, res)
}

func TestUserUpdateLoginIDBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().UpdateLoginID(context.Background(), "", "a@b.c")
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
	res, err := m.User().UpdateEmail(context.Background(), "abc", "a@b.c", true)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "a@b.c", res.Email)
	require.Equal(t, true, res.VerifiedEmail)
}

func TestUserUpdateEmailBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().UpdateEmail(context.Background(), "", "a@b.c", true)
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserUpdateEmailError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().UpdateEmail(context.Background(), "abc", "a@b.c", true)
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
	res, err := m.User().UpdatePhone(context.Background(), "abc", "+18005551234", false)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "+18005551234", res.Phone)
	require.Equal(t, false, res.VerifiedPhone)
}

func TestUserUpdatePhoneBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().UpdatePhone(context.Background(), "", "+18005551234", true)
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserUpdatePhoneError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().UpdatePhone(context.Background(), "abc", "+18005551234", true)
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
	res, err := m.User().UpdateDisplayName(context.Background(), "abc", "foo")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "foo", res.Name)
}

func TestUserUpdateNameBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().UpdateDisplayName(context.Background(), "", "foo")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserUpdateNameError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().UpdateDisplayName(context.Background(), "abc", "foo")
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
	res, err := m.User().UpdatePicture(context.Background(), "abc", "foo")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "foo", res.Name)
}

func TestUserUpdatePictureBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().UpdatePicture(context.Background(), "", "foo")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserUpdatePictureError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().UpdatePicture(context.Background(), "abc", "foo")
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
	res, err := m.User().UpdateCustomAttribute(context.Background(), "abc", "foo", "bar")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "foo", res.Name)
}

func TestUserUpdateCustomAttributeBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().UpdateCustomAttribute(context.Background(), "", "foo", "bar")
	require.Error(t, err)
	require.Nil(t, res)
	res, err = m.User().UpdateCustomAttribute(context.Background(), "id", "", "bar")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserUpdateCustomAttributeError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().UpdateCustomAttribute(context.Background(), "abc", "foo", "bar")
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
	res, err := m.User().AddRoles(context.Background(), "abc", []string{"foo"})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, []string{"foo"}, res.RoleNames)
}

func TestUserAddRoleBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().AddRoles(context.Background(), "", []string{"foo"})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserAddRoleError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().AddRoles(context.Background(), "abc", []string{"foo"})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserSetRoleSuccess(t *testing.T) {
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
	res, err := m.User().SetRoles(context.Background(), "abc", []string{"foo"})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, []string{"foo"}, res.RoleNames)
}

func TestUserSetRoleBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().SetRoles(context.Background(), "", []string{"foo"})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserSetRoleError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().SetRoles(context.Background(), "abc", []string{"foo"})
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
	res, err := m.User().RemoveRoles(context.Background(), "abc", []string{"foo", "bar"})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, []string{"qux", "zut"}, res.RoleNames)
}

func TestUserRemoveRoleBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().RemoveRoles(context.Background(), "", []string{"foo", "bar"})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserRemoveRoleError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().RemoveRoles(context.Background(), "abc", []string{"foo", "bar"})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserAddSSOAppsSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"ssoAppIds": []string{"foo"},
		}}
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, []any{"foo"}, req["ssoAppIds"])
	}, response))
	res, err := m.User().AddSSOApps(context.Background(), "abc", []string{"foo"})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, []string{"foo"}, res.SSOAppIDs)
}

func TestUserAddSSOAppsBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().AddSSOApps(context.Background(), "", []string{"foo"})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserAddSSOAppsError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().AddSSOApps(context.Background(), "abc", []string{"foo"})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserSetSSOAppsSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"ssoAppIds": []string{"foo"},
		}}
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, []any{"foo"}, req["ssoAppIds"])
	}, response))
	res, err := m.User().SetSSOApps(context.Background(), "abc", []string{"foo"})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, []string{"foo"}, res.SSOAppIDs)
}

func TestUserSetSSOAppsBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().SetSSOApps(context.Background(), "", []string{"foo"})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserSetSSOAppsError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().SetSSOApps(context.Background(), "abc", []string{"foo"})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserRemoveSSOAppsSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"ssoAppIds": []string{"qux", "zut"},
		}}
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, []any{"foo", "bar"}, req["ssoAppIds"])
	}, response))
	res, err := m.User().RemoveSSOApps(context.Background(), "abc", []string{"foo", "bar"})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, []string{"qux", "zut"}, res.SSOAppIDs)
}

func TestUserRemoveSSOAppsBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().RemoveSSOApps(context.Background(), "", []string{"foo", "bar"})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserRemoveSSOAppsError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().RemoveSSOApps(context.Background(), "abc", []string{"foo", "bar"})
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
	res, err := m.User().AddTenant(context.Background(), "abc", "456")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Len(t, res.UserTenants, 2)
	require.Equal(t, "123", res.UserTenants[0].TenantID)
	require.Equal(t, "456", res.UserTenants[1].TenantID)
}

func TestUserAddTenantBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().AddTenant(context.Background(), "", "123")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserAddTenantError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().AddTenant(context.Background(), "abc", "123")
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
	res, err := m.User().RemoveTenant(context.Background(), "abc", "456")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Len(t, res.UserTenants, 1)
	require.Equal(t, "123", res.UserTenants[0].TenantID)
}

func TestUserRemoveTenantBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().RemoveTenant(context.Background(), "", "123")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserRemoveTenantError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().RemoveTenant(context.Background(), "abc", "123")
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
	res, err := m.User().AddTenantRoles(context.Background(), "abc", "123", []string{"foo"})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Len(t, res.UserTenants, 1)
	require.Equal(t, "123", res.UserTenants[0].TenantID)
	require.Equal(t, []string{"foo"}, res.UserTenants[0].Roles)
}

func TestUserAddTenantRoleBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().AddTenantRoles(context.Background(), "", "123", []string{"foo"})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserAddTenantRoleError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().AddTenantRoles(context.Background(), "abc", "123", []string{"foo"})
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
	res, err := m.User().RemoveTenantRoles(context.Background(), "abc", "123", []string{"foo", "bar"})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Len(t, res.UserTenants, 1)
	require.Equal(t, "123", res.UserTenants[0].TenantID)
	require.Equal(t, []string{"qux", "zut"}, res.UserTenants[0].Roles)
}

func TestUserRemoveTenantRoleBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().RemoveTenantRoles(context.Background(), "", "123", []string{"foo", "bar"})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserRemoveTenantRoleError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().RemoveTenantRoles(context.Background(), "abc", "123", []string{"foo", "bar"})
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserSetTemporaryPasswordSuccess(t *testing.T) {
	response := map[string]any{}
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, "123", req["password"])
		require.False(t, req["setActive"].(bool))
	}, response))
	err := m.User().SetTemporaryPassword(context.Background(), "abc", "123")
	require.NoError(t, err)
}

func TestUserSetTemporaryPasswordBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	err := m.User().SetTemporaryPassword(context.Background(), "", "123")
	require.Error(t, err)
	err = m.User().SetTemporaryPassword(context.Background(), "abc", "")
	require.Error(t, err)
}

func TestUserSetTemporaryPasswordError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	err := m.User().SetTemporaryPassword(context.Background(), "abc", "123")
	require.Error(t, err)
}

func TestUserSetActivePasswordSuccess(t *testing.T) {
	response := map[string]any{}
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, "123", req["password"])
		require.True(t, req["setActive"].(bool))
	}, response))
	err := m.User().SetActivePassword(context.Background(), "abc", "123")
	require.NoError(t, err)
}

func TestUserSetActivePasswordBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	err := m.User().SetActivePassword(context.Background(), "", "123")
	require.Error(t, err)
	err = m.User().SetActivePassword(context.Background(), "abc", "")
	require.Error(t, err)
}

func TestUserSetActivePasswordError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	err := m.User().SetActivePassword(context.Background(), "abc", "123")
	require.Error(t, err)
}

func TestUserSetPasswordSuccess(t *testing.T) {
	response := map[string]any{}
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
		require.Equal(t, "123", req["password"])
		require.False(t, req["setActive"].(bool))
	}, response))
	err := m.User().SetPassword(context.Background(), "abc", "123")
	require.NoError(t, err)
}

func TestUserSetPasswordBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	err := m.User().SetPassword(context.Background(), "", "123")
	require.Error(t, err)
	err = m.User().SetPassword(context.Background(), "abc", "")
	require.Error(t, err)
}

func TestUserSetPasswordError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	err := m.User().SetPassword(context.Background(), "abc", "123")
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
	err := m.User().ExpirePassword(context.Background(), "abc")
	require.NoError(t, err)
}

func TestUserExpirePasswordBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	err := m.User().ExpirePassword(context.Background(), "")
	require.Error(t, err)
}

func TestUserExpirePasswordError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	err := m.User().ExpirePassword(context.Background(), "abc")
	require.Error(t, err)
}

func TestUserRemoveAllPasskeysSuccess(t *testing.T) {
	response := map[string]any{}
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["loginId"])
	}, response))
	err := m.User().RemoveAllPasskeys(context.Background(), "abc")
	require.NoError(t, err)
}

func TestUserRemoveAllPasskeysBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	err := m.User().RemoveAllPasskeys(context.Background(), "")
	require.Error(t, err)
}

func TestUserRemoveAllPasskeysError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	err := m.User().RemoveAllPasskeys(context.Background(), "abc")
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
	res, err := m.User().GetProviderToken(context.Background(), "abc", "pro")
	require.NoError(t, err)
	require.NotEmpty(t, res)
	assert.EqualValues(t, "pro", res.Provider)
}

func TestUserProviderTokenBadInput(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := m.User().GetProviderToken(context.Background(), "", "pro")
	require.Error(t, err)
	require.Empty(t, res)

	res, err = m.User().GetProviderToken(context.Background(), "abc", "")
	require.Error(t, err)
	require.Empty(t, res)
}

func TestUserProviderTokenError(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := m.User().GetProviderToken(context.Background(), "abc", "pro")
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
	loginOptions := descope.LoginOptions{
		MFA: true,
	}
	visited := false
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		visited = true
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, loginID, req["loginId"])
		require.Equal(t, string(descope.MethodSMS), req["deliveryMethod"])
		b, err := utils.Marshal(req["loginOptions"])
		require.NoError(t, err)
		var loginOptionsReq descope.LoginOptions
		err = utils.Unmarshal(b, &loginOptionsReq)
		require.NoError(t, err)
		require.Equal(t, loginOptions, loginOptionsReq)
	}, response))

	resCode, err := m.User().GenerateOTPForTestUser(context.Background(), descope.MethodSMS, loginID, &loginOptions)
	require.NoError(t, err)
	require.NotEmpty(t, resCode)
	require.True(t, visited)
	assert.EqualValues(t, code, resCode)
}

func TestGenerateOTPForTestUserSuccessMethodVoice(t *testing.T) {
	loginID := "some-id"
	code := "123456"
	response := map[string]any{
		"loginId": loginID,
		"code":    code,
	}
	loginOptions := descope.LoginOptions{
		MFA: true,
	}
	visited := false
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		visited = true
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, loginID, req["loginId"])
		require.Equal(t, string(descope.MethodVoice), req["deliveryMethod"])
		b, err := utils.Marshal(req["loginOptions"])
		require.NoError(t, err)
		var loginOptionsReq descope.LoginOptions
		err = utils.Unmarshal(b, &loginOptionsReq)
		require.NoError(t, err)
		require.Equal(t, loginOptions, loginOptionsReq)
	}, response))

	resCode, err := m.User().GenerateOTPForTestUser(context.Background(), descope.MethodVoice, loginID, &loginOptions)
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
	resCode, err := m.User().GenerateOTPForTestUser(context.Background(), descope.MethodSMS, "", nil)
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
	loginOptions := descope.LoginOptions{
		MFA: true,
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
		b, err := utils.Marshal(req["loginOptions"])
		require.NoError(t, err)
		var loginOptionsReq descope.LoginOptions
		err = utils.Unmarshal(b, &loginOptionsReq)
		require.NoError(t, err)
		require.Equal(t, loginOptions, loginOptionsReq)
	}, response))
	resLink, err := m.User().GenerateMagicLinkForTestUser(context.Background(), descope.MethodSMS, loginID, URI, &loginOptions)
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
	resLink, err := m.User().GenerateMagicLinkForTestUser(context.Background(), descope.MethodSMS, "", URI, nil)
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
	loginOptions := descope.LoginOptions{
		MFA: true,
	}
	visited := false
	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		visited = true
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, loginID, req["loginId"])
		require.Equal(t, URI, req["URI"])
		b, err := utils.Marshal(req["loginOptions"])
		require.NoError(t, err)
		var loginOptionsReq descope.LoginOptions
		err = utils.Unmarshal(b, &loginOptionsReq)
		require.NoError(t, err)
		require.Equal(t, loginOptions, loginOptionsReq)
	}, response))
	resLink, resPendingRef, err := m.User().GenerateEnchantedLinkForTestUser(context.Background(), loginID, URI, &loginOptions)
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
	resLink, resPendingRef, err := m.User().GenerateEnchantedLinkForTestUser(context.Background(), "", URI, nil)
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
	token, err := mgmt.User().GenerateEmbeddedLink(context.Background(), loginID, map[string]any{"ak": "av"})
	require.NoError(t, err)
	require.EqualValues(t, readyToken, token)
}

func TestGenerateEmbeddedLinkMissingLoginID(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		called = true

	}))
	token, err := mgmt.User().GenerateEmbeddedLink(context.Background(), "", map[string]any{"ak": "av"})
	require.Error(t, err)
	require.False(t, called)
	require.Empty(t, token)
}

func TestGenerateEmbeddedLinkHTTPError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(func(r *http.Request) {
		called = true
	}))
	token, err := mgmt.User().GenerateEmbeddedLink(context.Background(), "test", map[string]any{"ak": "av"})
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
	res, err := m.User().CreateTestUser(context.Background(), "abc", user)
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
	res, err := m.User().CreateTestUser(context.Background(), "abc", user)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "a@b.c", res.Email)
}

func TestUserHistorySuccess(t *testing.T) {
	response := []map[string]any{
		{
			"userId":    "kuku",
			"city":      "kefar saba",
			"country":   "Israel",
			"ip":        "1.1.1.1",
			"loginTime": 32,
		},
		{
			"userId":    "nunu",
			"city":      "eilat",
			"country":   "Israele",
			"ip":        "1.1.1.2",
			"loginTime": 23,
		},
	}

	m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := []string{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, []string{"one", "two"}, req)
	}, response))

	userHistory, err := m.User().History(context.Background(), []string{"one", "two"})
	require.NoError(t, err)
	require.NotNil(t, userHistory)
	require.Len(t, userHistory, 2)

	assert.Equal(t, "kuku", userHistory[0].UserID)
	assert.Equal(t, "kefar saba", userHistory[0].City)
	assert.Equal(t, "Israel", userHistory[0].Country)
	assert.Equal(t, "1.1.1.1", userHistory[0].IP)
	assert.Equal(t, int32(32), userHistory[0].LoginTime)

	assert.Equal(t, "nunu", userHistory[1].UserID)
	assert.Equal(t, "eilat", userHistory[1].City)
	assert.Equal(t, "Israele", userHistory[1].Country)
	assert.Equal(t, "1.1.1.2", userHistory[1].IP)
	assert.Equal(t, int32(23), userHistory[1].LoginTime)
}

func TestHistoryNoUserIDs(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoOk(nil))
	userHistory, err := m.User().History(context.TODO(), nil)
	assert.ErrorIs(t, err, descope.ErrInvalidArguments)
	assert.Nil(t, userHistory)
}

func TestHistoryFailure(t *testing.T) {
	m := newTestMgmt(nil, helpers.DoBadRequest(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := []string{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, []string{"one", "two"}, req)
	}))
	userHistory, err := m.User().History(context.TODO(), []string{"one", "two"})
	assert.ErrorIs(t, err, descope.ErrInvalidResponse)
	assert.Nil(t, userHistory)
}
