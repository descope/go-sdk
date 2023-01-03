package mgmt

import (
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope/tests/helpers"
	"github.com/stretchr/testify/require"
)

func TestUserCreateSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["identifier"])
		require.Equal(t, "foo@bar.com", req["email"])
		roleNames := req["roleNames"].([]any)
		require.Len(t, roleNames, 1)
		require.Equal(t, "foo", roleNames[0])
	}))
	err := mgmt.User().Create("abc", "foo@bar.com", "", "", []string{"foo"}, nil)
	require.NoError(t, err)
}

func TestUserCreateError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.User().Create("", "foo@bar.com", "", "", nil, nil)
	require.Error(t, err)
}

func TestUserUpdateSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["identifier"])
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
	}))
	err := mgmt.User().Update("abc", "foo@bar.com", "", "", nil, []*AssociatedTenant{{TenantID: "x", Roles: []string{"foo"}}, {TenantID: "y", Roles: []string{"bar"}}})
	require.NoError(t, err)
}

func TestUserUpdateError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.User().Update("", "foo@bar.com", "", "", nil, nil)
	require.Error(t, err)
}

func TestUserDeleteSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["identifier"])
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
		require.Equal(t, "abc", params["identifier"])
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

func TestUserLoadByJWTSubjectSuccess(t *testing.T) {
	response := map[string]any{
		"user": map[string]any{
			"email": "a@b.c",
		}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		params := helpers.ReadParams(r)
		require.Equal(t, "abc", params["jwtSubject"])
	}, response))
	res, err := mgmt.User().LoadByJWTSubject("abc")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "a@b.c", res.Email)
}

func TestUserLoadByJWTSubjectBadInput(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.User().LoadByJWTSubject("")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestUserLoadByJWTSubjectError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.User().LoadByJWTSubject("abc")
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
