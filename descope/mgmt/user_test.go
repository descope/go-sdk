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
	err := mgmt.User().Create("key", "abc", "foo@bar.com", "", "", []string{"foo"}, nil)
	require.NoError(t, err)
}

func TestUserCreateError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.User().Create("key", "", "foo@bar.com", "", "", nil, nil)
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
	err := mgmt.User().Update("key", "abc", "foo@bar.com", "", "", nil, []UserTenants{{TenantID: "x", Roles: []string{"foo"}}, {TenantID: "y", Roles: []string{"bar"}}})
	require.NoError(t, err)
}

func TestUserUpdateError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.User().Update("key", "", "foo@bar.com", "", "", nil, nil)
	require.Error(t, err)
}

func TestUserDeleteSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["identifier"])
	}))
	err := mgmt.User().Delete("key", "abc")
	require.NoError(t, err)
}

func TestUserDeleteError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.User().Delete("key", "")
	require.Error(t, err)
}
