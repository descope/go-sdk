package mgmt

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUserCreateSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		err := readBody(r, &req)
		require.NoError(t, err)
		require.Equal(t, req["identifier"], "abc")
		require.Equal(t, req["email"], "foo@bar.com")
	}))
	err := mgmt.User().Create("key", "abc", "foo@bar.com", "", "", nil, nil)
	require.NoError(t, err)
}

func TestUserCreateError(t *testing.T) {
	mgmt := newTestMgmt(nil, DoOk(nil))
	err := mgmt.User().Create("key", "", "email", "", "", nil, nil)
	require.Error(t, err)
}
