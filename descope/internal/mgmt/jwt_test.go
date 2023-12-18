package mgmt

import (
	"context"
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope/tests/helpers"
	"github.com/stretchr/testify/require"
)

func TestUpdateJwt(t *testing.T) {
	orgJwt := "orgjwt"
	customClaims := map[string]any{"k1": "v1"}
	expectedJWT := "res"
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.EqualValues(t, orgJwt, req["jwt"])
		require.EqualValues(t, customClaims, req["customClaims"])

	}, map[string]interface{}{"jwt": expectedJWT}))
	jwtRes, err := mgmt.JWT().UpdateJWTWithCustomClaims(context.Background(), orgJwt, customClaims)
	require.NoError(t, err)
	require.EqualValues(t, expectedJWT, jwtRes)
}

func TestUpdateJwtMissingJWT(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		called = true

	}))
	jwtRes, err := mgmt.JWT().UpdateJWTWithCustomClaims(context.Background(), "", nil)
	require.Error(t, err)
	require.False(t, called)
	require.Empty(t, jwtRes)
}

func TestUpdateJwtHTTPError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(func(r *http.Request) {
		called = true
	}))
	jwtRes, err := mgmt.JWT().UpdateJWTWithCustomClaims(context.Background(), "test", nil)
	require.Error(t, err)
	require.True(t, called)
	require.Empty(t, jwtRes)
}
