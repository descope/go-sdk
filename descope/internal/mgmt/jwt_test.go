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
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		called = true
	}))
	jwtRes, err := mgmt.JWT().UpdateJWTWithCustomClaims(context.Background(), "", nil)
	require.Error(t, err)
	require.False(t, called)
	require.Empty(t, jwtRes)
}

func TestUpdateJwtHTTPError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(func(_ *http.Request) {
		called = true
	}))
	jwtRes, err := mgmt.JWT().UpdateJWTWithCustomClaims(context.Background(), "test", nil)
	require.Error(t, err)
	require.True(t, called)
	require.Empty(t, jwtRes)
}

func TestImpersonate(t *testing.T) {
	impID := "id1"
	loginID := "id2"
	expectedJWT := "res"
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.EqualValues(t, impID, req["impersonatorId"])
		require.EqualValues(t, loginID, req["loginId"])
		require.EqualValues(t, true, req["validateConsent"])
		require.EqualValues(t, "t1", req["selectedTenant"])
		require.EqualValues(t, map[string]any{"k1": "v1"}, req["customClaims"])

	}, map[string]interface{}{"jwt": expectedJWT}))
	jwtRes, err := mgmt.JWT().Impersonate(context.Background(), impID, loginID, true, map[string]any{"k1": "v1"}, "t1")
	require.NoError(t, err)
	require.EqualValues(t, expectedJWT, jwtRes)
}

func TestImpersonateMissingLoginID(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		called = true
	}))
	jwtRes, err := mgmt.JWT().Impersonate(context.Background(), "test", "", true, map[string]any{"k1": "v1"}, "t1")
	require.Error(t, err)
	require.False(t, called)
	require.Empty(t, jwtRes)
}

func TestImpersonateMissingImpersonator(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		called = true
	}))
	jwtRes, err := mgmt.JWT().Impersonate(context.Background(), "", "test", true, map[string]any{"k1": "v1"}, "t1")
	require.Error(t, err)
	require.False(t, called)
	require.Empty(t, jwtRes)
}
