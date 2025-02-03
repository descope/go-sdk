package mgmt

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/tests/helpers"
	"github.com/stretchr/testify/require"
)

func TestUpdateJwt(t *testing.T) {
	orgJwt := "orgjwt"
	customClaims := map[string]any{"k1": "v1"}
	expectedJWT := "res"
	refreshDuration := 3
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.EqualValues(t, orgJwt, req["jwt"])
		require.EqualValues(t, customClaims, req["customClaims"])
		require.EqualValues(t, refreshDuration, req["refreshDuration"])

	}, map[string]interface{}{"jwt": expectedJWT}))
	jwtRes, err := mgmt.JWT().UpdateJWTWithCustomClaims(context.Background(), orgJwt, customClaims, int32(refreshDuration))
	require.NoError(t, err)
	require.EqualValues(t, expectedJWT, jwtRes)
}

func TestUpdateJwtMissingJWT(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		called = true
	}))
	jwtRes, err := mgmt.JWT().UpdateJWTWithCustomClaims(context.Background(), "", nil, 0)
	require.Error(t, err)
	require.False(t, called)
	require.Empty(t, jwtRes)
}

func TestUpdateJwtHTTPError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(func(_ *http.Request) {
		called = true
	}))
	jwtRes, err := mgmt.JWT().UpdateJWTWithCustomClaims(context.Background(), "test", nil, 0)
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

const jwtTokenValid = `eyJhbGciOiJFUzM4NCIsImtpZCI6InRlc3RrZXkiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOlsidGVzdCJdLCJkcm4iOiJEUyIsImV4cCI6MzY1OTU2MTQzMCwiaWF0IjoxNjU5NTYxNDMwLCJpc3MiOiJ0ZXN0Iiwic3ViIjoic29tZXVzZXIiLCJ0ZXN0IjoidGVzdCJ9.tE6hXIuH74drymm6DSAs4FkaQSzf3MQ0D7pjC-9SaBRnqHoRuDOIJd3mIRsxzfb2nS6NX_tk6H1na6kFEKsJdMsUG-LbCqqib98z9tHtq-Jh6Axl5Qe9RITfIOwzOssw`
const jwtRTokenValid = `eyJhbGciOiJFUzM4NCIsImtpZCI6InRlc3RrZXkiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOlsidGVzdCJdLCJkcm4iOiJEU1IiLCJleHAiOjM2NTk1NjE0MzAsImlhdCI6MTY1OTU2MTQzMCwiaXNzIjoidGVzdCIsInN1YiI6InNvbWV1c2VyIiwidGVzdCI6InRlc3QifQ.zKbJKuGo9Q9NsvI_SdrH1pDH8uuTRnTcT4eMJe237Lr6ZrtRGbw2a0U0aEwgNrox2RXupkmD3vfQtZiD3AiU9xHY8X3xwTGsDwA497eT6RrA13zNufrhSMNjF6V5-xVl`

func TestSignIn(t *testing.T) {
	loginID := "id2"
	checked := false
	options := true
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/v1/mgmt/auth/signin") {
			checked = true
			require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
			req := map[string]any{}
			require.NoError(t, helpers.ReadBody(r, &req))
			require.EqualValues(t, loginID, req["loginId"])
			if options {
				require.EqualValues(t, "test", req["jwt"])
				require.EqualValues(t, true, req["mfa"])
				require.EqualValues(t, true, req["stepup"])
				require.EqualValues(t, true, req["revokeOtherSessions"])
				require.EqualValues(t, map[string]any{"k1": "v1"}, req["customClaims"])
			} else {
				require.Nil(t, req["jwt"])
				require.Nil(t, req["mfa"])
				require.Nil(t, req["stepup"])
				require.Nil(t, req["revokeOtherSessions"])
				require.Nil(t, req["customClaims"])
			}
		}
	}, &descope.JWTResponse{
		RefreshJwt: jwtRTokenValid,
		SessionJwt: jwtTokenValid,
		User: &descope.UserResponse{
			User: descope.User{
				Name:  "name",
				Phone: "phone",
			},
		},
		FirstSeen: true,
	}))
	jwtRes, err := mgmt.JWT().SignIn(context.Background(), loginID, &descope.MgmLoginOptions{Stepup: true, MFA: true, RevokeOtherSessions: true, CustomClaims: map[string]any{"k1": "v1"}, JWT: "test"})
	require.NoError(t, err)
	require.EqualValues(t, jwtRTokenValid, jwtRes.RefreshToken.JWT)
	require.True(t, checked)

	checked = false
	options = false
	jwtRes, err = mgmt.JWT().SignIn(context.Background(), loginID, nil)
	require.NoError(t, err)
	require.EqualValues(t, jwtRTokenValid, jwtRes.RefreshToken.JWT)
	require.True(t, checked)

	checked = false
	jwtRes, err = mgmt.JWT().SignIn(context.Background(), "", &descope.MgmLoginOptions{Stepup: true, MFA: true, RevokeOtherSessions: true, CustomClaims: map[string]any{"k1": "v1"}, JWT: "test"})
	require.Error(t, err)
	require.Nil(t, jwtRes)
	require.False(t, checked)

	jwtRes, err = mgmt.JWT().SignIn(context.Background(), loginID, &descope.MgmLoginOptions{Stepup: true, MFA: true, RevokeOtherSessions: true, CustomClaims: map[string]any{"k1": "v1"}})
	require.Error(t, err)
	require.Nil(t, jwtRes)
	require.False(t, checked)
}

func TestSignUp(t *testing.T) {
	loginID := "id2"
	checked := false
	options := true
	user := true
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/v1/mgmt/auth/signup") {
			checked = true
			require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
			req := map[string]any{}
			require.NoError(t, helpers.ReadBody(r, &req))
			require.EqualValues(t, loginID, req["loginId"])
			if user {
				require.EqualValues(t, "name", req["user"].(map[string]any)["name"])
				require.EqualValues(t, "phone", req["user"].(map[string]any)["phone"])
				require.EqualValues(t, true, req["emailVerified"])
				require.EqualValues(t, true, req["phoneVerified"])
				require.EqualValues(t, "sso", req["ssoAppId"])
			} else {
				require.Nil(t, req["user"].(map[string]any)["name"])
				require.Nil(t, req["user"].(map[string]any)["phone"])
				require.Nil(t, req["emailVerified"])
				require.Nil(t, req["phoneVerified"])
				require.Nil(t, req["ssoAppId"])
			}
			if options {
				require.EqualValues(t, map[string]any{"k1": "v1"}, req["customClaims"])
			} else {
				require.Nil(t, req["customClaims"])
			}
		}
	}, &descope.JWTResponse{
		RefreshJwt: jwtRTokenValid,
		SessionJwt: jwtTokenValid,
		User: &descope.UserResponse{
			User: descope.User{
				Name:  "name",
				Phone: "phone",
			},
		},
		FirstSeen: true,
	}))
	jwtRes, err := mgmt.JWT().SignUp(context.Background(), loginID, &descope.MgmtUserRequest{User: descope.User{Name: "name", Phone: "phone"}, EmailVerified: true, PhoneVerified: true, SsoAppID: "sso"}, &descope.MgmSignUpOptions{CustomClaims: map[string]any{"k1": "v1"}})
	require.NoError(t, err)
	require.EqualValues(t, jwtRTokenValid, jwtRes.RefreshToken.JWT)
	require.True(t, checked)

	checked = false
	options = false
	jwtRes, err = mgmt.JWT().SignUp(context.Background(), loginID, &descope.MgmtUserRequest{User: descope.User{Name: "name", Phone: "phone"}, EmailVerified: true, PhoneVerified: true, SsoAppID: "sso"}, nil)
	require.NoError(t, err)
	require.EqualValues(t, jwtRTokenValid, jwtRes.RefreshToken.JWT)
	require.True(t, checked)

	checked = false
	options = true
	user = false
	jwtRes, err = mgmt.JWT().SignUp(context.Background(), loginID, nil, &descope.MgmSignUpOptions{CustomClaims: map[string]any{"k1": "v1"}})
	require.NoError(t, err)
	require.EqualValues(t, jwtRTokenValid, jwtRes.RefreshToken.JWT)
	require.True(t, checked)

	checked = false
	_, err = mgmt.JWT().SignUp(context.Background(), "", nil, &descope.MgmSignUpOptions{CustomClaims: map[string]any{"k1": "v1"}})
	require.Error(t, err)
	require.False(t, checked)
}

func TestSignUpOrIn(t *testing.T) {
	loginID := "id2"
	checked := false
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/v1/mgmt/auth/signup-in") {
			checked = true
			require.Equal(t, "Bearer a:key", r.Header.Get("Authorization"))
			req := map[string]any{}
			require.NoError(t, helpers.ReadBody(r, &req))
			require.EqualValues(t, loginID, req["loginId"])
			require.EqualValues(t, "name", req["user"].(map[string]any)["name"])
			require.EqualValues(t, "phone", req["user"].(map[string]any)["phone"])
			require.EqualValues(t, true, req["emailVerified"])
			require.EqualValues(t, true, req["phoneVerified"])
			require.EqualValues(t, "sso", req["ssoAppId"])
			require.EqualValues(t, map[string]any{"k1": "v1"}, req["customClaims"])
		}
	}, &descope.JWTResponse{
		RefreshJwt: jwtRTokenValid,
		SessionJwt: jwtTokenValid,
		User: &descope.UserResponse{
			User: descope.User{
				Name:  "name",
				Phone: "phone",
			},
		},
		FirstSeen: true,
	}))
	jwtRes, err := mgmt.JWT().SignUpOrIn(context.Background(), loginID, &descope.MgmtUserRequest{User: descope.User{Name: "name", Phone: "phone"}, EmailVerified: true, PhoneVerified: true, SsoAppID: "sso"}, &descope.MgmSignUpOptions{CustomClaims: map[string]any{"k1": "v1"}})
	require.NoError(t, err)
	require.EqualValues(t, jwtRTokenValid, jwtRes.RefreshToken.JWT)
	require.True(t, checked)
}
