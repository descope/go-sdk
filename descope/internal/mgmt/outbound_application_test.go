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

func TestOutboundApplicationCreateSuccess(t *testing.T) {
	response := map[string]any{"app": map[string]any{"id": "id1", "name": "app1"}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/outbound/app/create", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "app1", req["name"])
		assert.Equal(t, "sec", req["clientSecret"])
	}, response))
	app, err := mgmt.OutboundApplication().CreateApplication(context.Background(), &descope.CreateOutboundAppRequest{
		OutboundApp: descope.OutboundApp{
			Name: "app1",
		},
		ClientSecret: "sec",
	})
	require.NoError(t, err)
	require.NotNil(t, app)
	require.Equal(t, "id1", app.ID)
	require.Equal(t, "app1", app.Name)
}

func TestOutboundApplicationCreateError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		called = true
	}))

	// Nil request
	app, err := mgmt.OutboundApplication().CreateApplication(context.Background(), nil)
	require.Error(t, err)
	require.Nil(t, app)

	// Empty Name
	app, err = mgmt.OutboundApplication().CreateApplication(context.Background(), &descope.CreateOutboundAppRequest{})
	require.Error(t, err)
	require.Nil(t, app)
	require.False(t, called)
}

func TestOutboundApplicationUpdateSuccess(t *testing.T) {
	response := map[string]any{"app": map[string]any{"id": "id1", "name": "app1"}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/outbound/app/update", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "id1", req["app"].(map[string]any)["id"])
		assert.Equal(t, "app1", req["app"].(map[string]any)["name"])
		assert.Equal(t, "sec", req["app"].(map[string]any)["clientSecret"])
	}, response))
	secret := "sec"
	app, err := mgmt.OutboundApplication().UpdateApplication(context.Background(), &descope.OutboundApp{
		ID:   "id1",
		Name: "app1",
	}, &secret)
	require.NoError(t, err)
	require.NotNil(t, app)
	require.Equal(t, "id1", app.ID)
	require.Equal(t, "app1", app.Name)
}

func TestOutboundApplicationUpdateError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		called = true
	}))

	// Nil request
	app, err := mgmt.OutboundApplication().UpdateApplication(context.Background(), nil, nil)
	require.Error(t, err)
	require.Nil(t, app)

	// Empty ID
	app, err = mgmt.OutboundApplication().UpdateApplication(context.Background(), &descope.OutboundApp{Name: "app1"}, nil)
	require.Error(t, err)
	require.Nil(t, app)

	// Empty Name
	app, err = mgmt.OutboundApplication().UpdateApplication(context.Background(), &descope.OutboundApp{ID: "id1"}, nil)
	require.Error(t, err)
	require.Nil(t, app)
	require.False(t, called)
}

func TestOutboundApplicationDeleteSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/outbound/app/delete", r.URL.Path)
	}))
	err := mgmt.OutboundApplication().DeleteApplication(context.Background(), "id1")
	require.NoError(t, err)
}

func TestOutboundApplicationDeleteError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		called = true
	}))

	err := mgmt.OutboundApplication().DeleteApplication(context.Background(), "")
	require.Error(t, err)
	require.False(t, called)
}

func TestOutboundApplicationLoadSuccess(t *testing.T) {
	response := map[string]any{"app": map[string]any{"id": "id1", "name": "app1"}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Contains(t, r.URL.Path, "/v1/mgmt/outbound/app/id1")
	}, response))

	app, err := mgmt.OutboundApplication().LoadApplication(context.Background(), "id1")
	require.NoError(t, err)
	require.NotNil(t, app)
	require.Equal(t, "id1", app.ID)
	require.Equal(t, "app1", app.Name)
}

func TestOutboundApplicationLoadError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		called = true
	}))

	app, err := mgmt.OutboundApplication().LoadApplication(context.Background(), "")
	require.Error(t, err)
	require.Nil(t, app)
	require.False(t, called)
}

func TestOutboundApplicationLoadAllSuccess(t *testing.T) {
	response := map[string]any{"apps": []map[string]any{
		{"id": "id1", "name": "app1"},
		{"id": "id2", "name": "app2"},
	}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/outbound/apps", r.URL.Path)
	}, response))

	apps, err := mgmt.OutboundApplication().LoadAllApplications(context.Background())
	require.NoError(t, err)
	require.Len(t, apps, 2)
	require.Equal(t, "id1", apps[0].ID)
	require.Equal(t, "app2", apps[1].Name)
}

func TestOutboundApplicationLoadAllError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	apps, err := mgmt.OutboundApplication().LoadAllApplications(context.Background())
	require.Error(t, err)
	require.Nil(t, apps)
}

func TestOutboundApplicationFetchUserTokenSuccess(t *testing.T) {
	response := map[string]any{
		"token": map[string]any{
			"id":                "token-id",
			"appId":             "app-id",
			"userId":            "user-id",
			"tokenSub":          "sub",
			"accessToken":       "access-token",
			"accessTokenType":   "Bearer",
			"accessTokenExpiry": "2024-12-31T23:59:59Z",
			"hasRefreshToken":   true,
			"scopes":            []string{"read", "write"},
		},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/outbound/app/user/token", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "app-id", req["appId"])
		assert.Equal(t, "user-id", req["userId"])
		assert.Equal(t, []any{"read", "write"}, req["scopes"])
	}, response))

	token, err := mgmt.OutboundApplication().FetchUserToken(context.Background(), &descope.FetchOutboundAppUserTokenRequest{
		AppID:  "app-id",
		UserID: "user-id",
		Scopes: []string{"read", "write"},
	})
	require.NoError(t, err)
	require.NotNil(t, token)
	assert.Equal(t, "token-id", token.ID)
	assert.Equal(t, "app-id", token.AppID)
	assert.Equal(t, "user-id", token.UserID)
	assert.Equal(t, "access-token", token.AccessToken)
	assert.True(t, token.HasRefreshToken)
}

func TestOutboundApplicationFetchUserTokenError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		called = true
	}))

	token, err := mgmt.OutboundApplication().FetchUserToken(context.Background(), nil)
	require.Error(t, err)
	require.Nil(t, token)

	token, err = mgmt.OutboundApplication().FetchUserToken(context.Background(), &descope.FetchOutboundAppUserTokenRequest{})
	require.Error(t, err)
	require.Nil(t, token)

	token, err = mgmt.OutboundApplication().FetchUserToken(context.Background(), &descope.FetchOutboundAppUserTokenRequest{
		AppID: "app-id",
	})
	require.Error(t, err)
	require.Nil(t, token)
	require.False(t, called)
}

func TestOutboundApplicationFetchLatestUserTokenSuccess(t *testing.T) {
	response := map[string]any{"token": map[string]any{"id": "token-id", "appId": "app-id", "userId": "user-id"}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/outbound/app/user/token/latest", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "app-id", req["appId"])
		assert.Equal(t, "user-id", req["userId"])
	}, response))

	token, err := mgmt.OutboundApplication().FetchLatestUserToken(context.Background(), &descope.FetchOutboundAppUserTokenRequest{
		AppID:  "app-id",
		UserID: "user-id",
	})
	require.NoError(t, err)
	require.NotNil(t, token)
	assert.Equal(t, "token-id", token.ID)
}

func TestOutboundApplicationFetchLatestUserTokenError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		called = true
	}))

	token, err := mgmt.OutboundApplication().FetchLatestUserToken(context.Background(), nil)
	require.Error(t, err)
	require.Nil(t, token)

	token, err = mgmt.OutboundApplication().FetchLatestUserToken(context.Background(), &descope.FetchOutboundAppUserTokenRequest{AppID: "app-id"})
	require.Error(t, err)
	require.Nil(t, token)
	require.False(t, called)
}

func TestOutboundApplicationFetchTenantTokenSuccess(t *testing.T) {
	response := map[string]any{"token": map[string]any{"id": "token-id", "appId": "app-id", "tenantId": "tenant-id"}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/outbound/app/tenant/token", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "app-id", req["appId"])
		assert.Equal(t, "tenant-id", req["tenantId"])
		assert.Equal(t, []any{"read"}, req["scopes"])
	}, response))

	token, err := mgmt.OutboundApplication().FetchTenantToken(context.Background(), &descope.FetchOutboundAppTenantTokenRequest{
		AppID:    "app-id",
		TenantID: "tenant-id",
		Scopes:   []string{"read"},
	})
	require.NoError(t, err)
	require.NotNil(t, token)
	assert.Equal(t, "token-id", token.ID)
}

func TestOutboundApplicationFetchTenantTokenError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		called = true
	}))

	token, err := mgmt.OutboundApplication().FetchTenantToken(context.Background(), nil)
	require.Error(t, err)
	require.Nil(t, token)

	token, err = mgmt.OutboundApplication().FetchTenantToken(context.Background(), &descope.FetchOutboundAppTenantTokenRequest{AppID: "app-id"})
	require.Error(t, err)
	require.Nil(t, token)
	require.False(t, called)
}

func TestOutboundApplicationFetchLatestTenantTokenSuccess(t *testing.T) {
	response := map[string]any{"token": map[string]any{"id": "token-id", "appId": "app-id", "tenantId": "tenant-id"}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/outbound/app/tenant/token/latest", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "app-id", req["appId"])
		assert.Equal(t, "tenant-id", req["tenantId"])
	}, response))

	token, err := mgmt.OutboundApplication().FetchLatestTenantToken(context.Background(), &descope.FetchOutboundAppTenantTokenRequest{
		AppID:    "app-id",
		TenantID: "tenant-id",
	})
	require.NoError(t, err)
	require.NotNil(t, token)
	assert.Equal(t, "token-id", token.ID)
}

func TestOutboundApplicationListAppsWithUserTokenSuccess(t *testing.T) {
	response := map[string]any{"appIds": []string{"app1", "app2"}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/outbound/apps-with-user-token", r.URL.Path)
		assert.Equal(t, "user-id", r.URL.Query().Get("userId"))
		assert.Equal(t, "tenant-id", r.URL.Query().Get("tenantId"))
	}, response))

	appIDs, err := mgmt.OutboundApplication().ListAppsWithUserToken(context.Background(), "user-id", "tenant-id")
	require.NoError(t, err)
	require.Equal(t, []string{"app1", "app2"}, appIDs)
}

func TestOutboundApplicationListAppsWithUserTokenNoTenant(t *testing.T) {
	response := map[string]any{"appIds": []string{"app1"}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Equal(t, "user-id", r.URL.Query().Get("userId"))
		assert.Equal(t, "", r.URL.Query().Get("tenantId"))
	}, response))

	appIDs, err := mgmt.OutboundApplication().ListAppsWithUserToken(context.Background(), "user-id", "")
	require.NoError(t, err)
	require.Equal(t, []string{"app1"}, appIDs)
}

func TestOutboundApplicationListAppsWithUserTokenError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		called = true
	}))

	appIDs, err := mgmt.OutboundApplication().ListAppsWithUserToken(context.Background(), "", "")
	require.Error(t, err)
	require.Nil(t, appIDs)
	require.False(t, called)
}

func TestOutboundApplicationUploadUserAPIKeySuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/outbound/app/user/apikey/upload", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "app-id", req["appId"])
		assert.Equal(t, "user-id", req["userId"])
		assert.Equal(t, "secret-key", req["apiKey"])
		assert.Equal(t, "tenant-id", req["tenantId"])
	}))

	err := mgmt.OutboundApplication().UploadUserAPIKey(context.Background(), &descope.UploadOutboundAppUserAPIKeyRequest{
		AppID:    "app-id",
		UserID:   "user-id",
		APIKey:   "secret-key",
		TenantID: "tenant-id",
	})
	require.NoError(t, err)
}

func TestOutboundApplicationUploadUserAPIKeyError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		called = true
	}))

	require.Error(t, mgmt.OutboundApplication().UploadUserAPIKey(context.Background(), nil))
	require.Error(t, mgmt.OutboundApplication().UploadUserAPIKey(context.Background(), &descope.UploadOutboundAppUserAPIKeyRequest{UserID: "u", APIKey: "k"}))
	require.Error(t, mgmt.OutboundApplication().UploadUserAPIKey(context.Background(), &descope.UploadOutboundAppUserAPIKeyRequest{AppID: "a", APIKey: "k"}))
	require.Error(t, mgmt.OutboundApplication().UploadUserAPIKey(context.Background(), &descope.UploadOutboundAppUserAPIKeyRequest{AppID: "a", UserID: "u"}))
	require.False(t, called)
}

func TestOutboundApplicationUploadTenantAPIKeySuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/outbound/app/tenant/apikey/upload", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "app-id", req["appId"])
		assert.Equal(t, "tenant-id", req["tenantId"])
		assert.Equal(t, "secret-key", req["apiKey"])
	}))

	err := mgmt.OutboundApplication().UploadTenantAPIKey(context.Background(), &descope.UploadOutboundAppTenantAPIKeyRequest{
		AppID:    "app-id",
		TenantID: "tenant-id",
		APIKey:   "secret-key",
	})
	require.NoError(t, err)
}

func TestOutboundApplicationUploadTenantAPIKeyError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		called = true
	}))

	require.Error(t, mgmt.OutboundApplication().UploadTenantAPIKey(context.Background(), nil))
	require.Error(t, mgmt.OutboundApplication().UploadTenantAPIKey(context.Background(), &descope.UploadOutboundAppTenantAPIKeyRequest{TenantID: "t", APIKey: "k"}))
	require.Error(t, mgmt.OutboundApplication().UploadTenantAPIKey(context.Background(), &descope.UploadOutboundAppTenantAPIKeyRequest{AppID: "a", APIKey: "k"}))
	require.Error(t, mgmt.OutboundApplication().UploadTenantAPIKey(context.Background(), &descope.UploadOutboundAppTenantAPIKeyRequest{AppID: "a", TenantID: "t"}))
	require.False(t, called)
}

func TestOutboundApplicationUploadUserTokenSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/outbound/app/user/oauthtoken/upload", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "app-id", req["appId"])
		assert.Equal(t, "user-id", req["userId"])
		assert.Equal(t, "refresh", req["refreshToken"])
		assert.Equal(t, true, req["verifyRefresh"])
	}))

	err := mgmt.OutboundApplication().UploadUserToken(context.Background(), &descope.UploadOutboundAppUserTokenRequest{
		OutboundAppUserTokenToUpload: descope.OutboundAppUserTokenToUpload{
			AppID:        "app-id",
			UserID:       "user-id",
			RefreshToken: "refresh",
			Scopes:       []string{"read"},
		},
		VerifyRefresh: true,
	})
	require.NoError(t, err)
}

func TestOutboundApplicationUploadUserTokenError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		called = true
	}))

	require.Error(t, mgmt.OutboundApplication().UploadUserToken(context.Background(), nil))
	// missing both refresh and access token
	require.Error(t, mgmt.OutboundApplication().UploadUserToken(context.Background(), &descope.UploadOutboundAppUserTokenRequest{
		OutboundAppUserTokenToUpload: descope.OutboundAppUserTokenToUpload{AppID: "a", UserID: "u"},
	}))
	require.False(t, called)
}

func TestOutboundApplicationUploadTenantTokenSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/outbound/app/tenant/oauthtoken/upload", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		assert.Equal(t, "app-id", req["appId"])
		assert.Equal(t, "tenant-id", req["tenantId"])
		assert.Equal(t, "access", req["accessToken"])
	}))

	err := mgmt.OutboundApplication().UploadTenantToken(context.Background(), &descope.UploadOutboundAppTenantTokenRequest{
		OutboundAppTenantTokenToUpload: descope.OutboundAppTenantTokenToUpload{
			AppID:       "app-id",
			TenantID:    "tenant-id",
			AccessToken: "access",
		},
	})
	require.NoError(t, err)
}

func TestOutboundApplicationUploadTenantTokenError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		called = true
	}))

	require.Error(t, mgmt.OutboundApplication().UploadTenantToken(context.Background(), nil))
	require.Error(t, mgmt.OutboundApplication().UploadTenantToken(context.Background(), &descope.UploadOutboundAppTenantTokenRequest{
		OutboundAppTenantTokenToUpload: descope.OutboundAppTenantTokenToUpload{AppID: "a"},
	}))
	require.False(t, called)
}

func TestOutboundApplicationBatchUploadUserTokensSuccess(t *testing.T) {
	response := map[string]any{"failures": []map[string]any{
		{"appId": "app-id", "userId": "user-2", "errorCode": "E152110", "reason": "bad token"},
	}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/outbound/app/user/oauthtoken/batch/upload", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		tokens := req["tokens"].([]any)
		require.Len(t, tokens, 2)
		assert.Equal(t, "app-id", tokens[0].(map[string]any)["appId"])
	}, response))

	res, err := mgmt.OutboundApplication().BatchUploadUserTokens(context.Background(), []*descope.OutboundAppUserTokenToUpload{
		{AppID: "app-id", UserID: "user-1", AccessToken: "a1"},
		{AppID: "app-id", UserID: "user-2", AccessToken: "a2"},
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Len(t, res.Failures, 1)
	assert.Equal(t, "E152110", res.Failures[0].ErrorCode)
	assert.Equal(t, "user-2", res.Failures[0].UserID)
}

func TestOutboundApplicationBatchUploadUserTokensError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		called = true
	}))

	res, err := mgmt.OutboundApplication().BatchUploadUserTokens(context.Background(), nil)
	require.Error(t, err)
	require.Nil(t, res)
	require.False(t, called)
}

func TestOutboundApplicationBatchUploadTenantTokensSuccess(t *testing.T) {
	response := map[string]any{"failures": []map[string]any{}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/outbound/app/tenant/oauthtoken/batch/upload", r.URL.Path)
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Len(t, req["tokens"].([]any), 1)
	}, response))

	res, err := mgmt.OutboundApplication().BatchUploadTenantTokens(context.Background(), []*descope.OutboundAppTenantTokenToUpload{
		{AppID: "app-id", TenantID: "tenant-1", AccessToken: "a1"},
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Empty(t, res.Failures)
}

func TestOutboundApplicationDeleteUserTokensSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/outbound/user/tokens", r.URL.Path)
		assert.Equal(t, "app-id", r.URL.Query().Get("appId"))
		assert.Equal(t, "user-id", r.URL.Query().Get("userId"))
	}))

	err := mgmt.OutboundApplication().DeleteUserTokens(context.Background(), "app-id", "user-id")
	require.NoError(t, err)
}

func TestOutboundApplicationDeleteUserTokensByAppID(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/outbound/user/tokens", r.URL.Path)
		assert.Equal(t, "app-id", r.URL.Query().Get("appId"))
		assert.Equal(t, "", r.URL.Query().Get("userId"))
	}))

	err := mgmt.OutboundApplication().DeleteUserTokens(context.Background(), "app-id", "")
	require.NoError(t, err)
}

func TestOutboundApplicationDeleteUserTokensByUserID(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/outbound/user/tokens", r.URL.Path)
		assert.Equal(t, "", r.URL.Query().Get("appId"))
		assert.Equal(t, "user-id", r.URL.Query().Get("userId"))
	}))

	err := mgmt.OutboundApplication().DeleteUserTokens(context.Background(), "", "user-id")
	require.NoError(t, err)
}

func TestOutboundApplicationDeleteUserTokensError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		called = true
	}))

	err := mgmt.OutboundApplication().DeleteUserTokens(context.Background(), "", "")
	require.Error(t, err)
	require.False(t, called)
}

func TestOutboundApplicationDeleteTokenByIDSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		assert.Equal(t, "/v1/mgmt/outbound/token", r.URL.Path)
		assert.Equal(t, "token-id", r.URL.Query().Get("id"))
	}))

	err := mgmt.OutboundApplication().DeleteTokenByID(context.Background(), "token-id")
	require.NoError(t, err)
}

func TestOutboundApplicationDeleteTokenByIDError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOk(func(_ *http.Request) {
		called = true
	}))

	err := mgmt.OutboundApplication().DeleteTokenByID(context.Background(), "")
	require.Error(t, err)
	require.False(t, called)
}
