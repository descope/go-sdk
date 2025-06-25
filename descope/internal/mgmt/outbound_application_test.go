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
