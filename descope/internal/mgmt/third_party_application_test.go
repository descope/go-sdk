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

func TestThirdPartyApplicationCreateSuccess(t *testing.T) {
	response := map[string]any{"id": "qux", "cleartext": "secret"}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "id1", req["id"])
		require.Equal(t, "abc", req["name"])
		require.Equal(t, "desc", req["description"])
		require.Equal(t, "logo", req["logo"])
		require.Equal(t, "http://dummy.com", req["loginPageUrl"])
	}, response))

	id, secret, err := mgmt.ThirdPartyApplication().CreateApplication(context.Background(), &descope.ThirdPartyApplicationRequest{
		ID:           "id1",
		Name:         "abc",
		Description:  "desc",
		Logo:         "logo",
		LoginPageURL: "http://dummy.com",
	})
	require.NoError(t, err)
	require.Equal(t, "qux", id)
	require.Equal(t, "secret", secret)
}

func TestThirdPartyApplicationCreateError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))

	// Empty application
	id, secret, err := mgmt.ThirdPartyApplication().CreateApplication(context.Background(), nil)
	require.Error(t, err)
	require.Empty(t, id)
	require.Empty(t, secret)

	// Empty application Name
	id, secret, err = mgmt.ThirdPartyApplication().CreateApplication(context.Background(), &descope.ThirdPartyApplicationRequest{ID: "id1"})
	require.Error(t, err)
	require.Empty(t, id)
	require.Empty(t, secret)
}

func TestThirdPartyApplicationUpdateSuccess(t *testing.T) {
	response := map[string]any{"id": "qux"}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "id1", req["id"])
		require.Equal(t, "abc", req["name"])
		require.Equal(t, "desc", req["description"])
		require.Equal(t, "logo", req["logo"])
		require.Equal(t, "http://dummy.com", req["loginPageUrl"])
		require.Equal(t, []any{"http://dummy.com/callback"}, req["approvedCallbackUrls"])
		require.Equal(t, []any{map[string]any{"name": "scope1", "description": "desc1", "values": []any{"v1"}}}, req["permissionsScopes"])
		require.Equal(t, []any{map[string]any{"name": "scope2", "description": "desc2", "values": []any{"v2"}}}, req["attributesScopes"])
	}, response))

	err := mgmt.ThirdPartyApplication().UpdateApplication(context.Background(), &descope.ThirdPartyApplicationRequest{
		ID:                   "id1",
		Name:                 "abc",
		Description:          "desc",
		Logo:                 "logo",
		LoginPageURL:         "http://dummy.com",
		ApprovedCallbackUrls: []string{"http://dummy.com/callback"},
		PermissionsScopes:    []*descope.ThirdPartyApplicationScope{{Name: "scope1", Description: "desc1", Values: []string{"v1"}}},
		AttributesScopes:     []*descope.ThirdPartyApplicationScope{{Name: "scope2", Description: "desc2", Values: []string{"v2"}}},
	})
	require.NoError(t, err)
}

func TestThirdPartyApplicationUpdateError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))

	// Empty application
	err := mgmt.ThirdPartyApplication().UpdateApplication(context.Background(), nil)
	require.Error(t, err)

	// Empty application ID
	err = mgmt.ThirdPartyApplication().UpdateApplication(context.Background(), &descope.ThirdPartyApplicationRequest{})
	require.Error(t, err)

	// Empty application Name
	err = mgmt.ThirdPartyApplication().UpdateApplication(context.Background(), &descope.ThirdPartyApplicationRequest{ID: "id1"})
	require.Error(t, err)
}

func TestThirdPartyApplicationPatchSuccess(t *testing.T) {
	response := map[string]any{"id": "qux"}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "id1", req["id"])
		require.Equal(t, "desc", req["description"])
		require.Equal(t, []any{"http://dummy.com/callback"}, req["approvedCallbackUrls"])
		require.Equal(t, []any{map[string]any{"name": "scope2", "description": "desc2", "values": []any{"v2"}}}, req["attributesScopes"])
	}, response))

	err := mgmt.ThirdPartyApplication().PatchApplication(context.Background(), &descope.ThirdPartyApplicationRequest{
		ID:                   "id1",
		Description:          "desc",
		ApprovedCallbackUrls: []string{"http://dummy.com/callback"},
		AttributesScopes:     []*descope.ThirdPartyApplicationScope{{Name: "scope2", Description: "desc2", Values: []string{"v2"}}},
	})
	require.NoError(t, err)
}

func TestThirdPartyApplicationPatchError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))

	// Empty application
	err := mgmt.ThirdPartyApplication().PatchApplication(context.Background(), nil)
	require.Error(t, err)

	// Empty application ID
	err = mgmt.ThirdPartyApplication().PatchApplication(context.Background(), &descope.ThirdPartyApplicationRequest{})
	require.Error(t, err)
}

func TestThirdPartyApplicationGetSecretSuccess(t *testing.T) {
	response := map[string]any{
		"cleartext": "11",
	}

	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
	}, response))
	res, err := mgmt.ThirdPartyApplication().GetApplicationSecret(context.Background(), "id1")
	require.NoError(t, err)
	require.Equal(t, "11", res)
}

func TestThirdPartyApplicationGetSecretErrorEmpty(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.ThirdPartyApplication().GetApplicationSecret(context.Background(), "")
	require.Error(t, err)
	require.Empty(t, res)
}

func TestThirdPartyApplicationGetSecretError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.ThirdPartyApplication().GetApplicationSecret(context.Background(), "test")
	require.Error(t, err)
	require.Empty(t, res)
}

func TestThirdPartyApplicationRotateSecretSuccess(t *testing.T) {
	response := map[string]any{
		"cleartext": "11",
	}

	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
	}, response))
	res, err := mgmt.ThirdPartyApplication().RotateApplicationSecret(context.Background(), "id1")
	require.NoError(t, err)
	require.Equal(t, "11", res)
}

func TestThirdPartyApplicationRotateSecretErrorEmpty(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.ThirdPartyApplication().RotateApplicationSecret(context.Background(), "")
	require.Error(t, err)
	require.Empty(t, res)
}

func TestThirdPartyApplicationRotateSecretError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.ThirdPartyApplication().RotateApplicationSecret(context.Background(), "test")
	require.Error(t, err)
	require.Empty(t, res)
}

func TestThirdPartyApplicationDeleteSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["id"])
	}))
	err := mgmt.ThirdPartyApplication().DeleteApplication(context.Background(), "abc")
	require.NoError(t, err)
}

func TestThirdPartyApplicationDeleteError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.ThirdPartyApplication().DeleteApplication(context.Background(), "")
	require.Error(t, err)
}

func TestThirdPartyApplicationLoadSuccess(t *testing.T) {
	response := map[string]any{
		"id":           "id1",
		"name":         "abc",
		"description":  "desc",
		"logo":         "logo",
		"loginPageUrl": "http://dummy.com",
		"permissionsScopes": []map[string]any{
			{"name": "scope1", "description": "desc1"},
		},
		"attributesScopes": []map[string]any{
			{"name": "scope2", "description": "desc2"},
		},
	}

	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
	}, response))
	res, err := mgmt.ThirdPartyApplication().LoadApplication(context.Background(), "id1")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "id1", res.ID)
	require.Equal(t, "abc", res.Name)
	require.Equal(t, "desc", res.Description)
	require.Equal(t, "logo", res.Logo)
	require.Equal(t, "http://dummy.com", res.LoginPageURL)
	require.Len(t, res.PermissionsScopes, 1)
	require.Equal(t, "scope1", res.PermissionsScopes[0].Name)
	require.Equal(t, "desc1", res.PermissionsScopes[0].Description)
	require.Len(t, res.AttributesScopes, 1)
	require.Equal(t, "scope2", res.AttributesScopes[0].Name)
	require.Equal(t, "desc2", res.AttributesScopes[0].Description)
}

func TestThirdPartyApplicationLoadError(t *testing.T) {
	// Empty ID
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.ThirdPartyApplication().LoadApplication(context.Background(), "")
	require.Error(t, err)
	require.Nil(t, res)

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err = mgmt.ThirdPartyApplication().LoadApplication(context.Background(), "t1")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestAllThirdPartyApplicationsLoadSuccess(t *testing.T) {
	response := map[string]any{
		"apps": []map[string]any{
			{
				"id":                   "id1",
				"name":                 "abc",
				"description":          "desc",
				"logo":                 "logo",
				"loginPageUrl":         "http://dummy.com",
				"approvedCallbackUrls": []any{"http://dummy.com/callback"},
				"permissionsScopes": []map[string]any{
					{"name": "scope1", "description": "desc1"},
				},
			},
			{
				"id":           "id2",
				"name":         "efg",
				"description":  "desc",
				"loginPageUrl": "http://dummy.com",
				"attributesScopes": []map[string]any{
					{"name": "scope1", "description": "desc1"},
				},
			},
		}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
	}, response))
	res, err := mgmt.ThirdPartyApplication().LoadAllApplications(context.Background())
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Len(t, res, 2)
	for i := range res {
		if i == 0 {
			require.Equal(t, "id1", res[i].ID)
			require.Equal(t, "abc", res[i].Name)
			require.Equal(t, "desc", res[i].Description)
			require.Equal(t, "logo", res[i].Logo)
			require.Equal(t, "http://dummy.com", res[i].LoginPageURL)
			require.Len(t, res[i].ApprovedCallbackUrls, 1)
			require.Equal(t, "http://dummy.com/callback", res[i].ApprovedCallbackUrls[0])
			require.Len(t, res[i].PermissionsScopes, 1)
			require.Equal(t, "scope1", res[i].PermissionsScopes[0].Name)
			require.Equal(t, "desc1", res[i].PermissionsScopes[0].Description)
			require.Len(t, res[i].AttributesScopes, 0)
		} else {
			require.Equal(t, "id2", res[i].ID)
			require.Equal(t, "efg", res[i].Name)
			require.Equal(t, "desc", res[i].Description)
			require.Empty(t, res[i].Logo)
			require.Equal(t, "http://dummy.com", res[i].LoginPageURL)
			require.Len(t, res[i].ApprovedCallbackUrls, 0)
			require.Len(t, res[i].PermissionsScopes, 0)
			require.Len(t, res[i].AttributesScopes, 1)
			require.Equal(t, "scope1", res[i].AttributesScopes[0].Name)
			require.Equal(t, "desc1", res[i].AttributesScopes[0].Description)
		}
	}
}

func TestAllThirdPartyApplicationsLoadError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.ThirdPartyApplication().LoadAllApplications(context.Background())
	require.Error(t, err)
	require.Nil(t, res)
}

func TestSearchThirdPartyApplicationConsents(t *testing.T) {
	response := map[string]any{
		"consents": []map[string]any{
			{
				"id":     "id1",
				"appId":  "app1",
				"userId": "user1",
				"scopes": []any{"scope1"},
			},
			{
				"id":     "id2",
				"appId":  "app2",
				"userId": "user2",
			},
		},
		"total": 2,
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
	}, response))
	res, total, err := mgmt.ThirdPartyApplication().SearchConsents(context.Background(), &descope.ThirdPartyApplicationConsentSearchOptions{
		AppID: "app1",
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Len(t, res, 2)
	require.Equal(t, 2, total)
	assert.EqualValues(t, "id1", res[0].ID)
	assert.EqualValues(t, "app1", res[0].AppID)
	assert.EqualValues(t, "user1", res[0].UserID)
	assert.Len(t, res[0].Scopes, 1)
	assert.EqualValues(t, "scope1", res[0].Scopes[0])
	assert.EqualValues(t, "id2", res[1].ID)
}

func TestSearchThirdPartyApplicationConsentsEmptyError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, total, err := mgmt.ThirdPartyApplication().SearchConsents(context.Background(), nil)
	require.Error(t, err)
	require.Nil(t, res)
	require.Zero(t, total)
}

func TestSearchThirdPartyApplicationConsentError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, total, err := mgmt.ThirdPartyApplication().SearchConsents(context.Background(), &descope.ThirdPartyApplicationConsentSearchOptions{
		AppID: "app1",
	})
	require.Error(t, err)
	require.Nil(t, res)
	require.Zero(t, total)
}

func TestDeleteThirdPartyApplicationConsents(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
	}))
	err := mgmt.ThirdPartyApplication().DeleteConsents(context.Background(), &descope.ThirdPartyApplicationConsentDeleteOptions{
		AppID: "app1",
	})
	require.NoError(t, err)
}

func TestDeleteThirdPartyApplicationConsentsEmptyError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.ThirdPartyApplication().DeleteConsents(context.Background(), nil)
	require.Error(t, err)
}

func TestDeleteThirdPartyApplicationConsentsError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	err := mgmt.ThirdPartyApplication().DeleteConsents(context.Background(), &descope.ThirdPartyApplicationConsentDeleteOptions{
		ConsentIDs: []string{"id1"},
	})
	require.Error(t, err)
}
