package mgmt

import (
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/tests/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetSSOSettingsSuccess(t *testing.T) {
	tenantID := "abc"
	response := map[string]any{
		"tenantID":       tenantID,
		"idpEntityID":    "idpEntityID",
		"idpSSOURL":      "idpSSOURL",
		"idpCertificate": "idpCertificate",
		"idpMetadataURL": "idpMetadataURL",
		"spEntityId":     "spEntityId",
		"spACSUrl":       "spACSUrl",
		"spCertificate":  "spCertificate",
		"userMapping": map[string]string{
			"name":        "name",
			"email":       "email",
			"username":    "username",
			"phoneNumber": "phoneNumber",
			"group":       "group",
		},
		"groupsMapping": []map[string]any{
			{
				"role": map[string]string{
					"id":   "role.id",
					"name": "role.name",
				},
				"groups": []string{"group1"},
			},
		},
		"redirectURL": "redirectURL",
		"domain":      "lulu",
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		params := helpers.ReadParams(r)
		require.Equal(t, tenantID, params["tenantId"])
	}, response))
	res, err := mgmt.SSO().GetSettings(tenantID)
	require.NoError(t, err)
	assert.EqualValues(t, tenantID, res.TenantID)
	assert.EqualValues(t, "idpEntityID", res.IdpEntityID)
	assert.EqualValues(t, "idpSSOURL", res.IdpSSOURL)
	assert.EqualValues(t, "idpCertificate", res.IdpCertificate)
	assert.EqualValues(t, "idpMetadataURL", res.IdpMetadataURL)
	assert.EqualValues(t, "spEntityId", res.SpEntityID)
	assert.EqualValues(t, "spACSUrl", res.SpACSUrl)
	assert.EqualValues(t, "spCertificate", res.SpCertificate)
	assert.EqualValues(t, "email", res.UserMapping.Email)
	assert.EqualValues(t, "group", res.UserMapping.Group)
	assert.EqualValues(t, "name", res.UserMapping.Name)
	assert.EqualValues(t, "phoneNumber", res.UserMapping.PhoneNumber)
	assert.EqualValues(t, "username", res.UserMapping.Username)
	require.Len(t, res.GroupsMapping, 1)
	assert.EqualValues(t, []string{"group1"}, res.GroupsMapping[0].Groups)
	assert.EqualValues(t, "role.id", res.GroupsMapping[0].Role.ID)
	assert.EqualValues(t, "role.name", res.GroupsMapping[0].Role.Name)
	assert.EqualValues(t, "redirectURL", res.RedirectURL)
	assert.EqualValues(t, "lulu", res.Domain)
}

func TestDeleteSSOSettingsSuccess(t *testing.T) {
	tenantID := "abc"

	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		params := helpers.ReadParams(r)
		require.Equal(t, tenantID, params["tenantId"])
	}, map[string]any{}))
	err := mgmt.SSO().DeleteSettings(tenantID)
	assert.NoError(t, err)
}

func TestDeleteSSOSettingsError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		called = true
	}, map[string]any{}))
	err := mgmt.SSO().DeleteSettings("")
	assert.Error(t, err)
	assert.False(t, called)
}

func TestGetSSOSettingsError(t *testing.T) {
	tenantID := "abc"
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		params := helpers.ReadParams(r)
		require.Equal(t, tenantID, params["tenantId"])
	}))
	res, err := mgmt.SSO().GetSettings(tenantID)
	require.Error(t, err)
	assert.Nil(t, res)
}

func TestGetSSOSettingsErrorMissingTenantID(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(func(r *http.Request) {}))
	res, err := mgmt.SSO().GetSettings("")
	require.ErrorIs(t, err, utils.NewInvalidArgumentError("tenantID"))
	assert.Nil(t, res)
}

func TestSSOConfigureSettingsSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["tenantId"])
		require.Equal(t, "http://idpURL", req["idpURL"])
		require.Equal(t, "mycert", req["idpCert"])
		require.Equal(t, "entity", req["entityId"])
		require.Equal(t, "https://redirect", req["redirectURL"])
		require.Equal(t, "domain.com", req["domain"])
	}))
	err := mgmt.SSO().ConfigureSettings("abc", "http://idpURL", "mycert", "entity", "https://redirect", "domain.com")
	require.NoError(t, err)
}

func TestSSOConfigureSettingsError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.SSO().ConfigureSettings("", "http://idpURL", "mycert", "entity", "", "")
	require.Error(t, err)
	err = mgmt.SSO().ConfigureSettings("abc", "", "mycert", "entity", "", "")
	require.Error(t, err)
	err = mgmt.SSO().ConfigureSettings("abc", "http://idpURL", "", "entity", "", "")
	require.Error(t, err)
	err = mgmt.SSO().ConfigureSettings("abc", "http://idpURL", "mycert", "", "", "")
	require.Error(t, err)
}

func TestSSOConfigureMetadataSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["tenantId"])
		require.Equal(t, "http://idpURL", req["idpMetadataURL"])
		require.Equal(t, "https://redirect", req["redirectURL"])
		require.Equal(t, "domain.com", req["domain"])
	}))
	err := mgmt.SSO().ConfigureMetadata("abc", "http://idpURL", "https://redirect", "domain.com")
	require.NoError(t, err)
}

func TestSSOConfigureMetadataError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.SSO().ConfigureMetadata("", "http://idpURL", "https://redirect", "domain.com")
	require.Error(t, err)
	err = mgmt.SSO().ConfigureMetadata("abc", "", "https://redirect", "domain.com")
	require.Error(t, err)
}

func TestSSOConfigureMappingSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["tenantId"])
		roleMappings := req["roleMappings"].([]any)
		require.Len(t, roleMappings, 2)
		for i := range roleMappings {
			mapping := roleMappings[i].(map[string]any)
			groups := mapping["groups"].([]any)
			require.Len(t, groups, 1)
			if i == 0 {
				require.Equal(t, "x", mapping["roleName"])
				require.Equal(t, "foo", groups[0])
			} else {
				require.Equal(t, "y", mapping["roleName"])
				require.Equal(t, "bar", groups[0])
			}
		}
		require.Equal(t, "INAME", req["attributeMapping"].(map[string]any)["name"])
	}))
	err := mgmt.SSO().ConfigureMapping("abc", []*descope.RoleMapping{{Groups: []string{"foo"}, Role: "x"}, {Groups: []string{"bar"}, Role: "y"}}, &descope.AttributeMapping{Name: "INAME"})
	require.NoError(t, err)
}

func TestSSOConfigureMappingError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.SSO().ConfigureMapping("", nil, nil)
	require.Error(t, err)
}
