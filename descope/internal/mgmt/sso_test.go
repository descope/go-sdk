package mgmt

import (
	"context"
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
		"domains":     []string{"lulu", "kuku"},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		params := helpers.ReadParams(r)
		require.Equal(t, tenantID, params["tenantId"])
	}, response))
	res, err := mgmt.SSO().GetSettings(context.Background(), tenantID)
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
	assert.EqualValues(t, []string{"lulu", "kuku"}, res.Domains)
	assert.EqualValues(t, "lulu", res.Domain)
}

func TestDeleteSSOSettingsSuccess(t *testing.T) {
	tenantID := "abc"

	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		params := helpers.ReadParams(r)
		require.Equal(t, tenantID, params["tenantId"])
	}, map[string]any{}))
	err := mgmt.SSO().DeleteSettings(context.Background(), tenantID)
	assert.NoError(t, err)
}

func TestDeleteSSOSettingsError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(_ *http.Request) {
		called = true
	}, map[string]any{}))
	err := mgmt.SSO().DeleteSettings(context.Background(), "")
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
	res, err := mgmt.SSO().GetSettings(context.Background(), tenantID)
	require.Error(t, err)
	assert.Nil(t, res)
}

func TestGetSSOSettingsErrorMissingTenantID(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(func(_ *http.Request) {}))
	res, err := mgmt.SSO().GetSettings(context.Background(), "")
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
		domains := req["domains"].([]any)
		require.Len(t, domains, 2)
		require.Equal(t, "domain.com", domains[0])
		require.Equal(t, "test.com", domains[1])
	}))
	err := mgmt.SSO().ConfigureSettings(context.Background(), "abc", "http://idpURL", "mycert", "entity", "https://redirect", []string{"domain.com", "test.com"})
	require.NoError(t, err)
}

func TestSSOConfigureSettingsError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.SSO().ConfigureSettings(context.Background(), "", "http://idpURL", "mycert", "entity", "", nil)
	require.Error(t, err)
	err = mgmt.SSO().ConfigureSettings(context.Background(), "abc", "", "mycert", "entity", "", nil)
	require.Error(t, err)
	err = mgmt.SSO().ConfigureSettings(context.Background(), "abc", "http://idpURL", "", "entity", "", nil)
	require.Error(t, err)
	err = mgmt.SSO().ConfigureSettings(context.Background(), "abc", "http://idpURL", "mycert", "", "", nil)
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
		domains := req["domains"].([]any)
		require.Len(t, domains, 2)
		require.Equal(t, "domain.com", domains[0])
		require.Equal(t, "test.com", domains[1])
	}))
	err := mgmt.SSO().ConfigureMetadata(context.Background(), "abc", "http://idpURL", "https://redirect", []string{"domain.com", "test.com"})
	require.NoError(t, err)
}

func TestSSOConfigureMetadataError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.SSO().ConfigureMetadata(context.Background(), "", "http://idpURL", "https://redirect", []string{"domain.com"})
	require.Error(t, err)
	err = mgmt.SSO().ConfigureMetadata(context.Background(), "abc", "", "https://redirect", []string{"domain.com"})
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
	err := mgmt.SSO().ConfigureMapping(context.Background(), "abc", []*descope.RoleMapping{{Groups: []string{"foo"}, Role: "x"}, {Groups: []string{"bar"}, Role: "y"}}, &descope.AttributeMapping{Name: "INAME"})
	require.NoError(t, err)
}

func TestSSOConfigureMappingError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.SSO().ConfigureMapping(context.Background(), "", nil, nil)
	require.Error(t, err)
}

func TestLoadSettingsSuccess(t *testing.T) {
	tenantID := "abc"
	response := map[string]any{
		"tenant": map[string]any{
			"id":       tenantID,
			"name":     "T1",
			"authType": "saml",
			"domains":  []string{"lulu"},
		},
		"saml": map[string]any{
			"tenantID":       tenantID,
			"idpEntityID":    "idpEntityID",
			"idpSSOURL":      "idpSSOURL",
			"idpCertificate": "idpCertificate",
			"idpMetadataURL": "idpMetadataURL",
			"spEntityId":     "spEntityId",
			"spACSUrl":       "spACSUrl",
			"spCertificate":  "spCertificate",
			"attributeMapping": map[string]string{
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
		},
		"oidc": map[string]any{
			"name":        "myName",
			"clientId":    "abcdef",
			"authUrl":     "http://dummy.com",
			"tokenUrl":    "http://dummy.com",
			"userDataUrl": "http://dummy.com",
			"userAttrMapping": map[string]any{
				"givenName": "myGivenName",
			},
		},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		params := helpers.ReadParams(r)
		require.Equal(t, tenantID, params["tenantId"])
	}, response))
	res, err := mgmt.SSO().LoadSettings(context.Background(), tenantID)
	require.NoError(t, err)
	require.NotNil(t, res.Tenant)
	assert.EqualValues(t, tenantID, res.Tenant.ID)
	assert.EqualValues(t, []string{"lulu"}, res.Tenant.Domains)

	require.NotNil(t, res.Saml)
	assert.EqualValues(t, "idpEntityID", res.Saml.IdpEntityID)
	assert.EqualValues(t, "idpSSOURL", res.Saml.IdpSSOURL)
	assert.EqualValues(t, "idpCertificate", res.Saml.IdpCertificate)
	assert.EqualValues(t, "idpMetadataURL", res.Saml.IdpMetadataURL)
	assert.EqualValues(t, "spEntityId", res.Saml.SpEntityID)
	assert.EqualValues(t, "spACSUrl", res.Saml.SpACSUrl)
	assert.EqualValues(t, "spCertificate", res.Saml.SpCertificate)
	assert.EqualValues(t, "email", res.Saml.AttributeMapping.Email)
	assert.EqualValues(t, "group", res.Saml.AttributeMapping.Group)
	assert.EqualValues(t, "name", res.Saml.AttributeMapping.Name)
	assert.EqualValues(t, "phoneNumber", res.Saml.AttributeMapping.PhoneNumber)
	require.Len(t, res.Saml.GroupsMapping, 1)
	assert.EqualValues(t, []string{"group1"}, res.Saml.GroupsMapping[0].Groups)
	assert.EqualValues(t, "role.id", res.Saml.GroupsMapping[0].Role.ID)
	assert.EqualValues(t, "role.name", res.Saml.GroupsMapping[0].Role.Name)
	assert.EqualValues(t, "redirectURL", res.Saml.RedirectURL)

	require.NotNil(t, res.Oidc)
	assert.EqualValues(t, "myName", res.Oidc.Name)
	assert.EqualValues(t, "abcdef", res.Oidc.ClientID)
	assert.EqualValues(t, "http://dummy.com", res.Oidc.AuthURL)
	assert.EqualValues(t, "http://dummy.com", res.Oidc.TokenURL)
	assert.EqualValues(t, "http://dummy.com", res.Oidc.UserDataURL)
	require.NotNil(t, res.Oidc.AttributeMapping)
	assert.EqualValues(t, "myGivenName", res.Oidc.AttributeMapping.GivenName)
}

func TestLoadSettingsError(t *testing.T) {
	tenantID := "abc"
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		params := helpers.ReadParams(r)
		require.Equal(t, tenantID, params["tenantId"])
	}))
	res, err := mgmt.SSO().LoadSettings(context.Background(), tenantID)
	require.Error(t, err)
	assert.Nil(t, res)
}

func TestLoadSettingsErrorMissingTenantID(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(func(_ *http.Request) {}))
	res, err := mgmt.SSO().LoadSettings(context.Background(), "")
	require.ErrorIs(t, err, utils.NewInvalidArgumentError("tenantID"))
	assert.Nil(t, res)
}

func TestSSOConfigureSAMLSettingsSuccess(t *testing.T) {
	settings := &descope.SSOSAMLSettings{
		IdpURL:      "http://idpURL",
		IdpEntityID: "entity",
		IdpCert:     "mycert",
		AttributeMapping: &descope.AttributeMapping{
			GivenName: "myGivenName",
			CustomAttributes: map[string]string{
				"attr1": "val1",
			},
		},
		RoleMappings: []*descope.RoleMapping{
			{
				Groups: []string{"grp1", "grp2"},
				Role:   "role1",
			},
		},
	}
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["tenantId"])
		require.Equal(t, "https://redirect", req["redirectUrl"])

		domains := req["domains"].([]any)
		require.Len(t, domains, 1)
		require.Equal(t, "domain.com", domains[0])

		settings, found := req["settings"]
		require.True(t, found)
		sett, ok := settings.(map[string]any)
		require.True(t, ok)
		require.Equal(t, "http://idpURL", sett["idpUrl"])
		require.Equal(t, "mycert", sett["idpCert"])
		require.Equal(t, "entity", sett["entityId"])

		userAttrMappingMap, found := sett["attributeMapping"]
		require.True(t, found)
		userAttrMapping, ok := userAttrMappingMap.(map[string]any)
		require.True(t, ok)
		require.Equal(t, "myGivenName", userAttrMapping["givenName"])

		roleMappingMap, found := sett["roleMappings"]
		require.True(t, found)
		roleMappingInt, ok := roleMappingMap.([]interface{})
		require.True(t, ok)
		require.Len(t, roleMappingInt, 1)
		mappingMap, ok := roleMappingInt[0].(map[string]any)
		require.True(t, ok)
		require.Equal(t, []any{"grp1", "grp2"}, mappingMap["groups"])
		require.Equal(t, "role1", mappingMap["roleName"])
	}))
	err := mgmt.SSO().ConfigureSAMLSettings(context.Background(), "abc", settings, "https://redirect", []string{"domain.com"})
	require.NoError(t, err)
}

func TestSSOConfigureSAMLSettingsError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.SSO().ConfigureSAMLSettings(context.Background(), "", nil, "", []string{})
	require.Error(t, err)
	err = mgmt.SSO().ConfigureSAMLSettings(context.Background(), "abc", nil, "", []string{})
	require.Error(t, err)

	settings := &descope.SSOSAMLSettings{}
	err = mgmt.SSO().ConfigureSAMLSettings(context.Background(), "abc", settings, "", []string{})
	require.Error(t, err)

	settings.IdpURL = "http://idpURL"
	err = mgmt.SSO().ConfigureSAMLSettings(context.Background(), "abc", settings, "", []string{})
	require.Error(t, err)

	settings.IdpCert = "mycert"
	err = mgmt.SSO().ConfigureSAMLSettings(context.Background(), "abc", settings, "", []string{})
	require.Error(t, err)
}

func TestSSOConfigureSAMLSettingsByMetadataSuccess(t *testing.T) {
	settings := &descope.SSOSAMLSettingsByMetadata{
		IdpMetadataURL: "http://idpURL",
		AttributeMapping: &descope.AttributeMapping{
			GivenName: "myGivenName",
			CustomAttributes: map[string]string{
				"attr1": "val1",
			},
		},
		RoleMappings: []*descope.RoleMapping{
			{
				Groups: []string{"grp1", "grp2"},
				Role:   "role1",
			},
		},
	}
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["tenantId"])
		require.Equal(t, "https://redirect", req["redirectUrl"])

		domains := req["domains"].([]any)
		require.Len(t, domains, 1)
		require.Equal(t, "domain.com", domains[0])

		settings, found := req["settings"]
		require.True(t, found)
		sett, ok := settings.(map[string]any)
		require.True(t, ok)
		require.Equal(t, "http://idpURL", sett["idpMetadataUrl"])

		userAttrMappingMap, found := sett["attributeMapping"]
		require.True(t, found)
		userAttrMapping, ok := userAttrMappingMap.(map[string]any)
		require.True(t, ok)
		require.Equal(t, "myGivenName", userAttrMapping["givenName"])

		roleMappingMap, found := sett["roleMappings"]
		require.True(t, found)
		roleMappingInt, ok := roleMappingMap.([]interface{})
		require.True(t, ok)
		require.Len(t, roleMappingInt, 1)
		mappingMap, ok := roleMappingInt[0].(map[string]any)
		require.True(t, ok)
		require.Equal(t, []any{"grp1", "grp2"}, mappingMap["groups"])
		require.Equal(t, "role1", mappingMap["roleName"])
	}))
	err := mgmt.SSO().ConfigureSAMLSettingsByMetadata(context.Background(), "abc", settings, "https://redirect", []string{"domain.com"})
	require.NoError(t, err)
}

func TestSSOConfigureSAMLSettingsByMetadataError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.SSO().ConfigureSAMLSettingsByMetadata(context.Background(), "", nil, "https://redirect", []string{"domain.com"})
	require.Error(t, err)

	err = mgmt.SSO().ConfigureSAMLSettingsByMetadata(context.Background(), "abc", nil, "https://redirect", []string{"domain.com"})
	require.Error(t, err)

	settings := &descope.SSOSAMLSettingsByMetadata{}
	err = mgmt.SSO().ConfigureSAMLSettingsByMetadata(context.Background(), "abc", settings, "https://redirect", []string{"domain.com"})
	require.Error(t, err)
}

func TestSSOConfigureOIDCSettingsSuccess(t *testing.T) {
	oidcSettings := &descope.SSOOIDCSettings{
		Name:        "name",
		ClientID:    "clientId",
		AuthURL:     "http://dummy.com",
		TokenURL:    "http://dummy.com",
		UserDataURL: "http://dummy.com",
		RedirectURL: "https://redirect",
		AttributeMapping: &descope.OIDCAttributeMapping{
			GivenName: "myGivenName",
		},
	}
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["tenantId"])

		domains := req["domains"].([]any)
		require.Len(t, domains, 1)
		require.Equal(t, "domain.com", domains[0])

		settings, found := req["settings"]
		require.True(t, found)
		sett, ok := settings.(map[string]any)
		require.True(t, ok)
		require.Equal(t, "name", sett["name"])
		require.Equal(t, "clientId", sett["clientId"])
		require.Equal(t, "http://dummy.com", sett["authUrl"])
		require.Equal(t, "http://dummy.com", sett["tokenUrl"])
		require.Equal(t, "http://dummy.com", sett["userDataUrl"])
		require.Equal(t, "https://redirect", sett["redirectUrl"])

		userAttrMappingInt, found := sett["userAttrMapping"]
		require.True(t, found)
		userAttrMapping, _ := userAttrMappingInt.(map[string]any)
		require.Equal(t, "myGivenName", userAttrMapping["givenName"])
	}))
	err := mgmt.SSO().ConfigureOIDCSettings(context.Background(), "abc", oidcSettings, []string{"domain.com"})
	require.NoError(t, err)
}

func TestSSOConfigureOIDCSettingsError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.SSO().ConfigureOIDCSettings(context.Background(), "", nil, []string{})
	require.Error(t, err)
	err = mgmt.SSO().ConfigureOIDCSettings(context.Background(), "abc", nil, []string{})
	require.Error(t, err)
}
