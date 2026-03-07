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
		require.Empty(t, params["ssoId"])
	}, map[string]any{}))
	err := mgmt.SSO().DeleteSettings(context.Background(), tenantID, "")
	assert.NoError(t, err)
}

func TestDeleteSSOSettingsWithSSOIDSuccess(t *testing.T) {
	tenantID := "abc"
	ssoID := "somessoid"

	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		params := helpers.ReadParams(r)
		require.Equal(t, tenantID, params["tenantId"])
		require.Equal(t, ssoID, params["ssoId"])
	}, map[string]any{}))
	err := mgmt.SSO().DeleteSettings(context.Background(), tenantID, ssoID)
	assert.NoError(t, err)
}

func TestDeleteSSOSettingsError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(_ *http.Request) {
		called = true
	}, map[string]any{}))
	err := mgmt.SSO().DeleteSettings(context.Background(), "", "")
	assert.Error(t, err)
	assert.False(t, called)
}

func TestNewSSOSettingsSuccess(t *testing.T) {
	tenantID := "abc"
	ssoID := "somessoid"
	displayName := "somessodisplayname"
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
			"redirectURL":     "redirectURL",
			"defaultSSORoles": []string{"defrole1", "defrole2"},
			"groupsPriority":  []string{"group1"},
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
		"ssoId": ssoID,
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, tenantID, req["tenantId"])
		require.Equal(t, ssoID, req["ssoId"])
		require.Equal(t, displayName, req["displayName"])
	}, response))
	res, err := mgmt.SSO().NewSettings(context.Background(), tenantID, ssoID, displayName)
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
	assert.EqualValues(t, []string{"defrole1", "defrole2"}, res.Saml.DefaultSSORoles)
	assert.EqualValues(t, []string{"group1"}, res.Saml.GroupsPriority)

	require.NotNil(t, res.Oidc)
	assert.EqualValues(t, "myName", res.Oidc.Name)
	assert.EqualValues(t, "abcdef", res.Oidc.ClientID)
	assert.EqualValues(t, "http://dummy.com", res.Oidc.AuthURL)
	assert.EqualValues(t, "http://dummy.com", res.Oidc.TokenURL)
	assert.EqualValues(t, "http://dummy.com", res.Oidc.UserDataURL)
	require.NotNil(t, res.Oidc.AttributeMapping)
	assert.EqualValues(t, "myGivenName", res.Oidc.AttributeMapping.GivenName)

	require.Equal(t, ssoID, res.SSOID)
}

func TestNewSSOSettingsError(t *testing.T) {
	tenantID := "abc"
	ssoID := "somessoid"
	displayName := "somessodisplayname"
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, tenantID, req["tenantId"])
		require.Equal(t, ssoID, req["ssoId"])
		require.Equal(t, displayName, req["displayName"])
	}))
	res, err := mgmt.SSO().NewSettings(context.Background(), tenantID, ssoID, displayName)
	require.Error(t, err)
	assert.Nil(t, res)
}

func TestNewSettingsErrorMissingTenantID(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(func(_ *http.Request) {}))
	res, err := mgmt.SSO().NewSettings(context.Background(), "", "", "")
	require.ErrorIs(t, err, utils.NewInvalidArgumentError("tenantID"))
	assert.Nil(t, res)
}

func TestNewSettingsErrorMissingDisplayName(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(func(_ *http.Request) {}))
	res, err := mgmt.SSO().NewSettings(context.Background(), "aaa", "", "")
	require.ErrorIs(t, err, utils.NewInvalidArgumentError("displayName"))
	assert.Nil(t, res)
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

func TestConfigureSSORedirectURLSuccess(t *testing.T) {
	url1 := "http://idpURL1"
	url2 := "http://idpURL2"
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["tenantId"])
		require.Equal(t, "ssoid", req["ssoId"])
		require.Equal(t, url1, req["samlRedirectUrl"])
		require.Equal(t, url2, req["oauthRedirectUrl"])
	}))
	err := mgmt.SSO().ConfigureSSORedirectURL(context.Background(), "abc", &url1, &url2, "ssoid")
	require.NoError(t, err)
}

func TestConfigureSSORedirectURLError(t *testing.T) {
	called := false
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(func(_ *http.Request) {
		called = true
	}))
	url := "http://idpURL"

	err := mgmt.SSO().ConfigureSSORedirectURL(context.Background(), "", &url, nil, "")
	require.Error(t, err)
	err = mgmt.SSO().ConfigureSSORedirectURL(context.Background(), "abc", nil, nil, "")
	require.Error(t, err)
	assert.False(t, called)
	err = mgmt.SSO().ConfigureSSORedirectURL(context.Background(), "abc", &url, nil, "")
	require.Error(t, err)
	assert.True(t, called)
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
			"redirectURL":     "redirectURL",
			"defaultSSORoles": []string{"defrole1", "defrole2"},
			"groupsPriority":  []string{"group1"},
			"fgaMappings": map[string]any{
				"group1": map[string]any{
					"relations": []map[string]any{
						{
							"resource":           "res1",
							"relationDefinition": "rd1",
							"namespace":          "ns1",
						},
						{
							"resource":           "res2",
							"relationDefinition": "rd2",
							"namespace":          "ns2",
						},
					},
				},
				"group2": map[string]any{
					"relations": []map[string]any{
						{
							"resource":           "res3",
							"relationDefinition": "rd3",
							"namespace":          "ns3",
						},
					},
				},
			},
			"configFGATenantIDResourcePrefix": "tenant_prefix_",
			"configFGATenantIDResourceSuffix": "_tenant_suffix",
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
		require.Empty(t, params["ssoId"])
	}, response))
	res, err := mgmt.SSO().LoadSettings(context.Background(), tenantID, "")
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
	assert.EqualValues(t, []string{"defrole1", "defrole2"}, res.Saml.DefaultSSORoles)
	assert.EqualValues(t, []string{"group1"}, res.Saml.GroupsPriority)
	assert.EqualValues(t, 2, len(res.Saml.FgaMappings))
	assert.EqualValues(t, 2, len(res.Saml.FgaMappings["group1"].Relations))
	assert.EqualValues(t, 1, len(res.Saml.FgaMappings["group2"].Relations))
	assert.EqualValues(t, "res1", res.Saml.FgaMappings["group1"].Relations[0].Resource)
	assert.EqualValues(t, "rd1", res.Saml.FgaMappings["group1"].Relations[0].RelationDefinition)
	assert.EqualValues(t, "ns1", res.Saml.FgaMappings["group1"].Relations[0].Namespace)
	assert.EqualValues(t, "res2", res.Saml.FgaMappings["group1"].Relations[1].Resource)
	assert.EqualValues(t, "rd2", res.Saml.FgaMappings["group1"].Relations[1].RelationDefinition)
	assert.EqualValues(t, "ns2", res.Saml.FgaMappings["group1"].Relations[1].Namespace)
	assert.EqualValues(t, "res3", res.Saml.FgaMappings["group2"].Relations[0].Resource)
	assert.EqualValues(t, "rd3", res.Saml.FgaMappings["group2"].Relations[0].RelationDefinition)
	assert.EqualValues(t, "ns3", res.Saml.FgaMappings["group2"].Relations[0].Namespace)
	assert.EqualValues(t, "tenant_prefix_", res.Saml.ConfigFGATenantIDResourcePrefix)
	assert.EqualValues(t, "_tenant_suffix", res.Saml.ConfigFGATenantIDResourceSuffix)

	require.NotNil(t, res.Oidc)
	assert.EqualValues(t, "myName", res.Oidc.Name)
	assert.EqualValues(t, "abcdef", res.Oidc.ClientID)
	assert.EqualValues(t, "http://dummy.com", res.Oidc.AuthURL)
	assert.EqualValues(t, "http://dummy.com", res.Oidc.TokenURL)
	assert.EqualValues(t, "http://dummy.com", res.Oidc.UserDataURL)
	require.NotNil(t, res.Oidc.AttributeMapping)
	assert.EqualValues(t, "myGivenName", res.Oidc.AttributeMapping.GivenName)
	require.Empty(t, res.SSOID)
}

func TestLoadSettingsWithSSOIDSuccess(t *testing.T) {
	tenantID := "abc"
	ssoID := "somessoid"
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
		"ssoId": ssoID,
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		params := helpers.ReadParams(r)
		require.Equal(t, tenantID, params["tenantId"])
		require.Equal(t, ssoID, params["ssoId"])
	}, response))
	res, err := mgmt.SSO().LoadSettings(context.Background(), tenantID, ssoID)
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
	assert.Nil(t, res.Saml.FgaMappings)

	require.NotNil(t, res.Oidc)
	assert.EqualValues(t, "myName", res.Oidc.Name)
	assert.EqualValues(t, "abcdef", res.Oidc.ClientID)
	assert.EqualValues(t, "http://dummy.com", res.Oidc.AuthURL)
	assert.EqualValues(t, "http://dummy.com", res.Oidc.TokenURL)
	assert.EqualValues(t, "http://dummy.com", res.Oidc.UserDataURL)
	require.NotNil(t, res.Oidc.AttributeMapping)
	assert.EqualValues(t, "myGivenName", res.Oidc.AttributeMapping.GivenName)

	require.Equal(t, ssoID, res.SSOID)
}

func TestLoadSettingsError(t *testing.T) {
	tenantID := "abc"
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		params := helpers.ReadParams(r)
		require.Equal(t, tenantID, params["tenantId"])
	}))
	res, err := mgmt.SSO().LoadSettings(context.Background(), tenantID, "")
	require.Error(t, err)
	assert.Nil(t, res)
}

func TestLoadAllSettingsSuccess(t *testing.T) {
	tenantID := "abc"
	ssoID := "somessoid"
	response := map[string]any{
		"SSOSettings": []map[string]any{{
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
				"fgaMappings": map[string]any{
					"group1": map[string]any{
						"relations": []map[string]any{
							{
								"resource":           "res1",
								"relationDefinition": "rd1",
								"namespace":          "ns1",
							},
						},
					},
				},
				"configFGATenantIDResourcePrefix": "prefix_value_",
				"configFGATenantIDResourceSuffix": "_suffix_value",
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
			"ssoId": ssoID,
		}},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		params := helpers.ReadParams(r)
		require.Equal(t, tenantID, params["tenantId"])
	}, response))
	resAll, err := mgmt.SSO().LoadAllSettings(context.Background(), tenantID)
	require.NoError(t, err)
	require.Len(t, resAll, 1)
	res := resAll[0]
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
	assert.EqualValues(t, 1, len(res.Saml.FgaMappings))
	assert.EqualValues(t, 1, len(res.Saml.FgaMappings["group1"].Relations))
	assert.EqualValues(t, "res1", res.Saml.FgaMappings["group1"].Relations[0].Resource)
	assert.EqualValues(t, "rd1", res.Saml.FgaMappings["group1"].Relations[0].RelationDefinition)
	assert.EqualValues(t, "ns1", res.Saml.FgaMappings["group1"].Relations[0].Namespace)
	assert.EqualValues(t, "prefix_value_", res.Saml.ConfigFGATenantIDResourcePrefix)
	assert.EqualValues(t, "_suffix_value", res.Saml.ConfigFGATenantIDResourceSuffix)

	require.NotNil(t, res.Oidc)
	assert.EqualValues(t, "myName", res.Oidc.Name)
	assert.EqualValues(t, "abcdef", res.Oidc.ClientID)
	assert.EqualValues(t, "http://dummy.com", res.Oidc.AuthURL)
	assert.EqualValues(t, "http://dummy.com", res.Oidc.TokenURL)
	assert.EqualValues(t, "http://dummy.com", res.Oidc.UserDataURL)
	require.NotNil(t, res.Oidc.AttributeMapping)
	assert.EqualValues(t, "myGivenName", res.Oidc.AttributeMapping.GivenName)
	require.Equal(t, ssoID, res.SSOID)
}

func TestLoadAllSettingsError(t *testing.T) {
	tenantID := "abc"
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		params := helpers.ReadParams(r)
		require.Equal(t, tenantID, params["tenantId"])
	}))
	resAll, err := mgmt.SSO().LoadAllSettings(context.Background(), tenantID)
	require.Error(t, err)
	require.Nil(t, resAll)
}

func TestLoadAllSettingsErrorMissingTenantID(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(func(_ *http.Request) {}))
	res, err := mgmt.SSO().LoadAllSettings(context.Background(), "")
	require.ErrorIs(t, err, utils.NewInvalidArgumentError("tenantID"))
	assert.Nil(t, res)
}

func TestLoadSettingsErrorMissingTenantID(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(func(_ *http.Request) {}))
	res, err := mgmt.SSO().LoadSettings(context.Background(), "", "")
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
		SpACSUrl:        "https://spacsurl.com",
		SpEntityID:      "spentityid",
		DefaultSSORoles: []string{"defrole1", "defrole2"},
		GroupsPriority:  []string{"group1"},
		FgaMappings: map[string]*descope.FGAGroupMapping{
			"group1": {
				Relations: []*descope.FGAGroupMappingRelation{
					{
						Resource:           "res1",
						RelationDefinition: "rd1",
						Namespace:          "ns1",
					},
					{
						Resource:           "res2",
						RelationDefinition: "rd2",
						Namespace:          "ns2",
					},
				},
			},
			"group2": {
				Relations: []*descope.FGAGroupMappingRelation{
					{
						Resource:           "res3",
						RelationDefinition: "rd3",
						Namespace:          "ns3",
					},
				},
			},
		},
	}
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["tenantId"])
		require.Empty(t, req["ssoId"])
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
		require.Equal(t, []any{"defrole1", "defrole2"}, sett["defaultSSORoles"])
		require.Equal(t, []any{"group1"}, sett["groupsPriority"])

		require.Equal(t, "https://spacsurl.com", sett["spACSUrl"])
		require.Equal(t, "spentityid", sett["spEntityId"])

		userAttrMappingMap, found := sett["attributeMapping"]
		require.True(t, found)
		userAttrMapping, ok := userAttrMappingMap.(map[string]any)
		require.True(t, ok)
		require.Equal(t, "myGivenName", userAttrMapping["givenName"])

		roleMappingMap, found := sett["roleMappings"]
		require.True(t, found)
		roleMappingInt, ok := roleMappingMap.([]any)
		require.True(t, ok)
		require.Len(t, roleMappingInt, 1)
		mappingMap, ok := roleMappingInt[0].(map[string]any)
		require.True(t, ok)
		require.Equal(t, []any{"grp1", "grp2"}, mappingMap["groups"])
		require.Equal(t, "role1", mappingMap["roleName"])

		fgaMappings, found := sett["fgaMappings"]
		require.True(t, found)
		fgaMappingsMap, ok := fgaMappings.(map[string]any)
		require.True(t, ok)
		require.Equal(t, 2, len(fgaMappingsMap))
		// Assert group1 mappings
		group1Map, ok := fgaMappingsMap["group1"].(map[string]any)
		require.True(t, ok)
		group1Relations, ok := group1Map["relations"].([]any)
		require.True(t, ok)
		require.Len(t, group1Relations, 2)
		relation1 := group1Relations[0].(map[string]any)
		require.Equal(t, "res1", relation1["resource"])
		require.Equal(t, "rd1", relation1["relationDefinition"])
		require.Equal(t, "ns1", relation1["namespace"])
		relation2 := group1Relations[1].(map[string]any)
		require.Equal(t, "res2", relation2["resource"])
		require.Equal(t, "rd2", relation2["relationDefinition"])
		require.Equal(t, "ns2", relation2["namespace"])
		// Assert group2 mappings
		group2Map, ok := fgaMappingsMap["group2"].(map[string]any)
		require.True(t, ok)
		group2Relations, ok := group2Map["relations"].([]any)
		require.True(t, ok)
		require.Len(t, group2Relations, 1)
		relation3 := group2Relations[0].(map[string]any)
		require.Equal(t, "res3", relation3["resource"])
		require.Equal(t, "rd3", relation3["relationDefinition"])
		require.Equal(t, "ns3", relation3["namespace"])
	}))
	err := mgmt.SSO().ConfigureSAMLSettings(context.Background(), "abc", settings, "https://redirect", []string{"domain.com"}, "")
	require.NoError(t, err)
}

func TestSSOConfigureSAMLSettingsWithSSOIDSuccess(t *testing.T) {
	ssoID := "somessoid"
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
		SpACSUrl:   "https://spacsurl.com",
		SpEntityID: "spentityid",
	}
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["tenantId"])
		require.Equal(t, ssoID, req["ssoId"])
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

		require.Equal(t, "https://spacsurl.com", sett["spACSUrl"])
		require.Equal(t, "spentityid", sett["spEntityId"])

		userAttrMappingMap, found := sett["attributeMapping"]
		require.True(t, found)
		userAttrMapping, ok := userAttrMappingMap.(map[string]any)
		require.True(t, ok)
		require.Equal(t, "myGivenName", userAttrMapping["givenName"])

		roleMappingMap, found := sett["roleMappings"]
		require.True(t, found)
		roleMappingInt, ok := roleMappingMap.([]any)
		require.True(t, ok)
		require.Len(t, roleMappingInt, 1)
		mappingMap, ok := roleMappingInt[0].(map[string]any)
		require.True(t, ok)
		require.Equal(t, []any{"grp1", "grp2"}, mappingMap["groups"])
		require.Equal(t, "role1", mappingMap["roleName"])

		_, found = sett["fgaMappings"]
		require.False(t, found)
	}))
	err := mgmt.SSO().ConfigureSAMLSettings(context.Background(), "abc", settings, "https://redirect", []string{"domain.com"}, ssoID)
	require.NoError(t, err)
}

func TestSSOConfigureSAMLSettingsError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.SSO().ConfigureSAMLSettings(context.Background(), "", nil, "", []string{}, "")
	require.Error(t, err)
	err = mgmt.SSO().ConfigureSAMLSettings(context.Background(), "abc", nil, "", []string{}, "")
	require.Error(t, err)

	settings := &descope.SSOSAMLSettings{}
	err = mgmt.SSO().ConfigureSAMLSettings(context.Background(), "abc", settings, "", []string{}, "")
	require.Error(t, err)

	settings.IdpURL = "http://idpURL"
	err = mgmt.SSO().ConfigureSAMLSettings(context.Background(), "abc", settings, "", []string{}, "")
	require.Error(t, err)

	settings.IdpCert = "mycert"
	err = mgmt.SSO().ConfigureSAMLSettings(context.Background(), "abc", settings, "", []string{}, "")
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
		SpACSUrl:        "https://spacsurl.com",
		SpEntityID:      "spentityid",
		DefaultSSORoles: []string{"defrole1", "defrole2"},
		GroupsPriority:  []string{"group1"},
		FgaMappings: map[string]*descope.FGAGroupMapping{
			"group1": {
				Relations: []*descope.FGAGroupMappingRelation{
					{
						Resource:           "res1",
						RelationDefinition: "rd1",
						Namespace:          "ns1",
					},
				},
			},
		},
	}
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["tenantId"])
		require.Empty(t, req["ssoId"])
		require.Equal(t, "https://redirect", req["redirectUrl"])

		domains := req["domains"].([]any)
		require.Len(t, domains, 1)
		require.Equal(t, "domain.com", domains[0])

		settings, found := req["settings"]
		require.True(t, found)
		sett, ok := settings.(map[string]any)
		require.True(t, ok)
		require.Equal(t, "http://idpURL", sett["idpMetadataUrl"])

		require.Equal(t, "https://spacsurl.com", sett["spACSUrl"])
		require.Equal(t, "spentityid", sett["spEntityId"])
		require.Equal(t, []any{"defrole1", "defrole2"}, sett["defaultSSORoles"])
		require.Equal(t, []any{"group1"}, sett["groupsPriority"])

		userAttrMappingMap, found := sett["attributeMapping"]
		require.True(t, found)
		userAttrMapping, ok := userAttrMappingMap.(map[string]any)
		require.True(t, ok)
		require.Equal(t, "myGivenName", userAttrMapping["givenName"])

		roleMappingMap, found := sett["roleMappings"]
		require.True(t, found)
		roleMappingInt, ok := roleMappingMap.([]any)
		require.True(t, ok)
		require.Len(t, roleMappingInt, 1)
		mappingMap, ok := roleMappingInt[0].(map[string]any)
		require.True(t, ok)
		require.Equal(t, []any{"grp1", "grp2"}, mappingMap["groups"])
		require.Equal(t, "role1", mappingMap["roleName"])

		fgaMappings, found := sett["fgaMappings"]
		require.True(t, found)
		fgaMappingsMap, ok := fgaMappings.(map[string]any)
		require.True(t, ok)
		require.Equal(t, 1, len(fgaMappingsMap))
		group1Map, ok := fgaMappingsMap["group1"].(map[string]any)
		require.True(t, ok)
		group1Relations, ok := group1Map["relations"].([]any)
		require.True(t, ok)
		require.Len(t, group1Relations, 1)
		relation1 := group1Relations[0].(map[string]any)
		require.Equal(t, "res1", relation1["resource"])
		require.Equal(t, "rd1", relation1["relationDefinition"])
		require.Equal(t, "ns1", relation1["namespace"])
	}))
	err := mgmt.SSO().ConfigureSAMLSettingsByMetadata(context.Background(), "abc", settings, "https://redirect", []string{"domain.com"}, "")
	require.NoError(t, err)
}

func TestSSOConfigureSAMLSettingsByMetadataWithSSOIDSuccess(t *testing.T) {
	ssoID := "somessoid"
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
		SpACSUrl:   "https://spacsurl.com",
		SpEntityID: "spentityid",
	}
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["tenantId"])
		require.Equal(t, ssoID, req["ssoId"])
		require.Equal(t, "https://redirect", req["redirectUrl"])

		domains := req["domains"].([]any)
		require.Len(t, domains, 1)
		require.Equal(t, "domain.com", domains[0])

		settings, found := req["settings"]
		require.True(t, found)
		sett, ok := settings.(map[string]any)
		require.True(t, ok)
		require.Equal(t, "http://idpURL", sett["idpMetadataUrl"])

		require.Equal(t, "https://spacsurl.com", sett["spACSUrl"])
		require.Equal(t, "spentityid", sett["spEntityId"])

		userAttrMappingMap, found := sett["attributeMapping"]
		require.True(t, found)
		userAttrMapping, ok := userAttrMappingMap.(map[string]any)
		require.True(t, ok)
		require.Equal(t, "myGivenName", userAttrMapping["givenName"])

		roleMappingMap, found := sett["roleMappings"]
		require.True(t, found)
		roleMappingInt, ok := roleMappingMap.([]any)
		require.True(t, ok)
		require.Len(t, roleMappingInt, 1)
		mappingMap, ok := roleMappingInt[0].(map[string]any)
		require.True(t, ok)
		require.Equal(t, []any{"grp1", "grp2"}, mappingMap["groups"])
		require.Equal(t, "role1", mappingMap["roleName"])

		_, found = sett["fgaMappings"]
		require.False(t, found)
	}))
	err := mgmt.SSO().ConfigureSAMLSettingsByMetadata(context.Background(), "abc", settings, "https://redirect", []string{"domain.com"}, ssoID)
	require.NoError(t, err)
}

func TestSSOConfigureSAMLSettingsByMetadataError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.SSO().ConfigureSAMLSettingsByMetadata(context.Background(), "", nil, "https://redirect", []string{"domain.com"}, "")
	require.Error(t, err)

	err = mgmt.SSO().ConfigureSAMLSettingsByMetadata(context.Background(), "abc", nil, "https://redirect", []string{"domain.com"}, "")
	require.Error(t, err)

	settings := &descope.SSOSAMLSettingsByMetadata{}
	err = mgmt.SSO().ConfigureSAMLSettingsByMetadata(context.Background(), "abc", settings, "https://redirect", []string{"domain.com"}, "")
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
		GroupsMapping: []*descope.GroupsMapping{
			{
				Role: &descope.RoleItem{
					ID:   "role.id",
					Name: "role.name",
				},
				Groups: []string{"grp1", "grp2"},
			},
		},
		DefaultSSORoles: []string{"defrole1", "defrole2"},
		GroupsPriority:  []string{"group1"},
		FgaMappings: map[string]*descope.FGAGroupMapping{
			"aa": {
				Relations: []*descope.FGAGroupMappingRelation{},
			},
		},
	}
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["tenantId"])
		require.Empty(t, req["ssoId"])

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
		require.Equal(t, []any{"defrole1", "defrole2"}, sett["defaultSSORoles"])
		require.Equal(t, []any{"group1"}, sett["groupsPriority"])
		require.Equal(t, []any{map[string]any{"groups": []any{"grp1", "grp2"}, "role": map[string]any{"id": "role.id", "name": "role.name"}}}, sett["groupsMapping"])
		require.Equal(t, map[string]any(map[string]any{"aa": map[string]any{}}), sett["fgaMappings"])
	}))
	err := mgmt.SSO().ConfigureOIDCSettings(context.Background(), "abc", oidcSettings, []string{"domain.com"}, "")
	require.NoError(t, err)
}

func TestSSOConfigureOIDCSettingsWithSSOIDSuccess(t *testing.T) {
	ssoID := "somessoid"
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
		require.Equal(t, ssoID, req["ssoId"])

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
	err := mgmt.SSO().ConfigureOIDCSettings(context.Background(), "abc", oidcSettings, []string{"domain.com"}, ssoID)
	require.NoError(t, err)
}

func TestSSOConfigureSAMLSettingsWithConfigFGAMappingResourceIDSuccess(t *testing.T) {
	settings := &descope.SSOSAMLSettings{
		IdpURL:      "http://idpURL",
		IdpEntityID: "entity",
		IdpCert:     "mycert",
		AttributeMapping: &descope.AttributeMapping{
			GivenName: "myGivenName",
		},
		ConfigFGATenantIDResourcePrefix: "prefix_",
		ConfigFGATenantIDResourceSuffix: "_suffix",
	}
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["tenantId"])
		require.Equal(t, "https://redirect", req["redirectUrl"])

		settings, found := req["settings"]
		require.True(t, found)
		sett, ok := settings.(map[string]any)
		require.True(t, ok)
		require.Equal(t, "http://idpURL", sett["idpUrl"])
		require.Equal(t, "mycert", sett["idpCert"])
		require.Equal(t, "entity", sett["entityId"])

		configFGATenantIDResourcePrefix, found := sett["configFGATenantIDResourcePrefix"]
		require.True(t, found)
		require.Equal(t, "prefix_", configFGATenantIDResourcePrefix)
		configFGATenantIDResourceSuffix, found := sett["configFGATenantIDResourceSuffix"]
		require.True(t, found)
		require.Equal(t, "_suffix", configFGATenantIDResourceSuffix)
	}))
	err := mgmt.SSO().ConfigureSAMLSettings(context.Background(), "abc", settings, "https://redirect", []string{"domain.com"}, "")
	require.NoError(t, err)
}

func TestSSOConfigureSAMLSettingsByMetadataWithConfigFGAMappingResourceIDSuccess(t *testing.T) {
	settings := &descope.SSOSAMLSettingsByMetadata{
		IdpMetadataURL: "http://idpURL",
		AttributeMapping: &descope.AttributeMapping{
			GivenName: "myGivenName",
		},
		ConfigFGATenantIDResourcePrefix: "tenant_",
		ConfigFGATenantIDResourceSuffix: "_prod",
	}
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["tenantId"])
		require.Equal(t, "https://redirect", req["redirectUrl"])

		settings, found := req["settings"]
		require.True(t, found)
		sett, ok := settings.(map[string]any)
		require.True(t, ok)
		require.Equal(t, "http://idpURL", sett["idpMetadataUrl"])

		configFGATenantIDResourcePrefix, found := sett["configFGATenantIDResourcePrefix"]
		require.True(t, found)
		require.Equal(t, "tenant_", configFGATenantIDResourcePrefix)
		configFGATenantIDResourceSuffix, found := sett["configFGATenantIDResourceSuffix"]
		require.True(t, found)
		require.Equal(t, "_prod", configFGATenantIDResourceSuffix)
	}))
	err := mgmt.SSO().ConfigureSAMLSettingsByMetadata(context.Background(), "abc", settings, "https://redirect", []string{"domain.com"}, "")
	require.NoError(t, err)
}

func TestSSOConfigureOIDCSettingsError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.SSO().ConfigureOIDCSettings(context.Background(), "", nil, []string{}, "")
	require.Error(t, err)
	err = mgmt.SSO().ConfigureOIDCSettings(context.Background(), "abc", nil, []string{}, "")
	require.Error(t, err)
}

func TestRecalculateSSOMappingsSuccess(t *testing.T) {
	response := map[string]any{}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		tenantID, found := req["tenantId"]
		require.True(t, found)
		require.Equal(t, "tenant123", tenantID)
		ssoID, found := req["ssoId"]
		require.True(t, found)
		require.Equal(t, "sso456", ssoID)
	}, response))

	err := mgmt.SSO().RecalculateSSOMappings(context.Background(), "tenant123", "sso456")
	require.NoError(t, err)
}

func TestRecalculateSSOMappingsWithoutSSOID(t *testing.T) {
	response := map[string]any{}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		tenantID, found := req["tenantId"]
		require.True(t, found)
		require.Equal(t, "tenant123", tenantID)
		_, found = req["ssoId"]
		require.False(t, found) // ssoId should not be present
	}, response))

	err := mgmt.SSO().RecalculateSSOMappings(context.Background(), "tenant123", "")
	require.NoError(t, err)
}

func TestRecalculateSSOMappingsError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))

	// Test with empty tenant ID
	err := mgmt.SSO().RecalculateSSOMappings(context.Background(), "", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "tenantID")
}
