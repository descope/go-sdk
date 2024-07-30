package mgmt

import (
	"context"
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/tests/helpers"
	"github.com/stretchr/testify/require"
)

func TestSSOApplicationCreateOIDCApplicationSuccess(t *testing.T) {
	response := map[string]any{"id": "qux"}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "id1", req["id"])
		require.Equal(t, "abc", req["name"])
		require.Equal(t, "desc", req["description"])
		require.Equal(t, true, req["enabled"])
		require.Equal(t, "logo", req["logo"])
		require.Equal(t, "http://dummy.com", req["loginPageUrl"])
		require.True(t, req["forceAuthentication"].(bool))
	}, response))

	id, err := mgmt.SSOApplication().CreateOIDCApplication(context.Background(), &descope.OIDCApplicationRequest{
		ID:                  "id1",
		Name:                "abc",
		Description:         "desc",
		Enabled:             true,
		Logo:                "logo",
		LoginPageURL:        "http://dummy.com",
		ForceAuthentication: true,
	})
	require.NoError(t, err)
	require.Equal(t, "qux", id)
}

func TestSSOApplicationCreateOIDCApplicationError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))

	// Empty application
	id, err := mgmt.SSOApplication().CreateOIDCApplication(context.Background(), nil)
	require.Error(t, err)
	require.Empty(t, id)

	// Empty application Name
	id, err = mgmt.SSOApplication().CreateOIDCApplication(context.Background(), &descope.OIDCApplicationRequest{ID: "id1"})
	require.Error(t, err)
	require.Empty(t, id)
}

func TestSSOApplicationCreateSAMLApplicationSuccess(t *testing.T) {
	response := map[string]any{"id": "qux"}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "id1", req["id"])
		require.Equal(t, "abc", req["name"])
		require.Equal(t, "desc", req["description"])
		require.Equal(t, true, req["enabled"])
		require.Equal(t, "logo", req["logo"])

		require.Equal(t, "http://dummy.com/login", req["loginPageUrl"])
		require.Equal(t, true, req["useMetadataInfo"])
		require.Equal(t, "http://dummy.com/md", req["metadataUrl"])
		require.Equal(t, "aaaa", req["entityId"])
		require.Equal(t, "http://dummy.com/acs", req["acsUrl"])
		require.Equal(t, "cert", req["certificate"])
		require.Equal(t, []any{map[string]any{"name": "n1", "type": "t1", "value": "v1"}}, req["attributeMapping"])
		require.Equal(t, []any{map[string]any{"filterType": "ft1", "name": "n1", "roles": []any{map[string]any{"id": "r1", "name": "rn1"}}, "type": "t1", "value": "v1"}}, req["groupsMapping"])
		require.Equal(t, []any{"http://dummy.com/acsallow"}, req["acsAllowedCallbacks"])
		require.Equal(t, "rs", req["defaultRelayState"])
		require.Equal(t, "email", req["subjectNameIdType"])
		require.Equal(t, "", req["subjectNameIdFormat"])
		require.True(t, req["forceAuthentication"].(bool))
		require.Equal(t, "http://dummy.com/logout", req["logoutRedirectUrl"])

	}, response))

	id, err := mgmt.SSOApplication().CreateSAMLApplication(context.Background(), &descope.SAMLApplicationRequest{
		ID:                  "id1",
		Name:                "abc",
		Description:         "desc",
		Enabled:             true,
		Logo:                "logo",
		LoginPageURL:        "http://dummy.com/login",
		UseMetadataInfo:     true,
		MetadataURL:         "http://dummy.com/md",
		EntityID:            "aaaa",
		AcsURL:              "http://dummy.com/acs",
		Certificate:         "cert",
		AttributeMapping:    []descope.SAMLIDPAttributeMappingInfo{{Name: "n1", Type: "t1", Value: "v1"}},
		GroupsMapping:       []descope.SAMLIDPGroupsMappingInfo{{Name: "n1", Type: "t1", FilterType: "ft1", Value: "v1", Roles: []descope.SAMLIDPRoleGroupMappingInfo{{ID: "r1", Name: "rn1"}}}},
		AcsAllowedCallbacks: []string{"http://dummy.com/acsallow"},
		DefaultRelayState:   "rs",
		SubjectNameIDType:   "email",
		SubjectNameIDFormat: "",
		ForceAuthentication: true,
		LogoutRedirectURL:   "http://dummy.com/logout",
	})
	require.NoError(t, err)
	require.Equal(t, "qux", id)
}

func TestSSOApplicationCreateSAMLApplicationError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))

	// Empty application
	id, err := mgmt.SSOApplication().CreateSAMLApplication(context.Background(), nil)
	require.Error(t, err)
	require.Empty(t, id)

	// Empty application Name
	id, err = mgmt.SSOApplication().CreateSAMLApplication(context.Background(), &descope.SAMLApplicationRequest{ID: "id1"})
	require.Error(t, err)
	require.Empty(t, id)
}

func TestSSOApplicationUpdateOIDCApplicationSuccess(t *testing.T) {
	response := map[string]any{"id": "qux"}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "id1", req["id"])
		require.Equal(t, "abc", req["name"])
		require.Equal(t, "desc", req["description"])
		require.Equal(t, true, req["enabled"])
		require.Equal(t, "logo", req["logo"])
		require.Equal(t, "http://dummy.com", req["loginPageUrl"])
		require.True(t, req["forceAuthentication"].(bool))
	}, response))

	err := mgmt.SSOApplication().UpdateOIDCApplication(context.Background(), &descope.OIDCApplicationRequest{
		ID:                  "id1",
		Name:                "abc",
		Description:         "desc",
		Enabled:             true,
		Logo:                "logo",
		LoginPageURL:        "http://dummy.com",
		ForceAuthentication: true,
	})
	require.NoError(t, err)
}

func TestSSOApplicationUpdateOIDCApplicationError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))

	// Empty application
	err := mgmt.SSOApplication().UpdateOIDCApplication(context.Background(), nil)
	require.Error(t, err)

	// Empty application ID
	err = mgmt.SSOApplication().UpdateOIDCApplication(context.Background(), &descope.OIDCApplicationRequest{})
	require.Error(t, err)

	// Empty application Name
	err = mgmt.SSOApplication().UpdateOIDCApplication(context.Background(), &descope.OIDCApplicationRequest{ID: "id1"})
	require.Error(t, err)
}

func TestSSOApplicationUpdateSAMLApplicationSuccess(t *testing.T) {
	response := map[string]any{"id": "qux"}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "id1", req["id"])
		require.Equal(t, "abc", req["name"])
		require.Equal(t, "desc", req["description"])
		require.Equal(t, true, req["enabled"])
		require.Equal(t, "logo", req["logo"])

		require.Equal(t, "http://dummy.com/login", req["loginPageUrl"])
		require.Equal(t, true, req["useMetadataInfo"])
		require.Equal(t, "http://dummy.com/md", req["metadataUrl"])
		require.Equal(t, "aaaa", req["entityId"])
		require.Equal(t, "http://dummy.com/acs", req["acsUrl"])
		require.Equal(t, "cert", req["certificate"])
		require.Equal(t, []any{map[string]any{"name": "n1", "type": "t1", "value": "v1"}}, req["attributeMapping"])
		require.Equal(t, []any{map[string]any{"filterType": "ft1", "name": "n1", "roles": []any{map[string]any{"id": "r1", "name": "rn1"}}, "type": "t1", "value": "v1"}}, req["groupsMapping"])
		require.Equal(t, []any{"http://dummy.com/acsallow"}, req["acsAllowedCallbacks"])
		require.Equal(t, "rs", req["defaultRelayState"])
		require.Equal(t, "email", req["subjectNameIdType"])
		require.Equal(t, "", req["subjectNameIdFormat"])
		require.True(t, req["forceAuthentication"].(bool))
		require.Equal(t, "http://dummy.com/logout", req["logoutRedirectUrl"])

	}, response))

	err := mgmt.SSOApplication().UpdateSAMLApplication(context.Background(), &descope.SAMLApplicationRequest{
		ID:                  "id1",
		Name:                "abc",
		Description:         "desc",
		Enabled:             true,
		Logo:                "logo",
		LoginPageURL:        "http://dummy.com/login",
		UseMetadataInfo:     true,
		MetadataURL:         "http://dummy.com/md",
		EntityID:            "aaaa",
		AcsURL:              "http://dummy.com/acs",
		Certificate:         "cert",
		AttributeMapping:    []descope.SAMLIDPAttributeMappingInfo{{Name: "n1", Type: "t1", Value: "v1"}},
		GroupsMapping:       []descope.SAMLIDPGroupsMappingInfo{{Name: "n1", Type: "t1", FilterType: "ft1", Value: "v1", Roles: []descope.SAMLIDPRoleGroupMappingInfo{{ID: "r1", Name: "rn1"}}}},
		AcsAllowedCallbacks: []string{"http://dummy.com/acsallow"},
		DefaultRelayState:   "rs",
		SubjectNameIDType:   "email",
		SubjectNameIDFormat: "",
		ForceAuthentication: true,
		LogoutRedirectURL:   "http://dummy.com/logout",
	})
	require.NoError(t, err)
}

func TestSSOApplicationUpdateSAMLApplicationError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))

	// Empty application
	err := mgmt.SSOApplication().UpdateSAMLApplication(context.Background(), nil)
	require.Error(t, err)

	// Empty application ID
	err = mgmt.SSOApplication().UpdateSAMLApplication(context.Background(), &descope.SAMLApplicationRequest{})
	require.Error(t, err)

	// Empty application Name
	err = mgmt.SSOApplication().UpdateSAMLApplication(context.Background(), &descope.SAMLApplicationRequest{ID: "id1"})
	require.Error(t, err)
}

func TestSSOApplicationDeleteSuccess(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, "abc", req["id"])
	}))
	err := mgmt.SSOApplication().Delete(context.Background(), "abc")
	require.NoError(t, err)
}

func TestSSOApplicationDeleteError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	err := mgmt.SSOApplication().Delete(context.Background(), "")
	require.Error(t, err)
}

func TestSSOApplicationLoadOIDCSuccess(t *testing.T) {
	response := map[string]any{
		"id":          "id1",
		"name":        "abc",
		"description": "desc",
		"enabled":     true,
		"logo":        "logo",
		"appType":     "oidc",
		"oidcSettings": map[string]any{
			"loginPageUrl":        "http://dummy.com",
			"issuer":              "http://dummy.com/P2AAAAA",
			"discoveryUrl":        "http://dummy.com/P2AAAAA/.well-known/openid-configuration",
			"forceAuthentication": true,
		},
	}

	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
	}, response))
	res, err := mgmt.SSOApplication().Load(context.Background(), "id1")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "id1", res.ID)
	require.Equal(t, "abc", res.Name)
	require.Equal(t, "desc", res.Description)
	require.Equal(t, true, res.Enabled)
	require.Equal(t, "logo", res.Logo)
	require.Equal(t, "oidc", res.AppType)
	require.NotNil(t, res.OIDCSettings)
	require.Equal(t, "http://dummy.com", res.OIDCSettings.LoginPageURL)
	require.Equal(t, "http://dummy.com/P2AAAAA", res.OIDCSettings.Issuer)
	require.Equal(t, "http://dummy.com/P2AAAAA/.well-known/openid-configuration", res.OIDCSettings.DiscoveryURL)
	require.True(t, res.OIDCSettings.ForceAuthentication)
	require.Nil(t, res.SAMLSettings)
}

func TestSSOApplicationLoadSAMLSuccess(t *testing.T) {
	response := map[string]any{
		"id":          "id1",
		"name":        "abc",
		"description": "desc",
		"enabled":     true,
		"logo":        "logo",
		"appType":     "saml",
		"samlSettings": map[string]any{
			"loginPageUrl":        "http://dummy.com/login",
			"idpCert":             "cert",
			"useMetadataInfo":     true,
			"metadataUrl":         "http://dummy.com/md",
			"entityId":            "aaaa",
			"acsUrl":              "http://dummy.com/acs",
			"certificate":         "cert",
			"attributeMapping":    []any{map[string]any{"name": "n1", "type": "t1", "value": "v1"}},
			"groupsMapping":       []any{map[string]any{"filterType": "ft1", "name": "n1", "roles": []any{map[string]any{"id": "r1", "name": "rn1"}}, "type": "t1", "value": "v1"}},
			"acsAllowedCallbacks": []any{"http://dummy.com/acsallow"},
			"idpMetadataUrl":      "http://dummy.com/ssomd",
			"idpEntityId":         "eId1",
			"idpSsoUrl":           "http://dummy.com/sso",
			"defaultRelayState":   "rs",
			"idpInitiatedUrl":     "http://dummy.com/idpinit",
			"subjectNameIdType":   "email",
			"subjectNameIdFormat": "",
			"forceAuthentication": true,
			"idpLogoutUrl":        "http://dummy.com/idplogout",
			"logoutRedirectUrl":   "http://dummy.com/logout",
		},
	}

	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
	}, response))
	res, err := mgmt.SSOApplication().Load(context.Background(), "id1")
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, "id1", res.ID)
	require.Equal(t, "abc", res.Name)
	require.Equal(t, "desc", res.Description)
	require.Equal(t, true, res.Enabled)
	require.Equal(t, "logo", res.Logo)
	require.Equal(t, "saml", res.AppType)
	require.Nil(t, res.OIDCSettings)
	require.NotNil(t, res.SAMLSettings)
	require.Equal(t, "http://dummy.com/login", res.SAMLSettings.LoginPageURL)
	require.Equal(t, true, res.SAMLSettings.UseMetadataInfo)
	require.Equal(t, "http://dummy.com/md", res.SAMLSettings.MetadataURL)
	require.Equal(t, "aaaa", res.SAMLSettings.EntityID)
	require.Equal(t, "http://dummy.com/acs", res.SAMLSettings.AcsURL)
	require.Equal(t, "cert", res.SAMLSettings.Certificate)
	require.Equal(t, []descope.SAMLIDPAttributeMappingInfo([]descope.SAMLIDPAttributeMappingInfo{{Name: "n1", Type: "t1", Value: "v1"}}), res.SAMLSettings.AttributeMapping)
	require.Equal(t, []descope.SAMLIDPGroupsMappingInfo([]descope.SAMLIDPGroupsMappingInfo{{Name: "n1", Type: "t1", FilterType: "ft1", Value: "v1", Roles: []descope.SAMLIDPRoleGroupMappingInfo{{ID: "r1", Name: "rn1"}}}}), res.SAMLSettings.GroupsMapping)
	require.Equal(t, []string{"http://dummy.com/acsallow"}, res.SAMLSettings.AcsAllowedCallbacks)
	require.Equal(t, "cert", res.SAMLSettings.IdpCert)
	require.Equal(t, "http://dummy.com/ssomd", res.SAMLSettings.IdpMetadataURL)
	require.Equal(t, "eId1", res.SAMLSettings.IdpEntityID)
	require.Equal(t, "http://dummy.com/sso", res.SAMLSettings.IdpSSOURL)
	require.Equal(t, "rs", res.SAMLSettings.DefaultRelayState)
	require.Equal(t, "http://dummy.com/idpinit", res.SAMLSettings.IdpInitiatedURL)
	require.Equal(t, "email", res.SAMLSettings.SubjectNameIDType)
	require.Equal(t, "", res.SAMLSettings.SubjectNameIDFormat)
	require.True(t, res.SAMLSettings.ForceAuthentication)
	require.Equal(t, "http://dummy.com/idplogout", res.SAMLSettings.IdpLogoutURL)
	require.Equal(t, "http://dummy.com/logout", res.SAMLSettings.LogoutRedirectURL)
}

func TestSSOApplicationLoadError(t *testing.T) {
	// Empty ID
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.SSOApplication().Load(context.Background(), "")
	require.Error(t, err)
	require.Nil(t, res)

	mgmt = newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err = mgmt.SSOApplication().Load(context.Background(), "t1")
	require.Error(t, err)
	require.Nil(t, res)
}

func TestAllSSOApplicationsLoadSuccess(t *testing.T) {
	response := map[string]any{
		"apps": []map[string]any{
			{
				"id":      "id1",
				"name":    "abc",
				"appType": "saml",
				"samlSettings": map[string]any{
					"loginPageUrl":    "http://dummy.com/login",
					"useMetadataInfo": true,
					"metadataUrl":     "http://dummy.com/md",
				},
			},
			{
				"id":      "id2",
				"name":    "efg",
				"appType": "oidc",
				"oidcSettings": map[string]any{
					"loginPageUrl": "http://dummy.com",
					"issuer":       "http://dummy.com/P2AAAAA",
					"discoveryUrl": "http://dummy.com/P2AAAAA/.well-known/openid-configuration",
				},
			},
		}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
	}, response))
	res, err := mgmt.SSOApplication().LoadAll(context.Background())
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Len(t, res, 2)
	for i := range res {
		if res[i].AppType == "saml" {
			require.Equal(t, "id1", res[i].ID)
			require.Equal(t, "abc", res[i].Name)
			require.NotNil(t, res[i].SAMLSettings)
			require.Equal(t, "http://dummy.com/login", res[i].SAMLSettings.LoginPageURL)
			require.Equal(t, true, res[i].SAMLSettings.UseMetadataInfo)
			require.Equal(t, "http://dummy.com/md", res[i].SAMLSettings.MetadataURL)
		} else {
			require.Equal(t, "id2", res[i].ID)
			require.Equal(t, "efg", res[i].Name)
			require.NotNil(t, res[i].OIDCSettings)
			require.Equal(t, "http://dummy.com", res[i].OIDCSettings.LoginPageURL)
			require.Equal(t, "http://dummy.com/P2AAAAA", res[i].OIDCSettings.Issuer)
			require.Equal(t, "http://dummy.com/P2AAAAA/.well-known/openid-configuration", res[i].OIDCSettings.DiscoveryURL)
		}
	}
}

func TestAllSSOApplicationsLoadError(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.SSOApplication().LoadAll(context.Background())
	require.Error(t, err)
	require.Nil(t, res)
}
