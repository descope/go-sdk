package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	urlpkg "net/url"
	"path"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/logger"
	"github.com/google/uuid"
)

const (
	defaultAPIPrefix          = "https://api"
	defaultDomainName         = "descope.com"
	defaultURL                = defaultAPIPrefix + "." + defaultDomainName
	AuthorizationHeaderName   = "Authorization"
	BearerAuthorizationPrefix = "Bearer "
	nullString                = "null"
)

var (
	Routes = endpoints{
		version:   "/v1/",
		versionV2: "/v2/",
		auth: authEndpoints{
			signInOTP:                    "auth/otp/signin",
			signUpOTP:                    "auth/otp/signup",
			signUpOrInOTP:                "auth/otp/signup-in",
			signUpTOTP:                   "auth/totp/signup",
			updateTOTP:                   "auth/totp/update",
			verifyTOTPCode:               "auth/totp/verify",
			signUpNOTP:                   "auth/notp/whatsapp/signup",
			signInNOTP:                   "auth/notp/whatsapp/signin",
			signUpOrInNOTP:               "auth/notp/whatsapp/signup-in",
			updateUserNOTP:               "auth/notp/whatsapp/update",
			getNOTPSession:               "auth/notp/pending-session",
			verifyCode:                   "auth/otp/verify",
			signUpPassword:               "auth/password/signup",
			signInPassword:               "auth/password/signin",
			sendResetPassword:            "auth/password/reset",
			updateUserPassword:           "auth/password/update",
			replaceUserPassword:          "auth/password/replace",
			passwordPolicy:               "auth/password/policy",
			signInMagicLink:              "auth/magiclink/signin",
			signUpMagicLink:              "auth/magiclink/signup",
			signUpOrInMagicLink:          "auth/magiclink/signup-in",
			verifyMagicLink:              "auth/magiclink/verify",
			signInEnchantedLink:          "auth/enchantedlink/signin",
			signUpEnchantedLink:          "auth/enchantedlink/signup",
			signUpOrInEnchantedLink:      "auth/enchantedlink/signup-in",
			verifyEnchantedLink:          "auth/enchantedlink/verify",
			getEnchantedLinkSession:      "auth/enchantedlink/pending-session",
			updateUserEmailEnchantedLink: "auth/enchantedlink/update/email",
			oauthSignUpOrIn:              "auth/oauth/authorize",
			oauthSignUp:                  "auth/oauth/authorize/signup",
			oauthSignIn:                  "auth/oauth/authorize/signin",
			oauthUpdateUser:              "auth/oauth/authorize/update",
			exchangeTokenOAuth:           "auth/oauth/exchange",
			samlStart:                    "auth/saml/authorize",
			exchangeTokenSAML:            "auth/saml/exchange",
			ssoStart:                     "auth/sso/authorize",
			exchangeTokenSSO:             "auth/sso/exchange",
			webauthnSignUpStart:          "auth/webauthn/signup/start",
			webauthnSignUpFinish:         "auth/webauthn/signup/finish",
			webauthnSignInStart:          "auth/webauthn/signin/start",
			webauthnSignInFinish:         "auth/webauthn/signin/finish",
			webauthnSignUpOrInStart:      "auth/webauthn/signup-in/start",
			webauthnUpdateStart:          "auth/webauthn/update/start",
			webauthnUpdateFinish:         "auth/webauthn/update/finish",
			updateUserEmailMagicLink:     "auth/magiclink/update/email",
			updateUserEmailOTP:           "auth/otp/update/email",
			updateUserPhoneMagicLink:     "auth/magiclink/update/phone",
			updateUserPhoneOTP:           "auth/otp/update/phone",
			exchangeAccessKey:            "auth/accesskey/exchange",
		},
		mgmt: mgmtEndpoints{
			tenantCreate:                             "mgmt/tenant/create",
			tenantUpdate:                             "mgmt/tenant/update",
			tenantDelete:                             "mgmt/tenant/delete",
			tenantLoad:                               "mgmt/tenant",
			tenantLoadAll:                            "mgmt/tenant/all",
			tenantSearchAll:                          "mgmt/tenant/search",
			tenantSettings:                           "mgmt/tenant/settings",
			tenantUpdateDefaultRoles:                 "mgmt/tenant/updateDefaultRoles",
			tenantGenerateSSOConfigurationLink:       "mgmt/tenant/adminlinks/sso/generate",
			tenantRevokeSSOConfigurationLink:         "mgmt/tenant/adminlinks/sso/revoke",
			ssoApplicationOIDCCreate:                 "mgmt/sso/idp/app/oidc/create",
			ssoApplicationSAMLCreate:                 "mgmt/sso/idp/app/saml/create",
			ssoApplicationOIDCUpdate:                 "mgmt/sso/idp/app/oidc/update",
			ssoApplicationSAMLUpdate:                 "mgmt/sso/idp/app/saml/update",
			ssoApplicationDelete:                     "mgmt/sso/idp/app/delete",
			ssoApplicationLoad:                       "mgmt/sso/idp/app/load",
			ssoApplicationLoadAll:                    "mgmt/sso/idp/apps/load",
			userCreate:                               "mgmt/user/create",
			testUserCreate:                           "mgmt/user/create/test",
			userCreateBatch:                          "mgmt/user/create/batch",
			userUpdate:                               "mgmt/user/update",
			userPatch:                                "mgmt/user/patch",
			userPatchBatch:                           "mgmt/user/patch/batch",
			userDelete:                               "mgmt/user/delete",
			userDeleteAllTestUsers:                   "mgmt/user/test/delete/all",
			userImport:                               "mgmt/user/import",
			userLoad:                                 "mgmt/user",
			usersLoad:                                "mgmt/users/load",
			userSearchAll:                            "mgmt/user/search",
			testUserSearchAll:                        "mgmt/user/search/test",
			userUpdateStatus:                         "mgmt/user/update/status",
			userUpdateLoginID:                        "mgmt/user/update/loginid",
			userUpdateEmail:                          "mgmt/user/update/email",
			userUpdatePhone:                          "mgmt/user/update/phone",
			userUpdateName:                           "mgmt/user/update/name",
			userUpdatePicture:                        "mgmt/user/update/picture",
			userUpdateCustomAttribute:                "mgmt/user/update/customAttribute",
			userAddTenant:                            "mgmt/user/update/tenant/add",
			userRemoveTenant:                         "mgmt/user/update/tenant/remove",
			userSetRole:                              "mgmt/user/update/role/set",
			userAddRole:                              "mgmt/user/update/role/add",
			userRemoveRole:                           "mgmt/user/update/role/remove",
			userAddSsoApps:                           "mgmt/user/update/ssoapp/add",
			userSetSsoApps:                           "mgmt/user/update/ssoapp/set",
			userRemoveSsoApps:                        "mgmt/user/update/ssoapp/remove",
			userSetPassword:                          "mgmt/user/password/set",
			userSetTemporaryPassword:                 "mgmt/user/password/set/temporary",
			userSetActivePassword:                    "mgmt/user/password/set/active",
			userExpirePassword:                       "mgmt/user/password/expire",
			userRemoveAllPasskeys:                    "mgmt/user/passkeys/delete",
			userRemoveTOTPSeed:                       "mgmt/user/totp/delete",
			userListTrustedDevices:                   "mgmt/user/trusteddevices/list",
			userRemoveTrustedDevices:                 "mgmt/user/trusteddevices/remove",
			userGetProviderToken:                     "mgmt/user/provider/token",
			userLogoutAllDevices:                     "mgmt/user/logout",
			userGenerateOTPForTest:                   "mgmt/tests/generate/otp",
			userGenerateMagicLinkForTest:             "mgmt/tests/generate/magiclink",
			userGenerateEnchantedLinkForTest:         "mgmt/tests/generate/enchantedlink",
			userCreateSigninEmbeddedLink:             "mgmt/user/signin/embeddedlink",
			userCreateSignUpEmbeddedLink:             "mgmt/user/signup/embeddedlink",
			userHistory:                              "mgmt/user/history",
			accessKeyCreate:                          "mgmt/accesskey/create",
			accessKeyLoad:                            "mgmt/accesskey",
			accessKeySearchAll:                       "mgmt/accesskey/search",
			accessKeyUpdate:                          "mgmt/accesskey/update",
			accessKeyDeactivate:                      "mgmt/accesskey/deactivate",
			accessKeyActivate:                        "mgmt/accesskey/activate",
			accessKeyDelete:                          "mgmt/accesskey/delete",
			ssoSettings:                              "mgmt/sso/settings",
			ssoLoadSettings:                          "mgmt/sso/settings",     // v2 only
			ssoLoadAllSettings:                       "mgmt/sso/settings/all", // v2 only
			ssoSettingsNew:                           "mgmt/sso/settings/new",
			ssoSAMLSettings:                          "mgmt/sso/saml",
			ssoSAMLSettingsByMetadata:                "mgmt/sso/saml/metadata",
			ssoRedirectURL:                           "mgmt/sso/redirect",
			ssoOIDCSettings:                          "mgmt/sso/oidc",
			ssoMetadata:                              "mgmt/sso/metadata",
			ssoMapping:                               "mgmt/sso/mapping",
			ssoRecalculateMappings:                   "mgmt/sso/recalculate-mappings",
			passwordSettings:                         "mgmt/password/settings",
			updateJWT:                                "mgmt/jwt/update",
			impersonate:                              "mgmt/impersonate",
			stopImpersonation:                        "mgmt/stop/impersonation",
			mgmtSignIn:                               "mgmt/auth/signin",
			mgmtSignUp:                               "mgmt/auth/signup",
			mgmtSignUpOrIn:                           "mgmt/auth/signup-in",
			anonymous:                                "mgmt/auth/anonymous",
			permissionCreate:                         "mgmt/permission/create",
			permissionUpdate:                         "mgmt/permission/update",
			permissionDelete:                         "mgmt/permission/delete",
			permissionLoadAll:                        "mgmt/permission/all",
			roleCreate:                               "mgmt/role/create",
			roleUpdate:                               "mgmt/role/update",
			roleDelete:                               "mgmt/role/delete",
			roleLoadAll:                              "mgmt/role/all",
			roleSearch:                               "mgmt/role/search",
			groupLoadAllGroups:                       "mgmt/group/all",
			groupLoadAllGroupsForMember:              "mgmt/group/member/all",
			groupLoadAllGroupMembers:                 "mgmt/group/members",
			runManagementFlow:                        "mgmt/flow/run",
			runManagementFlowAsync:                   "mgmt/flow/async/run",
			getManagementFlowAsyncResult:             "mgmt/flow/async/result",
			listFlows:                                "mgmt/flow/list",
			deleteFlows:                              "mgmt/flow/delete",
			flowExport:                               "mgmt/flow/export",
			flowImport:                               "mgmt/flow/import",
			themeExport:                              "mgmt/theme/export",
			themeImport:                              "mgmt/theme/import",
			projectsList:                             "mgmt/projects/list",
			projectClone:                             "mgmt/project/clone",
			projectUpdateName:                        "mgmt/project/update/name",
			projectUpdateTags:                        "mgmt/project/update/tags",
			projectDelete:                            "mgmt/project/delete",
			projectExportSnapshot:                    "mgmt/project/snapshot/export",
			projectImportSnapshot:                    "mgmt/project/snapshot/import",
			projectValidateSnapshot:                  "mgmt/project/snapshot/validate",
			auditSearch:                              "mgmt/audit/search",
			auditCreate:                              "mgmt/audit/event",
			analyticsSearch:                          "mgmt/analytics/search",
			auditWebhookCreate:                       "mgmt/connector/audit/web/set",
			authzSchemaSave:                          "mgmt/authz/schema/save",
			authzSchemaDelete:                        "mgmt/authz/schema/delete",
			authzSchemaLoad:                          "mgmt/authz/schema/load",
			authzNSSave:                              "mgmt/authz/ns/save",
			authzNSDelete:                            "mgmt/authz/ns/delete",
			authzRDSave:                              "mgmt/authz/rd/save",
			authzRDDelete:                            "mgmt/authz/rd/delete",
			authzRECreate:                            "mgmt/authz/re/create",
			authzREDelete:                            "mgmt/authz/re/delete",
			authzREDeleteResources:                   "mgmt/authz/re/deleteresources",
			authzREHasRelations:                      "mgmt/authz/re/has",
			authzREWho:                               "mgmt/authz/re/who",
			authzREResource:                          "mgmt/authz/re/resource",
			authzRETargets:                           "mgmt/authz/re/targets",
			authzRETargetAll:                         "mgmt/authz/re/targetall",
			authzRETargetWithRelation:                "mgmt/authz/re/targetwithrelation",
			authzGetModified:                         "mgmt/authz/getmodified",
			fgaSchemaDryRun:                          "mgmt/fga/schema/dryrun",
			fgaSaveSchema:                            "mgmt/fga/schema",
			fgaLoadSchema:                            "mgmt/fga/schema",
			fgaCreateRelations:                       "mgmt/fga/relations",
			fgaDeleteRelations:                       "mgmt/fga/relations/delete",
			fgaCheck:                                 "mgmt/fga/check",
			fgaLoadMappableSchema:                    "mgmt/fga/mappable/schema",
			fgaSearchMappableResources:               "mgmt/fga/mappable/resources",
			fgaResourcesLoad:                         "mgmt/fga/resources/load",
			fgaResourcesSave:                         "mgmt/fga/resources/save",
			outboundApplicationCreate:                "mgmt/outbound/app/create",
			outboundApplicationUpdate:                "mgmt/outbound/app/update",
			outboundApplicationDelete:                "mgmt/outbound/app/delete",
			outboundApplicationLoad:                  "mgmt/outbound/app",
			outboundApplicationLoadAll:               "mgmt/outbound/apps",
			outboundApplicationFetchUserToken:        "mgmt/outbound/app/user/token",
			outboundApplicationDeleteUserTokens:      "mgmt/outbound/user/tokens",
			outboundApplicationDeleteTokenByID:       "mgmt/outbound/token",
			thirdPartyApplicationCreate:              "mgmt/thirdparty/app/create",
			thirdPartyApplicationUpdate:              "mgmt/thirdparty/app/update",
			thirdPartyApplicationPatch:               "mgmt/thirdparty/app/patch",
			thirdPartyApplicationDelete:              "mgmt/thirdparty/app/delete",
			thirdPartyApplicationLoad:                "mgmt/thirdparty/app/load",
			thirdPartyApplicationLoadAll:             "mgmt/thirdparty/apps/load",
			thirdPartyApplicationSecret:              "mgmt/thirdparty/app/secret",
			thirdPartyApplicationRotate:              "mgmt/thirdparty/app/rotate",
			thirdPartyApplicationConsentDelete:       "mgmt/thirdparty/consents/delete",
			thirdPartyApplicationTenantConsentDelete: "mgmt/thirdparty/consents/delete/tenant",
			thirdPartyApplicationConsentsSearch:      "mgmt/thirdparty/consents/search",
			mgmtKeyCreate:                            "mgmt/managementkey",
			mgmtKeyUpdate:                            "mgmt/managementkey",
			mgmtKeyGet:                               "mgmt/managementkey",
			mgmtKeyDelete:                            "mgmt/managementkey/delete",
			mgmtKeySearch:                            "mgmt/managementkey/search",
			descoperCreate:                           "mgmt/descoper",
			descoperUpdate:                           "mgmt/descoper",
			descoperGet:                              "mgmt/descoper",
			descoperDelete:                           "mgmt/descoper",
			descoperSearch:                           "mgmt/descoper/list",
		},
		logout:       "auth/logout",
		logoutAll:    "auth/logoutall",
		keys:         "/keys/",
		refresh:      "auth/refresh",
		selectTenant: "auth/tenant/select",
		me:           "auth/me",
		meTenants:    "auth/me/tenants",
		history:      "auth/me/history",
	}

	instanceUUID = uuid.New().String()
)

type endpoints struct {
	version      string
	versionV2    string
	auth         authEndpoints
	mgmt         mgmtEndpoints
	logout       string
	logoutAll    string
	keys         string
	refresh      string
	selectTenant string
	me           string
	meTenants    string
	history      string
}

type authEndpoints struct {
	signInOTP                    string
	signUpOTP                    string
	signUpOrInOTP                string
	signUpTOTP                   string
	updateTOTP                   string
	verifyTOTPCode               string
	signUpNOTP                   string
	signInNOTP                   string
	signUpOrInNOTP               string
	updateUserNOTP               string
	getNOTPSession               string
	verifyCode                   string
	signUpPassword               string
	signInPassword               string
	sendResetPassword            string
	updateUserPassword           string
	replaceUserPassword          string
	passwordPolicy               string
	signInMagicLink              string
	signUpMagicLink              string
	signUpOrInMagicLink          string
	verifyMagicLink              string
	signInEnchantedLink          string
	signUpEnchantedLink          string
	signUpOrInEnchantedLink      string
	verifyEnchantedLink          string
	getEnchantedLinkSession      string
	updateUserEmailEnchantedLink string
	oauthSignUpOrIn              string
	oauthSignUp                  string
	oauthSignIn                  string
	oauthUpdateUser              string
	exchangeTokenOAuth           string
	samlStart                    string
	ssoStart                     string
	exchangeTokenSAML            string
	exchangeTokenSSO             string
	webauthnSignUpStart          string
	webauthnSignUpFinish         string
	webauthnSignInStart          string
	webauthnSignInFinish         string
	webauthnSignUpOrInStart      string
	webauthnUpdateStart          string
	webauthnUpdateFinish         string
	updateUserEmailMagicLink     string
	updateUserEmailOTP           string
	updateUserPhoneMagicLink     string
	updateUserPhoneOTP           string
	exchangeAccessKey            string
}

type mgmtEndpoints struct {
	tenantCreate             string
	tenantUpdate             string
	tenantDelete             string
	tenantLoad               string
	tenantLoadAll            string
	tenantSearchAll          string
	tenantSettings           string
	tenantUpdateDefaultRoles string

	tenantGenerateSSOConfigurationLink string
	tenantRevokeSSOConfigurationLink   string

	ssoApplicationOIDCCreate string
	ssoApplicationSAMLCreate string
	ssoApplicationOIDCUpdate string
	ssoApplicationSAMLUpdate string
	ssoApplicationDelete     string
	ssoApplicationLoad       string
	ssoApplicationLoadAll    string

	userCreate                string
	testUserCreate            string
	userCreateBatch           string
	userUpdate                string
	userPatch                 string
	userPatchBatch            string
	userDelete                string
	userDeleteAllTestUsers    string
	userImport                string
	userLoad                  string
	usersLoad                 string
	userSearchAll             string
	testUserSearchAll         string
	userUpdateStatus          string
	userUpdateLoginID         string
	userUpdateEmail           string
	userUpdatePhone           string
	userUpdateName            string
	userUpdatePicture         string
	userUpdateCustomAttribute string
	userAddTenant             string
	userRemoveTenant          string
	userAddRole               string
	userSetRole               string
	userRemoveRole            string
	userSetPassword           string
	userSetTemporaryPassword  string
	userSetActivePassword     string
	userExpirePassword        string
	userRemoveAllPasskeys     string
	userRemoveTOTPSeed        string
	userGetProviderToken      string
	userLogoutAllDevices      string
	userAddSsoApps            string
	userSetSsoApps            string
	userRemoveSsoApps         string
	userListTrustedDevices    string
	userRemoveTrustedDevices  string

	userGenerateOTPForTest           string
	userGenerateMagicLinkForTest     string
	userGenerateEnchantedLinkForTest string
	userCreateSigninEmbeddedLink     string
	userCreateSignUpEmbeddedLink     string

	userHistory string

	accessKeyCreate     string
	accessKeyLoad       string
	accessKeySearchAll  string
	accessKeyUpdate     string
	accessKeyDeactivate string
	accessKeyActivate   string
	accessKeyDelete     string

	//* Deprecated (use the below value instead) *//
	ssoSettings string
	ssoMetadata string
	ssoMapping  string
	///////////////////

	ssoLoadSettings           string
	ssoLoadAllSettings        string
	ssoSettingsNew            string
	ssoSAMLSettings           string
	ssoSAMLSettingsByMetadata string
	ssoRedirectURL            string
	ssoOIDCSettings           string
	ssoRecalculateMappings    string
	updateJWT                 string
	impersonate               string
	stopImpersonation         string
	mgmtSignIn                string
	mgmtSignUp                string
	mgmtSignUpOrIn            string
	anonymous                 string

	passwordSettings string

	permissionCreate  string
	permissionUpdate  string
	permissionDelete  string
	permissionLoadAll string

	roleCreate  string
	roleUpdate  string
	roleDelete  string
	roleLoadAll string
	roleSearch  string

	groupLoadAllGroups          string
	groupLoadAllGroupsForMember string
	groupLoadAllGroupMembers    string

	runManagementFlow            string
	runManagementFlowAsync       string
	getManagementFlowAsyncResult string
	listFlows                    string
	deleteFlows                  string
	flowExport                   string
	flowImport                   string
	themeExport                  string
	themeImport                  string

	projectsList            string
	projectClone            string
	projectUpdateName       string
	projectUpdateTags       string
	projectDelete           string
	projectExportSnapshot   string
	projectImportSnapshot   string
	projectValidateSnapshot string

	auditSearch        string
	auditCreate        string
	analyticsSearch    string
	auditWebhookCreate string

	authzSchemaSave           string
	authzSchemaDelete         string
	authzSchemaLoad           string
	authzNSSave               string
	authzNSDelete             string
	authzRDSave               string
	authzRDDelete             string
	authzRECreate             string
	authzREDelete             string
	authzREDeleteResources    string
	authzREHasRelations       string
	authzREWho                string
	authzREResource           string
	authzRETargets            string
	authzRETargetAll          string
	authzRETargetWithRelation string
	authzGetModified          string

	fgaSaveSchema              string
	fgaSchemaDryRun            string
	fgaLoadSchema              string
	fgaCreateRelations         string
	fgaDeleteRelations         string
	fgaCheck                   string
	fgaLoadMappableSchema      string
	fgaSearchMappableResources string
	fgaResourcesLoad           string
	fgaResourcesSave           string

	outboundApplicationCreate           string
	outboundApplicationUpdate           string
	outboundApplicationDelete           string
	outboundApplicationLoad             string
	outboundApplicationLoadAll          string
	outboundApplicationFetchUserToken   string
	outboundApplicationDeleteUserTokens string
	outboundApplicationDeleteTokenByID  string

	thirdPartyApplicationCreate              string
	thirdPartyApplicationUpdate              string
	thirdPartyApplicationPatch               string
	thirdPartyApplicationDelete              string
	thirdPartyApplicationLoad                string
	thirdPartyApplicationLoadAll             string
	thirdPartyApplicationSecret              string
	thirdPartyApplicationRotate              string
	thirdPartyApplicationConsentDelete       string
	thirdPartyApplicationTenantConsentDelete string
	thirdPartyApplicationConsentsSearch      string

	mgmtKeyCreate string
	mgmtKeyUpdate string
	mgmtKeyGet    string
	mgmtKeyDelete string
	mgmtKeySearch string

	descoperCreate string
	descoperUpdate string
	descoperGet    string
	descoperDelete string
	descoperSearch string
}

func (e *endpoints) SignInOTP() string {
	return path.Join(e.version, e.auth.signInOTP)
}

func (e *endpoints) SignUpOTP() string {
	return path.Join(e.version, e.auth.signUpOTP)
}

func (e *endpoints) SignUpOrInOTP() string {
	return path.Join(e.version, e.auth.signUpOrInOTP)
}

func (e *endpoints) SignUpTOTP() string {
	return path.Join(e.version, e.auth.signUpTOTP)
}

func (e *endpoints) UpdateTOTP() string {
	return path.Join(e.version, e.auth.updateTOTP)
}

func (e *endpoints) SignUpNOTP() string {
	return path.Join(e.version, e.auth.signUpNOTP)
}

func (e *endpoints) SignInNOTP() string {
	return path.Join(e.version, e.auth.signInNOTP)
}

func (e *endpoints) SignUpOrInNOTP() string {
	return path.Join(e.version, e.auth.signUpOrInNOTP)
}

func (e *endpoints) UpdateUserNOTP() string {
	return path.Join(e.version, e.auth.updateUserNOTP)
}

func (e *endpoints) GetNOTPSession() string {
	return path.Join(e.version, e.auth.getNOTPSession)
}

func (e *endpoints) VerifyCode() string {
	return path.Join(e.version, e.auth.verifyCode)
}

func (e *endpoints) VerifyTOTPCode() string {
	return path.Join(e.version, e.auth.verifyTOTPCode)
}

func (e *endpoints) SignUpPassword() string {
	return path.Join(e.version, e.auth.signUpPassword)
}

func (e *endpoints) SignInPassword() string {
	return path.Join(e.version, e.auth.signInPassword)
}

func (e *endpoints) SendResetPassword() string {
	return path.Join(e.version, e.auth.sendResetPassword)
}

func (e *endpoints) UpdateUserPassword() string {
	return path.Join(e.version, e.auth.updateUserPassword)
}

func (e *endpoints) ReplaceUserPassword() string {
	return path.Join(e.version, e.auth.replaceUserPassword)
}

func (e *endpoints) PasswordPolicy() string {
	return path.Join(e.version, e.auth.passwordPolicy)
}

func (e *endpoints) SignInMagicLink() string {
	return path.Join(e.version, e.auth.signInMagicLink)
}

func (e *endpoints) SignUpMagicLink() string {
	return path.Join(e.version, e.auth.signUpMagicLink)
}

func (e *endpoints) SignUpOrInMagicLink() string {
	return path.Join(e.version, e.auth.signUpOrInMagicLink)
}

func (e *endpoints) VerifyMagicLink() string {
	return path.Join(e.version, e.auth.verifyMagicLink)
}

func (e *endpoints) SignInEnchantedLink() string {
	return path.Join(e.version, e.auth.signInEnchantedLink)
}

func (e *endpoints) SignUpEnchantedLink() string {
	return path.Join(e.version, e.auth.signUpEnchantedLink)
}

func (e *endpoints) SignUpOrInEnchantedLink() string {
	return path.Join(e.version, e.auth.signUpOrInEnchantedLink)
}

func (e *endpoints) UpdateUserEmailEnchantedlink() string {
	return path.Join(e.version, e.auth.updateUserEmailEnchantedLink)
}

func (e *endpoints) VerifyEnchantedLink() string {
	return path.Join(e.version, e.auth.verifyEnchantedLink)
}

func (e *endpoints) GetEnchantedLinkSession() string {
	return path.Join(e.version, e.auth.getEnchantedLinkSession)
}

func (e *endpoints) OAuthSignUpOrIn() string {
	return path.Join(e.version, e.auth.oauthSignUpOrIn)
}

func (e *endpoints) OAuthSignIn() string {
	return path.Join(e.version, e.auth.oauthSignIn)
}

func (e *endpoints) OAuthSignUp() string {
	return path.Join(e.version, e.auth.oauthSignUp)
}

func (e *endpoints) OAuthUpdateUser() string {
	return path.Join(e.version, e.auth.oauthUpdateUser)
}

func (e *endpoints) ExchangeTokenOAuth() string {
	return path.Join(e.version, e.auth.exchangeTokenOAuth)
}

/* Deprecated (use SSOStart(..) instead) */
func (e *endpoints) SAMLStart() string {
	return path.Join(e.version, e.auth.samlStart)
}

/* Deprecated (use ExchangeTokenSSO(..) instead) */
func (e *endpoints) ExchangeTokenSAML() string {
	return path.Join(e.version, e.auth.exchangeTokenSAML)
}

func (e *endpoints) SSOStart() string {
	return path.Join(e.version, e.auth.ssoStart)
}

func (e *endpoints) ExchangeTokenSSO() string {
	return path.Join(e.version, e.auth.exchangeTokenSSO)
}

func (e *endpoints) WebAuthnSignUpStart() string {
	return path.Join(e.version, e.auth.webauthnSignUpStart)
}

func (e *endpoints) WebAuthnSignUpFinish() string {
	return path.Join(e.version, e.auth.webauthnSignUpFinish)
}

func (e *endpoints) WebAuthnSignInStart() string {
	return path.Join(e.version, e.auth.webauthnSignInStart)
}

func (e *endpoints) WebAuthnSignInFinish() string {
	return path.Join(e.version, e.auth.webauthnSignInFinish)
}

func (e *endpoints) WebAuthnSignUpOrInStart() string {
	return path.Join(e.version, e.auth.webauthnSignUpOrInStart)
}

func (e *endpoints) WebAuthnUpdateUserDeviceStart() string {
	return path.Join(e.version, e.auth.webauthnUpdateStart)
}

func (e *endpoints) WebAuthnUpdateUserDeviceFinish() string {
	return path.Join(e.version, e.auth.webauthnUpdateFinish)
}

func (e *endpoints) Logout() string {
	return path.Join(e.version, e.logout)
}

func (e *endpoints) LogoutAll() string {
	return path.Join(e.version, e.logoutAll)
}

func (e *endpoints) Me() string {
	return path.Join(e.version, e.me)
}

func (e *endpoints) MeTenants() string {
	return path.Join(e.version, e.meTenants)
}

func (e *endpoints) History() string {
	return path.Join(e.version, e.history)
}

func (e *endpoints) GetKeys() string {
	return path.Join(e.versionV2, e.keys)
}

func (e *endpoints) RefreshToken() string {
	return path.Join(e.version, e.refresh)
}

func (e *endpoints) SelectTenant() string {
	return path.Join(e.version, e.selectTenant)
}

func (e *endpoints) UpdateUserEmailMagiclink() string {
	return path.Join(e.version, e.auth.updateUserEmailMagicLink)
}

func (e *endpoints) UpdateUserEmailOTP() string {
	return path.Join(e.version, e.auth.updateUserEmailOTP)
}

func (e *endpoints) UpdateUserPhoneMagicLink() string {
	return path.Join(e.version, e.auth.updateUserPhoneMagicLink)
}

func (e *endpoints) UpdateUserPhoneOTP() string {
	return path.Join(e.version, e.auth.updateUserPhoneOTP)
}

func (e *endpoints) ExchangeAccessKey() string {
	return path.Join(e.version, e.auth.exchangeAccessKey)
}

func (e *endpoints) ManagementTenantCreate() string {
	return path.Join(e.version, e.mgmt.tenantCreate)
}

func (e *endpoints) ManagementTenantUpdate() string {
	return path.Join(e.version, e.mgmt.tenantUpdate)
}

func (e *endpoints) ManagementTenantDelete() string {
	return path.Join(e.version, e.mgmt.tenantDelete)
}

func (e *endpoints) ManagementTenantLoad() string {
	return path.Join(e.version, e.mgmt.tenantLoad)
}

func (e *endpoints) ManagementTenantLoadAll() string {
	return path.Join(e.version, e.mgmt.tenantLoadAll)
}

func (e *endpoints) ManagementTenantSearchAll() string {
	return path.Join(e.version, e.mgmt.tenantSearchAll)
}

func (e *endpoints) ManagementTenantSettings() string {
	return path.Join(e.version, e.mgmt.tenantSettings)
}

func (e *endpoints) ManagementTenantUpdateDefaultRoles() string {
	return path.Join(e.version, e.mgmt.tenantUpdateDefaultRoles)
}

func (e *endpoints) ManagementTenantGenerateSSOConfigurationLink() string {
	return path.Join(e.versionV2, e.mgmt.tenantGenerateSSOConfigurationLink)
}

func (e *endpoints) ManagementTenantRevokeSSOConfigurationLink() string {
	return path.Join(e.version, e.mgmt.tenantRevokeSSOConfigurationLink)
}

func (e *endpoints) ManagementSSOApplicationOIDCCreate() string {
	return path.Join(e.version, e.mgmt.ssoApplicationOIDCCreate)
}

func (e *endpoints) ManagementSSOApplicationSAMLCreate() string {
	return path.Join(e.version, e.mgmt.ssoApplicationSAMLCreate)
}

func (e *endpoints) ManagementSSOApplicationOIDCUpdate() string {
	return path.Join(e.version, e.mgmt.ssoApplicationOIDCUpdate)
}

func (e *endpoints) ManagementSSOApplicationSAMLUpdate() string {
	return path.Join(e.version, e.mgmt.ssoApplicationSAMLUpdate)
}

func (e *endpoints) ManagementSSOApplicationDelete() string {
	return path.Join(e.version, e.mgmt.ssoApplicationDelete)
}

func (e *endpoints) ManagementSSOApplicationLoad() string {
	return path.Join(e.version, e.mgmt.ssoApplicationLoad)
}

func (e *endpoints) ManagementSSOApplicationLoadAll() string {
	return path.Join(e.version, e.mgmt.ssoApplicationLoadAll)
}

func (e *endpoints) ManagementUserCreate() string {
	return path.Join(e.version, e.mgmt.userCreate)
}

func (e *endpoints) ManagementTestUserCreate() string {
	return path.Join(e.version, e.mgmt.testUserCreate)
}

func (e *endpoints) ManagementUserCreateBatch() string {
	return path.Join(e.version, e.mgmt.userCreateBatch)
}

func (e *endpoints) ManagementUserUpdate() string {
	return path.Join(e.version, e.mgmt.userUpdate)
}

func (e *endpoints) ManagementUserPatch() string {
	return path.Join(e.version, e.mgmt.userPatch)
}
func (e *endpoints) ManagementUserPatchBatch() string {
	return path.Join(e.version, e.mgmt.userPatchBatch)
}

func (e *endpoints) ManagementUserDelete() string {
	return path.Join(e.version, e.mgmt.userDelete)
}

func (e *endpoints) ManagementUserDeleteAllTestUsers() string {
	return path.Join(e.version, e.mgmt.userDeleteAllTestUsers)
}

func (e *endpoints) ManagementUserImport() string {
	return path.Join(e.version, e.mgmt.userImport)
}

func (e *endpoints) ManagementUserLoad() string {
	return path.Join(e.version, e.mgmt.userLoad)
}

func (e *endpoints) ManagementUsersLoad() string {
	return path.Join(e.version, e.mgmt.usersLoad)
}

func (e *endpoints) ManagementUserSearchAll() string {
	return path.Join(e.versionV2, e.mgmt.userSearchAll)
}

func (e *endpoints) ManagementTestUserSearchAll() string {
	return path.Join(e.versionV2, e.mgmt.testUserSearchAll)
}

func (e *endpoints) ManagementUserUpdateStatus() string {
	return path.Join(e.version, e.mgmt.userUpdateStatus)
}

func (e *endpoints) ManagementUserUpdateLoginID() string {
	return path.Join(e.version, e.mgmt.userUpdateLoginID)
}

func (e *endpoints) ManagementUserUpdateEmail() string {
	return path.Join(e.version, e.mgmt.userUpdateEmail)
}

func (e *endpoints) ManagementUserUpdatePhone() string {
	return path.Join(e.version, e.mgmt.userUpdatePhone)
}

func (e *endpoints) ManagementUserUpdateDisplayName() string {
	return path.Join(e.version, e.mgmt.userUpdateName)
}

func (e *endpoints) ManagementUserUpdatePicture() string {
	return path.Join(e.version, e.mgmt.userUpdatePicture)
}

func (e *endpoints) ManagementUserUpdateCustomAttribute() string {
	return path.Join(e.version, e.mgmt.userUpdateCustomAttribute)
}

func (e *endpoints) ManagementUserAddTenant() string {
	return path.Join(e.version, e.mgmt.userAddTenant)
}

func (e *endpoints) ManagementUserRemoveTenant() string {
	return path.Join(e.version, e.mgmt.userRemoveTenant)
}

func (e *endpoints) ManagementUserSetRole() string {
	return path.Join(e.version, e.mgmt.userSetRole)
}

func (e *endpoints) ManagementUserAddRole() string {
	return path.Join(e.versionV2, e.mgmt.userAddRole)
}

func (e *endpoints) ManagementUserRemoveRole() string {
	return path.Join(e.version, e.mgmt.userRemoveRole)
}

func (e *endpoints) ManagementUserAddSSOApps() string {
	return path.Join(e.version, e.mgmt.userAddSsoApps)
}

func (e *endpoints) ManagementUserSetSSOApps() string {
	return path.Join(e.version, e.mgmt.userSetSsoApps)
}

func (e *endpoints) ManagementUserRemoveSSOApps() string {
	return path.Join(e.version, e.mgmt.userRemoveSsoApps)
}

// Deprecated
func (e *endpoints) ManagementUserSetPassword() string {
	return path.Join(e.version, e.mgmt.userSetPassword)
}

func (e *endpoints) ManagementUserSetTemporaryPassword() string {
	return path.Join(e.version, e.mgmt.userSetTemporaryPassword)
}

func (e *endpoints) ManagementUserSetActivePassword() string {
	return path.Join(e.version, e.mgmt.userSetActivePassword)
}

func (e *endpoints) ManagementUserExpirePassword() string {
	return path.Join(e.version, e.mgmt.userExpirePassword)
}

func (e *endpoints) ManagementUserRemoveAllPasskeys() string {
	return path.Join(e.version, e.mgmt.userRemoveAllPasskeys)
}

func (e *endpoints) ManagementUserRemoveTOTPSeed() string {
	return path.Join(e.version, e.mgmt.userRemoveTOTPSeed)
}

func (e *endpoints) ManagementUserListTrustedDevices() string {
	return path.Join(e.version, e.mgmt.userListTrustedDevices)
}

func (e *endpoints) ManagementUserRemoveTrustedDevices() string {
	return path.Join(e.version, e.mgmt.userRemoveTrustedDevices)
}

func (e *endpoints) ManagementUserGetProviderToken() string {
	return path.Join(e.version, e.mgmt.userGetProviderToken)
}

func (e *endpoints) ManagementUserLogoutAllDevices() string {
	return path.Join(e.version, e.mgmt.userLogoutAllDevices)
}

func (e *endpoints) ManagementUserGenerateOTPForTest() string {
	return path.Join(e.version, e.mgmt.userGenerateOTPForTest)
}

func (e *endpoints) ManagementUserGenerateMagicLinkForTest() string {
	return path.Join(e.version, e.mgmt.userGenerateMagicLinkForTest)
}

func (e *endpoints) ManagementUserGenerateEnchantedLinkForTest() string {
	return path.Join(e.version, e.mgmt.userGenerateEnchantedLinkForTest)
}

func (e *endpoints) ManagementUserHistory() string {
	return path.Join(e.version, e.mgmt.userHistory)
}

func (e *endpoints) ManagementAccessKeyCreate() string {
	return path.Join(e.version, e.mgmt.accessKeyCreate)
}

func (e *endpoints) ManagementAccessKeyLoad() string {
	return path.Join(e.version, e.mgmt.accessKeyLoad)
}

func (e *endpoints) ManagementAccessKeySearchAll() string {
	return path.Join(e.version, e.mgmt.accessKeySearchAll)
}

func (e *endpoints) ManagementAccessKeyUpdate() string {
	return path.Join(e.version, e.mgmt.accessKeyUpdate)
}

func (e *endpoints) ManagementAccessKeyDeactivate() string {
	return path.Join(e.version, e.mgmt.accessKeyDeactivate)
}

func (e *endpoints) ManagementAccessKeyActivate() string {
	return path.Join(e.version, e.mgmt.accessKeyActivate)
}

func (e *endpoints) ManagementAccessKeyDelete() string {
	return path.Join(e.version, e.mgmt.accessKeyDelete)
}

func (e *endpoints) ManagementSSOLoadSettings() string {
	return path.Join(e.versionV2, e.mgmt.ssoLoadSettings)
}

func (e *endpoints) ManagementSSOLoadAllSettings() string {
	return path.Join(e.versionV2, e.mgmt.ssoLoadAllSettings)
}

func (e *endpoints) ManagementNewSSOSettings() string {
	return path.Join(e.version, e.mgmt.ssoSettingsNew)
}

func (e *endpoints) ManagementSSOSAMLSettings() string {
	return path.Join(e.version, e.mgmt.ssoSAMLSettings)
}

func (e *endpoints) ManagementSSOSAMLSettingsByMetadata() string {
	return path.Join(e.version, e.mgmt.ssoSAMLSettingsByMetadata)
}

func (e *endpoints) ManagementSSORedirectURL() string {
	return path.Join(e.version, e.mgmt.ssoRedirectURL)
}

func (e *endpoints) ManagementSSOOIDCSettings() string {
	return path.Join(e.version, e.mgmt.ssoOIDCSettings)
}

// // Deprecated
func (e *endpoints) ManagementSSOSettings() string {
	return path.Join(e.version, e.mgmt.ssoSettings)
}

func (e *endpoints) ManagementSSOMetadata() string {
	return path.Join(e.version, e.mgmt.ssoMetadata)
}

func (e *endpoints) ManagementSSOMapping() string {
	return path.Join(e.version, e.mgmt.ssoMapping)
}

func (e *endpoints) ManagementSSORecalculateMappings() string {
	return path.Join(e.version, e.mgmt.ssoRecalculateMappings)
}

func (e *endpoints) ManagementPasswordSettings() string {
	return path.Join(e.version, e.mgmt.passwordSettings)
}

func (e *endpoints) ManagementUpdateJWT() string {
	return path.Join(e.version, e.mgmt.updateJWT)
}

func (e *endpoints) ManagementImpersonate() string {
	return path.Join(e.version, e.mgmt.impersonate)
}

func (e *endpoints) ManagementStopImpersonation() string {
	return path.Join(e.version, e.mgmt.stopImpersonation)
}

func (e *endpoints) ManagementSignIn() string {
	return path.Join(e.version, e.mgmt.mgmtSignIn)
}

func (e *endpoints) ManagementSignUp() string {
	return path.Join(e.version, e.mgmt.mgmtSignUp)
}

func (e *endpoints) ManagementSignUpOrIn() string {
	return path.Join(e.version, e.mgmt.mgmtSignUpOrIn)
}

func (e *endpoints) Anonymous() string {
	return path.Join(e.version, e.mgmt.anonymous)
}

func (e *endpoints) ManagementGenerateSigninEmbeddedLink() string {
	return path.Join(e.version, e.mgmt.userCreateSigninEmbeddedLink)
}

func (e *endpoints) ManagementGenerateSignUpEmbeddedLink() string {
	return path.Join(e.version, e.mgmt.userCreateSignUpEmbeddedLink)
}

func (e *endpoints) ManagementPermissionCreate() string {
	return path.Join(e.version, e.mgmt.permissionCreate)
}

func (e *endpoints) ManagementPermissionUpdate() string {
	return path.Join(e.version, e.mgmt.permissionUpdate)
}

func (e *endpoints) ManagementPermissionDelete() string {
	return path.Join(e.version, e.mgmt.permissionDelete)
}

func (e *endpoints) ManagementPermissionLoadAll() string {
	return path.Join(e.version, e.mgmt.permissionLoadAll)
}

func (e *endpoints) ManagementRoleCreate() string {
	return path.Join(e.version, e.mgmt.roleCreate)
}

func (e *endpoints) ManagementRoleUpdate() string {
	return path.Join(e.version, e.mgmt.roleUpdate)
}

func (e *endpoints) ManagementRoleDelete() string {
	return path.Join(e.version, e.mgmt.roleDelete)
}

func (e *endpoints) ManagementRoleLoadAll() string {
	return path.Join(e.version, e.mgmt.roleLoadAll)
}

func (e *endpoints) ManagementRoleSearch() string {
	return path.Join(e.version, e.mgmt.roleSearch)
}

func (e *endpoints) ManagementGroupLoadAllGroups() string {
	return path.Join(e.version, e.mgmt.groupLoadAllGroups)
}

func (e *endpoints) ManagementGroupLoadAllGroupsForMember() string {
	return path.Join(e.version, e.mgmt.groupLoadAllGroupsForMember)
}

func (e *endpoints) ManagementGroupLoadAllGroupMembers() string {
	return path.Join(e.version, e.mgmt.groupLoadAllGroupMembers)
}

func (e *endpoints) ManagementRunManagementFlow() string {
	return path.Join(e.version, e.mgmt.runManagementFlow)
}

func (e *endpoints) ManagementRunManagementFlowAsync() string {
	return path.Join(e.version, e.mgmt.runManagementFlowAsync)
}

func (e *endpoints) ManagementGetManagementFlowAsyncResult() string {
	return path.Join(e.version, e.mgmt.getManagementFlowAsyncResult)
}

func (e *endpoints) ManagementListFlows() string {
	return path.Join(e.version, e.mgmt.listFlows)
}

func (e *endpoints) ManagementDeleteFlows() string {
	return path.Join(e.version, e.mgmt.deleteFlows)
}

func (e *endpoints) ManagementFlowExport() string {
	return path.Join(e.versionV2, e.mgmt.flowExport)
}

func (e *endpoints) ManagementFlowImport() string {
	return path.Join(e.versionV2, e.mgmt.flowImport)
}

func (e *endpoints) ManagementThemeExport() string {
	return path.Join(e.versionV2, e.mgmt.themeExport)
}

func (e *endpoints) ManagementThemeImport() string {
	return path.Join(e.versionV2, e.mgmt.themeImport)
}

func (e *endpoints) ManagementProjectsList() string {
	return path.Join(e.version, e.mgmt.projectsList)
}

func (e *endpoints) ManagementProjectClone() string {
	return path.Join(e.version, e.mgmt.projectClone)
}

func (e *endpoints) ManagementProjectUpdateName() string {
	return path.Join(e.version, e.mgmt.projectUpdateName)
}

func (e *endpoints) ManagementProjectUpdateTags() string {
	return path.Join(e.version, e.mgmt.projectUpdateTags)
}

func (e *endpoints) ManagementProjectDelete() string {
	return path.Join(e.version, e.mgmt.projectDelete)
}

func (e *endpoints) ManagementProjectExportSnapshot() string {
	return path.Join(e.version, e.mgmt.projectExportSnapshot)
}

func (e *endpoints) ManagementProjectImportSnapshot() string {
	return path.Join(e.version, e.mgmt.projectImportSnapshot)
}

func (e *endpoints) ManagementProjectValidateSnapshot() string {
	return path.Join(e.version, e.mgmt.projectValidateSnapshot)
}

func (e *endpoints) ManagementAuditSearch() string {
	return path.Join(e.version, e.mgmt.auditSearch)
}

func (e *endpoints) ManagementAuditCreate() string {
	return path.Join(e.version, e.mgmt.auditCreate)
}

func (e *endpoints) ManagementAuditWebhookCreate() string {
	return path.Join(e.versionV2, e.mgmt.auditWebhookCreate)
}

func (e *endpoints) ManagementAnalyticsSearch() string {
	return path.Join(e.version, e.mgmt.analyticsSearch)
}

func (e *endpoints) ManagementAuthzSchemaSave() string {
	return path.Join(e.version, e.mgmt.authzSchemaSave)
}

func (e *endpoints) ManagementAuthzSchemaDelete() string {
	return path.Join(e.version, e.mgmt.authzSchemaDelete)
}

func (e *endpoints) ManagementAuthzSchemaLoad() string {
	return path.Join(e.version, e.mgmt.authzSchemaLoad)
}

func (e *endpoints) ManagementAuthzNSSave() string {
	return path.Join(e.version, e.mgmt.authzNSSave)
}

func (e *endpoints) ManagementAuthzNSDelete() string {
	return path.Join(e.version, e.mgmt.authzNSDelete)
}

func (e *endpoints) ManagementAuthzRDSave() string {
	return path.Join(e.version, e.mgmt.authzRDSave)
}

func (e *endpoints) ManagementAuthzRDDelete() string {
	return path.Join(e.version, e.mgmt.authzRDDelete)
}

func (e *endpoints) ManagementAuthzRECreate() string {
	return path.Join(e.version, e.mgmt.authzRECreate)
}

func (e *endpoints) ManagementAuthzREDelete() string {
	return path.Join(e.version, e.mgmt.authzREDelete)
}

func (e *endpoints) ManagementAuthzREDeleteResources() string {
	return path.Join(e.version, e.mgmt.authzREDeleteResources)
}

func (e *endpoints) ManagementAuthzREHasRelations() string {
	return path.Join(e.version, e.mgmt.authzREHasRelations)
}

func (e *endpoints) ManagementAuthzREWho() string {
	return path.Join(e.version, e.mgmt.authzREWho)
}

func (e *endpoints) ManagementAuthzREResource() string {
	return path.Join(e.version, e.mgmt.authzREResource)
}

func (e *endpoints) ManagementAuthzRETargets() string {
	return path.Join(e.version, e.mgmt.authzRETargets)
}

func (e *endpoints) ManagementAuthzRETargetAll() string {
	return path.Join(e.version, e.mgmt.authzRETargetAll)
}

func (e *endpoints) ManagementAuthzRETargetWithRelation() string {
	return path.Join(e.version, e.mgmt.authzRETargetWithRelation)
}

func (e *endpoints) ManagementAuthzGetModified() string {
	return path.Join(e.version, e.mgmt.authzGetModified)
}

func (e *endpoints) ManagementFGASaveSchema() string {
	return path.Join(e.version, e.mgmt.fgaSaveSchema)
}

func (e *endpoints) ManagementFGASchemaDryRun() string {
	return path.Join(e.version, e.mgmt.fgaSchemaDryRun)
}

func (e *endpoints) ManagementFGALoadSchema() string {
	return path.Join(e.version, e.mgmt.fgaLoadSchema)
}

func (e *endpoints) ManagementFGACreateRelations() string {
	return path.Join(e.version, e.mgmt.fgaCreateRelations)
}

func (e *endpoints) ManagementFGADeleteRelations() string {
	return path.Join(e.version, e.mgmt.fgaDeleteRelations)
}

func (e *endpoints) ManagementFGALoadMappableSchema() string {
	return path.Join(e.version, e.mgmt.fgaLoadMappableSchema)
}

func (e *endpoints) ManagementFGASearchMappableResources() string {
	return path.Join(e.version, e.mgmt.fgaSearchMappableResources)
}

func (e *endpoints) ManagementFGACheck() string {
	return path.Join(e.version, e.mgmt.fgaCheck)
}

func (e *endpoints) ManagementFGAResourcesLoad() string {
	return path.Join(e.version, e.mgmt.fgaResourcesLoad)
}

func (e *endpoints) ManagementFGAResourcesSave() string {
	return path.Join(e.version, e.mgmt.fgaResourcesSave)
}

func (e *endpoints) ManagementOutboundApplicationCreate() string {
	return path.Join(e.version, e.mgmt.outboundApplicationCreate)
}

func (e *endpoints) ManagementOutboundApplicationUpdate() string {
	return path.Join(e.version, e.mgmt.outboundApplicationUpdate)
}

func (e *endpoints) ManagementOutboundApplicationDelete() string {
	return path.Join(e.version, e.mgmt.outboundApplicationDelete)
}

func (e *endpoints) ManagementOutboundApplicationLoad() string {
	return path.Join(e.version, e.mgmt.outboundApplicationLoad)
}

func (e *endpoints) ManagementOutboundApplicationLoadAll() string {
	return path.Join(e.version, e.mgmt.outboundApplicationLoadAll)
}

func (e *endpoints) ManagementOutboundApplicationFetchUserToken() string {
	return path.Join(e.version, e.mgmt.outboundApplicationFetchUserToken)
}

func (e *endpoints) ManagementOutboundApplicationDeleteUserTokens() string {
	return path.Join(e.version, e.mgmt.outboundApplicationDeleteUserTokens)
}

func (e *endpoints) ManagementOutboundApplicationDeleteTokenByID() string {
	return path.Join(e.version, e.mgmt.outboundApplicationDeleteTokenByID)
}

func (e *endpoints) ManagementThirdPartyApplicationCreate() string {
	return path.Join(e.version, e.mgmt.thirdPartyApplicationCreate)
}

func (e *endpoints) ManagementThirdPartyApplicationUpdate() string {
	return path.Join(e.version, e.mgmt.thirdPartyApplicationUpdate)
}

func (e *endpoints) ManagementThirdPartyApplicationDelete() string {
	return path.Join(e.version, e.mgmt.thirdPartyApplicationDelete)
}

func (e *endpoints) ManagementThirdPartyApplicationLoad() string {
	return path.Join(e.version, e.mgmt.thirdPartyApplicationLoad)
}

func (e *endpoints) ManagementThirdPartyApplicationLoadAll() string {
	return path.Join(e.version, e.mgmt.thirdPartyApplicationLoadAll)
}

func (e *endpoints) ManagementThirdPartyApplicationPatch() string {
	return path.Join(e.version, e.mgmt.thirdPartyApplicationPatch)
}

func (e *endpoints) ManagementThirdPartyApplicationSecret() string {
	return path.Join(e.version, e.mgmt.thirdPartyApplicationSecret)
}

func (e *endpoints) ManagementThirdPartyApplicationRotate() string {
	return path.Join(e.version, e.mgmt.thirdPartyApplicationRotate)
}

func (e *endpoints) ManagementThirdPartyApplicationDeleteConsent() string {
	return path.Join(e.version, e.mgmt.thirdPartyApplicationConsentDelete)
}

func (e *endpoints) ManagementThirdPartyApplicationDeleteTenantConsent() string {
	return path.Join(e.version, e.mgmt.thirdPartyApplicationTenantConsentDelete)
}

func (e *endpoints) ManagementThirdPartyApplicationSearchConsents() string {
	return path.Join(e.version, e.mgmt.thirdPartyApplicationConsentsSearch)
}

func (e *endpoints) ManagementMgmtKeyCreate() string {
	return path.Join(e.version, e.mgmt.mgmtKeyCreate)
}

func (e *endpoints) ManagementMgmtKeyUpdate() string {
	return path.Join(e.version, e.mgmt.mgmtKeyUpdate)
}

func (e *endpoints) ManagementMgmtKeyGet() string {
	return path.Join(e.version, e.mgmt.mgmtKeyGet)
}

func (e *endpoints) ManagementMgmtKeyDelete() string {
	return path.Join(e.version, e.mgmt.mgmtKeyDelete)
}

func (e *endpoints) ManagementMgmtKeySearch() string {
	return path.Join(e.version, e.mgmt.mgmtKeySearch)
}

func (e *endpoints) ManagementDescoperCreate() string {
	return path.Join(e.version, e.mgmt.descoperCreate)
}

func (e *endpoints) ManagementDescoperUpdate() string {
	return path.Join(e.version, e.mgmt.descoperUpdate)
}

func (e *endpoints) ManagementDescoperGet() string {
	return path.Join(e.version, e.mgmt.descoperGet)
}

func (e *endpoints) ManagementDescoperDelete() string {
	return path.Join(e.version, e.mgmt.descoperDelete)
}

func (e *endpoints) ManagementDescoperSearch() string {
	return path.Join(e.version, e.mgmt.descoperSearch)
}

type sdkInfo struct {
	name      string
	version   string
	goVersion string
	sha       string
}

type CertificateVerifyMode int

const (
	// Default: Always verify server certificate, unless the BaseURL is overridden to a value
	// that uses an ip address, localhost, or a custom port
	CertificateVerifyAutomatic CertificateVerifyMode = iota

	// Secure: Always verify server certificate, this is only needed if you override
	// the default BaseURL and the automatic behavior isn't suitable
	CertificateVerifyAlways

	// Insecure: Never verify server certificate
	CertificateVerifyNever
)

type ClientParams struct {
	ProjectID            string
	BaseURL              string
	ManagementKey        string
	DefaultClient        IHttpClient
	CustomDefaultHeaders map[string]string
	ExternalRequestID    func(context.Context) string
	CertificateVerify    CertificateVerifyMode
	RequestTimeout       time.Duration
}

type IHttpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type Client struct {
	httpClient        IHttpClient
	uri               string
	headers           map[string]string
	externalRequestID func(context.Context) string
	Conf              ClientParams
	sdkInfo           *sdkInfo
}
type HTTPResponse struct {
	Req     *http.Request
	Res     *http.Response
	BodyStr string
}
type HTTPRequest struct {
	Headers     map[string]string
	QueryParams map[string]string
	BaseURL     string
	ResBodyObj  any
	Request     *http.Request
	Cookies     []*http.Cookie
}

func baseURLForProjectID(projectID string) string {
	if len(projectID) >= 32 {
		region := projectID[1:5]
		return strings.Join([]string{defaultAPIPrefix, region, defaultDomainName}, ".")
	}
	return defaultURL
}

func NewClient(conf ClientParams) *Client {
	httpClient := conf.DefaultClient
	if httpClient == nil {
		var rt http.RoundTripper
		t, ok := http.DefaultTransport.(*http.Transport)
		if ok {
			t = t.Clone()
			t.MaxIdleConns = 100
			t.MaxConnsPerHost = 100
			t.MaxIdleConnsPerHost = 100
			t.TLSClientConfig.InsecureSkipVerify = conf.CertificateVerify.SkipVerifyValue(conf.BaseURL)
			rt = t
		} else {
			// App has set a different transport layer, we will not change its attributes, and use it as is
			// this will include the tls config
			rt = http.DefaultTransport // notest
		}
		var timeout = time.Second * 60
		if conf.RequestTimeout != 0 {
			timeout = conf.RequestTimeout // notest
		}
		httpClient = &http.Client{
			Timeout:   timeout,
			Transport: rt,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse // notest
			},
		}
	}
	defaultHeaders := map[string]string{}

	maps.Copy(defaultHeaders, conf.CustomDefaultHeaders)

	if conf.BaseURL == "" {
		conf.BaseURL = baseURLForProjectID(conf.ProjectID)
	}

	return &Client{
		uri:               conf.BaseURL,
		httpClient:        httpClient,
		headers:           defaultHeaders,
		externalRequestID: conf.ExternalRequestID,
		Conf:              conf,
		sdkInfo:           getSDKInfo(),
	}
}

func (c *Client) DoGetRequest(ctx context.Context, uri string, options *HTTPRequest, pswd string) (*HTTPResponse, error) {
	return c.DoRequest(ctx, http.MethodGet, uri, nil, options, pswd)
}

func (c *Client) DoDeleteRequest(ctx context.Context, uri string, options *HTTPRequest, pswd string) (*HTTPResponse, error) {
	return c.DoRequest(ctx, http.MethodDelete, uri, nil, options, pswd)
}

func (c *Client) DoPutRequest(ctx context.Context, uri string, body any, options *HTTPRequest, pswd string) (*HTTPResponse, error) {
	return c.doRequestWithBody(ctx, http.MethodPut, uri, body, options, pswd)
}

func (c *Client) DoPostRequest(ctx context.Context, uri string, body any, options *HTTPRequest, pswd string) (*HTTPResponse, error) {
	return c.doRequestWithBody(ctx, http.MethodPost, uri, body, options, pswd)
}

func (c *Client) DoPatchRequest(ctx context.Context, uri string, body any, options *HTTPRequest, pswd string) (*HTTPResponse, error) {
	return c.doRequestWithBody(ctx, http.MethodPatch, uri, body, options, pswd)
}

func (c *Client) doRequestWithBody(ctx context.Context, method string, uri string, body any, options *HTTPRequest, pswd string) (*HTTPResponse, error) {
	if options == nil {
		options = &HTTPRequest{}
	}
	if options.Headers == nil {
		options.Headers = map[string]string{}
	}
	if _, ok := options.Headers["Content-Type"]; !ok {
		options.Headers["Content-Type"] = "application/json"
	}

	var payload io.Reader
	// Originally this was an object, so nil comparison will not always work
	if body != nil {
		if b, err := utils.Marshal(body); err == nil {
			// According to the above comment, we might get here, and there are parsers that do not like this string
			// We prefer the body will be nil
			if string(b) != nullString {
				payload = bytes.NewBuffer(b)
			}
		} else {
			return nil, err
		}
	}

	return c.DoRequest(ctx, method, uri, payload, options, pswd)
}

func (c *Client) DoRequest(ctx context.Context, method, uriPath string, body io.Reader, options *HTTPRequest, pswd string) (*HTTPResponse, error) {
	if options == nil {
		options = &HTTPRequest{}
	}

	base := c.uri
	if options.BaseURL != "" {
		base = options.BaseURL
	}

	url := fmt.Sprintf("%s/%s", base, strings.TrimLeft(uriPath, "/"))
	req := options.Request
	if req == nil {
		var err error
		req, err = http.NewRequest(method, url, body)
		if err != nil {
			return nil, err
		}
	} else {
		query := req.URL.Query().Encode()
		if query != "" {
			url = fmt.Sprintf("%s?%s", url, query)
		}
		parsedURL, err := urlpkg.Parse(url)
		if err != nil {
			return nil, err
		}
		parsedURL.Query().Encode()
		req.URL = parsedURL
	}

	queryString := req.URL.Query()
	for key, value := range options.QueryParams {
		queryString.Set(key, value)
	}
	req.URL.RawQuery = queryString.Encode()

	for key, value := range c.headers {
		req.Header.Add(key, value)
	}

	if c.externalRequestID != nil {
		req.Header.Add("x-external-rid", c.externalRequestID(ctx))
	}

	for key, value := range options.Headers {
		req.Header.Add(key, value)
	}
	for _, cookie := range options.Cookies {
		req.AddCookie(cookie)
	}

	bearerParts := []string{}
	if len(c.Conf.ProjectID) > 0 {
		bearerParts = append(bearerParts, c.Conf.ProjectID)
	}
	if len(pswd) > 0 {
		bearerParts = append(bearerParts, pswd)
	}
	if mgmtKey := c.Conf.ManagementKey; len(mgmtKey) > 0 {
		// append a management key if available, this is true for both management and authentication requests
		// only using the different provided keys in the client initialization
		bearerParts = append(bearerParts, mgmtKey)
	}
	if len(bearerParts) > 0 {
		req.Header.Set(AuthorizationHeaderName, BearerAuthorizationPrefix+strings.Join(bearerParts, ":"))
	}

	c.addDescopeHeaders(req)

	logger.LogDebug("Sending request to [%s]", url)

	if ctx != nil {
		req = req.WithContext(ctx)
	}
	response, err := c.httpClient.Do(req)
	if err != nil {
		logger.LogError("Failed sending request to [%s]", err, url)
		return nil, err
	}

	if response.Body != nil {
		defer func() { _ = response.Body.Close() }()
	}
	if !isResponseOK(response) {
		err = c.parseDescopeError(response).WithInfo(descope.ErrorInfoKeys.HTTPResponseStatusCode, response.StatusCode)
		logger.LogInfo("Failed sending request to [%s], error: [%s]", url, err)
		return nil, err
	}

	resBytes, err := c.parseBody(response)
	if err != nil { // notest
		logger.LogError("Failed processing body from request to [%s]", err, url)
		return nil, descope.ErrInvalidResponse
	}

	if options.ResBodyObj != nil {
		if err = utils.Unmarshal(resBytes, &options.ResBodyObj); err != nil {
			logger.LogError("Failed parsing body from request to [%s]", err, url)
			return nil, descope.ErrInvalidResponse
		}
	}

	return &HTTPResponse{
		Req:     req,
		Res:     response,
		BodyStr: string(resBytes),
	}, nil
}

func (c *Client) parseBody(response *http.Response) (resBytes []byte, err error) {
	if response.Body != nil {
		resBytes, err = io.ReadAll(response.Body)
		if err != nil {
			return nil, err
		}
	}
	return
}

func (c *Client) parseDescopeError(response *http.Response) *descope.Error {
	body, err := c.parseBody(response)
	if err != nil { // notest
		logger.LogError("Failed to process error from server response", err)
		return descope.ErrInvalidResponse
	}

	var descopeErr *descope.Error
	if err := json.Unmarshal(body, &descopeErr); err != nil || descopeErr.Code == "" {
		logger.LogError("Failed to parse error from server response", err)
		return descope.ErrInvalidResponse
	}

	if descopeErr.Is(descope.ErrRateLimitExceeded) {
		if seconds, _ := strconv.Atoi(response.Header.Get(descope.ErrorInfoKeys.RateLimitExceededRetryAfter)); seconds != 0 {
			descopeErr = descopeErr.WithInfo(descope.ErrorInfoKeys.RateLimitExceededRetryAfter, seconds)
		}
	}

	if descopeErr.Description == "" {
		descopeErr.Description = "Server error"
	}

	return descopeErr
}

func isResponseOK(response *http.Response) bool {
	return response.StatusCode >= http.StatusOK && response.StatusCode < http.StatusMultipleChoices || response.StatusCode == http.StatusTemporaryRedirect
}

func (c *Client) addDescopeHeaders(req *http.Request) {
	req.Header.Set("x-descope-sdk-name", c.sdkInfo.name)
	req.Header.Set("x-descope-sdk-go-version", c.sdkInfo.goVersion)
	req.Header.Set("x-descope-sdk-version", c.sdkInfo.version)
	req.Header.Set("x-descope-sdk-sha", c.sdkInfo.sha)
	req.Header.Set("x-descope-sdk-uuid", instanceUUID)
	req.Header.Set("x-descope-project-id", c.Conf.ProjectID)
}

func getSDKInfo() *sdkInfo {
	sdkInfo := &sdkInfo{
		name:      "golang",
		goVersion: runtime.Version(),
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi != nil {
		for _, dep := range bi.Deps { // notest
			if strings.HasPrefix(dep.Path, "github.com/descope/go-sdk/descope") && len(dep.Version) > 0 {
				sdkInfo.version = dep.Version
				sdkInfo.sha = dep.Sum
				break
			}
		}
	}
	return sdkInfo
}

func (mode CertificateVerifyMode) SkipVerifyValue(baseURL string) bool {
	if mode == CertificateVerifyAlways {
		return false
	}
	if mode == CertificateVerifyNever {
		return true
	}
	if url, err := urlpkg.Parse(baseURL); err == nil {
		if !strings.Contains(url.Hostname(), ".") || url.Port() != "" {
			return true
		}
		if ip := net.ParseIP(url.Hostname()); ip != nil {
			return true
		}
	}
	return false
}
