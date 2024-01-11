package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
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
)

const (
	defaultURL                = "https://api.descope.com"
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
			oauthStart:                   "auth/oauth/authorize",
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
			tenantCreate:                     "mgmt/tenant/create",
			tenantUpdate:                     "mgmt/tenant/update",
			tenantDelete:                     "mgmt/tenant/delete",
			tenantLoad:                       "mgmt/tenant",
			tenantLoadAll:                    "mgmt/tenant/all",
			tenantSearchAll:                  "mgmt/tenant/search",
			ssoApplicationOIDCCreate:         "mgmt/sso/idp/app/create/oidc",
			ssoApplicationSAMLCreate:         "mgmt/sso/idp/app/create/saml",
			ssoApplicationOIDCUpdate:         "mgmt/sso/idp/app/update/oidc",
			ssoApplicationSAMLUpdate:         "mgmt/sso/idp/app/update/saml",
			ssoApplicationDelete:             "mgmt/sso/idp/app/delete",
			ssoApplicationLoad:               "mgmt/sso/idp/app/load",
			ssoApplicationLoadAll:            "mgmt/sso/idp/app/loadall",
			userCreate:                       "mgmt/user/create",
			userCreateBatch:                  "mgmt/user/create/batch",
			userUpdate:                       "mgmt/user/update",
			userDelete:                       "mgmt/user/delete",
			userDeleteAllTestUsers:           "mgmt/user/test/delete/all",
			userImport:                       "mgmt/user/import",
			userLoad:                         "mgmt/user",
			userSearchAll:                    "mgmt/user/search",
			userUpdateStatus:                 "mgmt/user/update/status",
			userUpdateLoginID:                "mgmt/user/update/loginid",
			userUpdateEmail:                  "mgmt/user/update/email",
			userUpdatePhone:                  "mgmt/user/update/phone",
			userUpdateName:                   "mgmt/user/update/name",
			userUpdatePicture:                "mgmt/user/update/picture",
			userUpdateCustomAttribute:        "mgmt/user/update/customAttribute",
			userAddTenant:                    "mgmt/user/update/tenant/add",
			userRemoveTenant:                 "mgmt/user/update/tenant/remove",
			userSetRole:                      "mgmt/user/update/role/set",
			userAddRole:                      "mgmt/user/update/role/add",
			userRemoveRole:                   "mgmt/user/update/role/remove",
			userSetPassword:                  "mgmt/user/password/set",
			userExpirePassword:               "mgmt/user/password/expire",
			userRemoveAllPasskeys:            "mgmt/user/passkeys/delete",
			userGetProviderToken:             "mgmt/user/provider/token",
			userLogoutAllDevices:             "mgmt/user/logout",
			userGenerateOTPForTest:           "mgmt/tests/generate/otp",
			userGenerateMagicLinkForTest:     "mgmt/tests/generate/magiclink",
			userGenerateEnchantedLinkForTest: "mgmt/tests/generate/enchantedlink",
			userCreateEmbeddedLink:           "mgmt/user/signin/embeddedlink",
			accessKeyCreate:                  "mgmt/accesskey/create",
			accessKeyLoad:                    "mgmt/accesskey",
			accessKeySearchAll:               "mgmt/accesskey/search",
			accessKeyUpdate:                  "mgmt/accesskey/update",
			accessKeyDeactivate:              "mgmt/accesskey/deactivate",
			accessKeyActivate:                "mgmt/accesskey/activate",
			accessKeyDelete:                  "mgmt/accesskey/delete",
			ssoSettings:                      "mgmt/sso/settings",
			ssoLoadSettings:                  "mgmt/sso/settings", // v2 only
			ssoSAMLSettings:                  "mgmt/sso/saml",
			ssoSAMLSettingsByMetadata:        "mgmt/sso/saml/metadata",
			ssoOIDCSettings:                  "mgmt/sso/oidc",
			ssoMetadata:                      "mgmt/sso/metadata",
			ssoMapping:                       "mgmt/sso/mapping",
			updateJWT:                        "mgmt/jwt/update",
			permissionCreate:                 "mgmt/permission/create",
			permissionUpdate:                 "mgmt/permission/update",
			permissionDelete:                 "mgmt/permission/delete",
			permissionLoadAll:                "mgmt/permission/all",
			roleCreate:                       "mgmt/role/create",
			roleUpdate:                       "mgmt/role/update",
			roleDelete:                       "mgmt/role/delete",
			roleLoadAll:                      "mgmt/role/all",
			groupLoadAllGroups:               "mgmt/group/all",
			groupLoadAllGroupsForMember:      "mgmt/group/member/all",
			groupLoadAllGroupMembers:         "mgmt/group/members",
			listFlows:                        "mgmt/flow/list",
			flowExport:                       "mgmt/flow/export",
			flowImport:                       "mgmt/flow/import",
			themeExport:                      "mgmt/theme/export",
			themeImport:                      "mgmt/theme/import",
			projectExport:                    "mgmt/project/export",
			projectImport:                    "mgmt/project/import",
			projectUpdateName:                "mgmt/project/update/name",
			projectClone:                     "mgmt/project/clone",
			projectDelete:                    "mgmt/project/delete",
			auditSearch:                      "mgmt/audit/search",
			authzSchemaSave:                  "mgmt/authz/schema/save",
			authzSchemaDelete:                "mgmt/authz/schema/delete",
			authzSchemaLoad:                  "mgmt/authz/schema/load",
			authzNSSave:                      "mgmt/authz/ns/save",
			authzNSDelete:                    "mgmt/authz/ns/delete",
			authzRDSave:                      "mgmt/authz/rd/save",
			authzRDDelete:                    "mgmt/authz/rd/delete",
			authzRECreate:                    "mgmt/authz/re/create",
			authzREDelete:                    "mgmt/authz/re/delete",
			authzREDeleteResources:           "mgmt/authz/re/deleteresources",
			authzREHasRelations:              "mgmt/authz/re/has",
			authzREWho:                       "mgmt/authz/re/who",
			authzREResource:                  "mgmt/authz/re/resource",
			authzRETargets:                   "mgmt/authz/re/targets",
			authzRETargetAll:                 "mgmt/authz/re/targetall",
		},
		logout:       "auth/logout",
		logoutAll:    "auth/logoutall",
		keys:         "/keys/",
		refresh:      "auth/refresh",
		selectTenant: "auth/tenant/select",
		me:           "auth/me",
	}
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
}

type authEndpoints struct {
	signInOTP                    string
	signUpOTP                    string
	signUpOrInOTP                string
	signUpTOTP                   string
	updateTOTP                   string
	verifyTOTPCode               string
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
	oauthStart                   string
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
	tenantCreate    string
	tenantUpdate    string
	tenantDelete    string
	tenantLoad      string
	tenantLoadAll   string
	tenantSearchAll string

	ssoApplicationOIDCCreate string
	ssoApplicationSAMLCreate string
	ssoApplicationOIDCUpdate string
	ssoApplicationSAMLUpdate string
	ssoApplicationDelete     string
	ssoApplicationLoad       string
	ssoApplicationLoadAll    string

	userCreate                string
	userCreateBatch           string
	userUpdate                string
	userDelete                string
	userDeleteAllTestUsers    string
	userImport                string
	userLoad                  string
	userSearchAll             string
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
	userExpirePassword        string
	userRemoveAllPasskeys     string
	userGetProviderToken      string
	userLogoutAllDevices      string

	userGenerateOTPForTest           string
	userGenerateMagicLinkForTest     string
	userGenerateEnchantedLinkForTest string
	userCreateEmbeddedLink           string

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
	ssoSAMLSettings           string
	ssoSAMLSettingsByMetadata string
	ssoOIDCSettings           string
	updateJWT                 string

	permissionCreate  string
	permissionUpdate  string
	permissionDelete  string
	permissionLoadAll string

	roleCreate  string
	roleUpdate  string
	roleDelete  string
	roleLoadAll string

	groupLoadAllGroups          string
	groupLoadAllGroupsForMember string
	groupLoadAllGroupMembers    string

	listFlows   string
	flowExport  string
	flowImport  string
	themeExport string
	themeImport string

	projectExport     string
	projectImport     string
	projectUpdateName string
	projectClone      string
	projectDelete     string

	auditSearch string

	authzSchemaSave        string
	authzSchemaDelete      string
	authzSchemaLoad        string
	authzNSSave            string
	authzNSDelete          string
	authzRDSave            string
	authzRDDelete          string
	authzRECreate          string
	authzREDelete          string
	authzREDeleteResources string
	authzREHasRelations    string
	authzREWho             string
	authzREResource        string
	authzRETargets         string
	authzRETargetAll       string
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
func (e *endpoints) OAuthStart() string {
	return path.Join(e.version, e.auth.oauthStart)
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

func (e *endpoints) ManagementUserCreateBatch() string {
	return path.Join(e.version, e.mgmt.userCreateBatch)
}

func (e *endpoints) ManagementUserUpdate() string {
	return path.Join(e.version, e.mgmt.userUpdate)
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

func (e *endpoints) ManagementUserSearchAll() string {
	return path.Join(e.version, e.mgmt.userSearchAll)
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
	return path.Join(e.version, e.mgmt.userAddRole)
}

func (e *endpoints) ManagementUserRemoveRole() string {
	return path.Join(e.version, e.mgmt.userRemoveRole)
}

func (e *endpoints) ManagementUserSetPassword() string {
	return path.Join(e.version, e.mgmt.userSetPassword)
}

func (e *endpoints) ManagementUserExpirePassword() string {
	return path.Join(e.version, e.mgmt.userExpirePassword)
}

func (e *endpoints) ManagementUserRemoveAllPasskeys() string {
	return path.Join(e.version, e.mgmt.userRemoveAllPasskeys)
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

func (e *endpoints) ManagementSSOSAMLSettings() string {
	return path.Join(e.version, e.mgmt.ssoSAMLSettings)
}
func (e *endpoints) ManagementSSOSAMLSettingsByMetadata() string {
	return path.Join(e.version, e.mgmt.ssoSAMLSettingsByMetadata)
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

func (e *endpoints) ManagementUpdateJWT() string {
	return path.Join(e.version, e.mgmt.updateJWT)
}

func (e *endpoints) ManagementGenerateEmbeddedLink() string {
	return path.Join(e.version, e.mgmt.userCreateEmbeddedLink)
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

func (e *endpoints) ManagementGroupLoadAllGroups() string {
	return path.Join(e.version, e.mgmt.groupLoadAllGroups)
}

func (e *endpoints) ManagementGroupLoadAllGroupsForMember() string {
	return path.Join(e.version, e.mgmt.groupLoadAllGroupsForMember)
}

func (e *endpoints) ManagementGroupLoadAllGroupMembers() string {
	return path.Join(e.version, e.mgmt.groupLoadAllGroupMembers)
}

func (e *endpoints) ManagementListFlows() string {
	return path.Join(e.version, e.mgmt.listFlows)
}

func (e *endpoints) ManagementFlowExport() string {
	return path.Join(e.version, e.mgmt.flowExport)
}

func (e *endpoints) ManagementFlowImport() string {
	return path.Join(e.version, e.mgmt.flowImport)
}

func (e *endpoints) ManagementThemeExport() string {
	return path.Join(e.version, e.mgmt.themeExport)
}

func (e *endpoints) ManagementThemeImport() string {
	return path.Join(e.version, e.mgmt.themeImport)
}

func (e *endpoints) ManagementProjectExport() string {
	return path.Join(e.version, e.mgmt.projectExport)
}

func (e *endpoints) ManagementProjectImport() string {
	return path.Join(e.version, e.mgmt.projectImport)
}

func (e *endpoints) ManagementProjectUpdateName() string {
	return path.Join(e.version, e.mgmt.projectUpdateName)
}

func (e *endpoints) ManagementProjectClone() string {
	return path.Join(e.version, e.mgmt.projectClone)
}

func (e *endpoints) ManagementProjectDelete() string {
	return path.Join(e.version, e.mgmt.projectDelete)
}

func (e *endpoints) ManagementAuditSearch() string {
	return path.Join(e.version, e.mgmt.auditSearch)
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
	DefaultClient        IHttpClient
	CustomDefaultHeaders map[string]string
	CertificateVerify    CertificateVerifyMode
}

type IHttpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type Client struct {
	httpClient IHttpClient
	uri        string
	headers    map[string]string
	conf       ClientParams
	sdkInfo    *sdkInfo
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
	ResBodyObj  interface{}
	Request     *http.Request
	Cookies     []*http.Cookie
}

func NewClient(conf ClientParams) *Client {
	httpClient := conf.DefaultClient
	if httpClient == nil {
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.MaxIdleConns = 100
		t.MaxConnsPerHost = 100
		t.MaxIdleConnsPerHost = 100
		t.TLSClientConfig.InsecureSkipVerify = conf.CertificateVerify.SkipVerifyValue(conf.BaseURL)
		httpClient = &http.Client{
			Timeout:   time.Second * 10,
			Transport: t,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // notest
			},
		}
	}
	defaultHeaders := map[string]string{}

	for key, value := range conf.CustomDefaultHeaders {
		defaultHeaders[key] = value
	}

	if conf.BaseURL == "" {
		conf.BaseURL = defaultURL
	}

	return &Client{
		uri:        conf.BaseURL,
		httpClient: httpClient,
		headers:    defaultHeaders,
		conf:       conf,
		sdkInfo:    getSDKInfo(),
	}
}

func (c *Client) DoGetRequest(ctx context.Context, uri string, options *HTTPRequest, pswd string) (*HTTPResponse, error) {
	return c.DoRequest(ctx, http.MethodGet, uri, nil, options, pswd)
}

func (c *Client) DoDeleteRequest(ctx context.Context, uri string, options *HTTPRequest, pswd string) (*HTTPResponse, error) {
	return c.DoRequest(ctx, http.MethodDelete, uri, nil, options, pswd)
}

func (c *Client) DoPostRequest(ctx context.Context, uri string, body interface{}, options *HTTPRequest, pswd string) (*HTTPResponse, error) {
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

	return c.DoRequest(ctx, http.MethodPost, uri, payload, options, pswd)
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

	for key, value := range options.Headers {
		req.Header.Add(key, value)
	}
	for _, cookie := range options.Cookies {
		req.AddCookie(cookie)
	}
	bearer := c.conf.ProjectID
	if len(pswd) > 0 {
		bearer = fmt.Sprintf("%s:%s", bearer, pswd)
	}
	req.Header.Set(AuthorizationHeaderName, BearerAuthorizationPrefix+bearer)
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
		defer response.Body.Close()
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
}

func getSDKInfo() *sdkInfo {
	sdkInfo := &sdkInfo{
		name:      "golang",
		goVersion: runtime.Version(),
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi != nil {
		for _, dep := range bi.Deps { // notest
			if strings.HasPrefix(dep.Path, "github.com/descope/go-sdk/descope") {
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
