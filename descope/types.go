package descope

import (
	"strings"
	"time"

	"github.com/descope/go-sdk/descope/logger"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"golang.org/x/exp/maps"
)

// TOTPResponse - returns all relevant data to complete a TOTP registration
// One can select which method of registration to use for handshaking with an Authenticator app
type TOTPResponse struct {
	ProvisioningURL string `json:"provisioningURL,omitempty"`
	Image           string `json:"image,omitempty"`
	Key             string `json:"key,omitempty"`
}

type NOTPResponse struct {
	RedirectURL string `json:"redirectUrl,omitempty"`
	Image       string `json:"image,omitempty"`
	PendingRef  string `json:"pendingRef,omitempty"` // Pending referral code used to poll the authentication info
}

type AuthenticationInfo struct {
	SessionToken *Token        `json:"token,omitempty"`
	RefreshToken *Token        `json:"refreshToken,omitempty"`
	User         *UserResponse `json:"user,omitempty"`
	FirstSeen    bool          `json:"firstSeen,omitempty"`
}

type AnonymousAuthenticationInfo struct {
	SessionToken *Token `json:"token,omitempty"`
	RefreshToken *Token `json:"refreshToken,omitempty"`
}

// UserTrustedDevice represents a device trusted for a user (i.e. remembered device for MFA bypass).
type UserTrustedDevice struct {
	ID             string    `json:"id,omitempty"`
	Name           string    `json:"name,omitempty"`
	DeviceType     string    `json:"deviceType,omitempty"`
	LastLoginTime  time.Time `json:"lastLoginTime,omitempty"`
	ExpirationTime time.Time `json:"expirationTime,omitempty"`
	LastLocation   string    `json:"lastLocation,omitempty"`
}

type WebAuthnTransactionResponse struct {
	TransactionID string `json:"transactionId,omitempty"`
	Options       string `json:"options,omitempty"`
	Create        bool   `json:"create,omitempty"`
}

type WebAuthnFinishRequest struct {
	TransactionID string `json:"transactionID,omitempty"`
	Response      string `json:"response,omitempty"`
}

type UserMapping struct {
	Name        string `json:"name,omitempty"`
	Email       string `json:"email,omitempty"`
	Username    string `json:"username,omitempty"`
	PhoneNumber string `json:"phoneNumber,omitempty"`
	Group       string `json:"group,omitempty"`
}

type RoleItem struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type GroupsMapping struct {
	Role   *RoleItem `json:"role,omitempty"`
	Groups []string  `json:"groups,omitempty"`
}

type SSOSettingsResponse struct {
	TenantID       string           `json:"tenantId,omitempty"`
	IdpEntityID    string           `json:"idpEntityId,omitempty"`
	IdpSSOURL      string           `json:"idpSSOUrl,omitempty"`
	IdpCertificate string           `json:"idpCertificate,omitempty"`
	IdpMetadataURL string           `json:"idpMetadataUrl,omitempty"`
	SpEntityID     string           `json:"spEntityId,omitempty"`
	SpACSUrl       string           `json:"spACSUrl,omitempty"`
	SpCertificate  string           `json:"spCertificate,omitempty"`
	UserMapping    *UserMapping     `json:"userMapping,omitempty"`
	GroupsMapping  []*GroupsMapping `json:"groupsMapping,omitempty"`
	RedirectURL    string           `json:"redirectUrl,omitempty"`
	Domains        []string         `json:"domains,omitempty"`
	// Deprecated - prefer using domains
	Domain string `json:"domain,omitempty"`
}

type PasswordSettings struct {
	Enabled         bool  `json:"enabled,omitempty"`
	MinLength       int32 `json:"minLength,omitempty"`
	Lowercase       bool  `json:"lowercase,omitempty"`
	Uppercase       bool  `json:"uppercase,omitempty"`
	Number          bool  `json:"number,omitempty"`
	NonAlphanumeric bool  `json:"nonAlphanumeric,omitempty"`
	Expiration      bool  `json:"expiration,omitempty"`
	ExpirationWeeks int32 `json:"expirationWeeks,omitempty"`
	Reuse           bool  `json:"reuse,omitempty"`
	ReuseAmount     int32 `json:"reuseAmount,omitempty"`
	Lock            bool  `json:"lock,omitempty"`
	LockAttempts    int32 `json:"lockAttempts,omitempty"`
}

type FGAGroupMappingRelation struct {
	Resource           string `json:"resource,omitempty"`
	RelationDefinition string `json:"relationDefinition,omitempty"`
	Namespace          string `json:"namespace,omitempty"`
}

type FGAGroupMapping struct {
	Relations []*FGAGroupMappingRelation `json:"relations,omitempty"`
}

type SSOSAMLSettingsResponse struct {
	IdpEntityID                     string                      `json:"idpEntityId,omitempty"`
	IdpSSOURL                       string                      `json:"idpSSOUrl,omitempty"`
	IdpCertificate                  string                      `json:"idpCertificate,omitempty"`
	IdpMetadataURL                  string                      `json:"idpMetadataUrl,omitempty"`
	SpEntityID                      string                      `json:"spEntityId,omitempty"`
	SpACSUrl                        string                      `json:"spACSUrl,omitempty"`
	SpCertificate                   string                      `json:"spCertificate,omitempty"`
	AttributeMapping                *AttributeMapping           `json:"attributeMapping,omitempty"`
	GroupsMapping                   []*GroupsMapping            `json:"groupsMapping,omitempty"`
	DefaultSSORoles                 []string                    `json:"defaultSSORoles,omitempty"`
	GroupsPriority                  []string                    `json:"groupsPriority,omitempty"` // list of group names in priority order (first = highest priority)
	RedirectURL                     string                      `json:"redirectUrl,omitempty"`
	FgaMappings                     map[string]*FGAGroupMapping `json:"fgaMappings,omitempty"`
	ConfigFGATenantIDResourcePrefix string                      `json:"configFGATenantIDResourcePrefix,omitempty"`
	ConfigFGATenantIDResourceSuffix string                      `json:"configFGATenantIDResourceSuffix,omitempty"`
}

type SSOSAMLSettings struct {
	IdpURL                          string                      `json:"idpUrl,omitempty"`
	IdpEntityID                     string                      `json:"entityId,omitempty"`
	IdpCert                         string                      `json:"idpCert,omitempty"`
	AttributeMapping                *AttributeMapping           `json:"attributeMapping,omitempty"`
	RoleMappings                    []*RoleMapping              `json:"roleMappings,omitempty"`
	DefaultSSORoles                 []string                    `json:"defaultSSORoles,omitempty"` // roles names
	GroupsPriority                  []string                    `json:"groupsPriority,omitempty"`  // list of group names in priority order (first = highest priority)
	FgaMappings                     map[string]*FGAGroupMapping `json:"fgaMappings,omitempty"`
	ConfigFGATenantIDResourcePrefix string                      `json:"configFGATenantIDResourcePrefix,omitempty"`
	ConfigFGATenantIDResourceSuffix string                      `json:"configFGATenantIDResourceSuffix,omitempty"`

	// NOTICE - the following fields should be overridden only in case of SSO migration, otherwise, do not modify these fields
	SpACSUrl   string `json:"spACSUrl,omitempty"`
	SpEntityID string `json:"spEntityId,omitempty"`
}

type SSOSAMLSettingsByMetadata struct {
	IdpMetadataURL                  string                      `json:"idpMetadataUrl,omitempty"`
	AttributeMapping                *AttributeMapping           `json:"attributeMapping,omitempty"`
	RoleMappings                    []*RoleMapping              `json:"roleMappings,omitempty"`
	DefaultSSORoles                 []string                    `json:"defaultSSORoles,omitempty"` // roles names
	GroupsPriority                  []string                    `json:"groupsPriority,omitempty"`  // list of group names in priority order (first = highest priority)
	FgaMappings                     map[string]*FGAGroupMapping `json:"fgaMappings,omitempty"`
	ConfigFGATenantIDResourcePrefix string                      `json:"configFGATenantIDResourcePrefix,omitempty"`
	ConfigFGATenantIDResourceSuffix string                      `json:"configFGATenantIDResourceSuffix,omitempty"`

	// NOTICE - the following fields should be overridden only in case of SSO migration, otherwise, do not modify these fields
	SpACSUrl   string `json:"spACSUrl,omitempty"`
	SpEntityID string `json:"spEntityId,omitempty"`
}

type OIDCAttributeMapping struct {
	LoginID       string `json:"loginId,omitempty"`
	Name          string `json:"name,omitempty"`
	GivenName     string `json:"givenName,omitempty"`
	MiddleName    string `json:"middleName,omitempty"`
	FamilyName    string `json:"familyName,omitempty"`
	Email         string `json:"email,omitempty"`
	VerifiedEmail string `json:"verifiedEmail,omitempty"`
	Username      string `json:"username,omitempty"`
	PhoneNumber   string `json:"phoneNumber,omitempty"`
	VerifiedPhone string `json:"verifiedPhone,omitempty"`
	Picture       string `json:"picture,omitempty"`
}

type SSOOIDCSettings struct {
	Name                 string                      `json:"name,omitempty"`
	ClientID             string                      `json:"clientId,omitempty"`
	ClientSecret         string                      `json:"clientSecret,omitempty"` // will be empty on response
	RedirectURL          string                      `json:"redirectUrl,omitempty"`
	AuthURL              string                      `json:"authUrl,omitempty"`
	TokenURL             string                      `json:"tokenUrl,omitempty"`
	UserDataURL          string                      `json:"userDataUrl,omitempty"`
	Scope                []string                    `json:"scope,omitempty"`
	JWKsURL              string                      `json:"JWKsUrl,omitempty"`
	AttributeMapping     *OIDCAttributeMapping       `json:"userAttrMapping,omitempty"`
	ManageProviderTokens bool                        `json:"manageProviderTokens,omitempty"`
	CallbackDomain       string                      `json:"callbackDomain,omitempty"`
	Prompt               []string                    `json:"prompt,omitempty"`
	GrantType            string                      `json:"grantType,omitempty"`
	Issuer               string                      `json:"issuer,omitempty"`
	GroupsMapping        []*GroupsMapping            `json:"groupsMapping,omitempty"`
	DefaultSSORoles      []string                    `json:"defaultSSORoles,omitempty"`
	GroupsPriority       []string                    `json:"groupsPriority,omitempty"` // list of group names in priority order (first = highest priority)
	FgaMappings          map[string]*FGAGroupMapping `json:"fgaMappings,omitempty"`
}

type SSOTenantSettingsResponse struct {
	Tenant *Tenant                  `json:"tenant,omitempty"`
	Saml   *SSOSAMLSettingsResponse `json:"saml,omitempty"`
	Oidc   *SSOOIDCSettings         `json:"oidc,omitempty"`
	SSOID  string                   `json:"ssoId,omitempty"`
}

type SSOTenantAllSettingsResponse struct {
	SSOSettings []*SSOTenantSettingsResponse `json:"SSOSettings,omitempty"`
}

type GenerateSSOConfigurationLinkResponse struct {
	AdminSSOConfigurationLink string `json:"adminSSOConfigurationLink,omitempty"`
}

type RecalculateSSOMappingsRequest struct {
	TenantID string `json:"tenantId,omitempty"`
	SSOID    string `json:"ssoId,omitempty"`
}

// PasswordPolicy - represents the rules for valid passwords configured in the policy
// in the Descope console. This can be used to implement client-side validation of new
// user passwords for a better user experience. Either way, the comprehensive
// policy is always enforced by Descope on the server side.
type PasswordPolicy struct {
	MinLength       int32 `json:"minLength,omitempty"`
	Lowercase       bool  `json:"lowercase,omitempty"`
	Uppercase       bool  `json:"uppercase,omitempty"`
	Number          bool  `json:"number,omitempty"`
	NonAlphanumeric bool  `json:"nonAlphanumeric,omitempty"`
}

type AuthFactor string

const (
	AuthFactorUnknown  AuthFactor = ""
	AuthFactorEmail    AuthFactor = "email"
	AuthFactorPhone    AuthFactor = "sms"
	AuthFactorSaml     AuthFactor = "fed"
	AuthFactorOAuth    AuthFactor = "oauth"
	AuthFactorWebauthn AuthFactor = "webauthn"
	AuthFactorTOTP     AuthFactor = "totp"
	AuthFactorMFA      AuthFactor = "mfa"
	AuthFactorPassword AuthFactor = "pwd"
)

type Token struct {
	RefreshExpiration int64          `json:"refreshExpiration,omitempty"`
	Expiration        int64          `json:"expiration,omitempty"`
	JWT               string         `json:"jwt,omitempty"`
	ID                string         `json:"id,omitempty"`
	ProjectID         string         `json:"projectId,omitempty"`
	Claims            map[string]any `json:"claims,omitempty"`
}

func (to *Token) GetTenants() []string {
	tenants := to.getTenants()
	if len(tenants) == 0 && to.Claims != nil && to.Claims[ClaimDescopeCurrentTenant] != nil {
		return []string{to.Claims[ClaimDescopeCurrentTenant].(string)}
	}
	return maps.Keys(tenants)
}

func (to *Token) GetTenantValue(tenant, key string) any {
	tenants := to.getTenants()
	if info, ok := tenants[tenant].(map[string]any); ok {
		return info[key]
	}
	return nil
}

func (to *Token) IsPermitted(permission string) bool {
	permitted := false
	if to.Claims != nil {
		if rawPerm, ok := to.Claims[ClaimAuthorizedGlobalPermissions]; ok {
			if permissions, ok := rawPerm.([]any); ok {
				for i := range permissions {
					if permissions[i] == permission {
						permitted = true
						break
					}
				}
			}
		}
	}
	return permitted
}

func (to *Token) IsPermittedPerTenant(tenant string, permission string) bool {
	permitted := false
	tenants := to.getTenants()
	if to.Claims[ClaimDescopeCurrentTenant] == tenant && len(tenants) == 0 {
		return to.IsPermitted(permission)
	}
	tPermissions, ok := tenants[tenant]
	if ok {
		if tPermissionsMap, ok := tPermissions.(map[string]any); ok {
			if rawPerm, ok := tPermissionsMap[ClaimAuthorizedGlobalPermissions]; ok {
				if permissions, ok := rawPerm.([]any); ok {
					for i := range permissions {
						if permissions[i] == permission {
							permitted = true
							break
						}
					}
				}
			}
		}
	}
	return permitted
}

func (to *Token) getTenants() map[string]any {
	if to.Claims != nil {
		if tenants, ok := to.Claims[ClaimAuthorizedTenants].(map[string]any); ok {
			return tenants
		}
	}
	return make(map[string]any)
}

func (to *Token) CustomClaim(value string) any {
	if to.Claims != nil {
		return to.Claims[value]
	}
	return nil
}

func (to *Token) AuthFactors() []AuthFactor {
	if to.Claims == nil {
		return nil
	}
	var afs []AuthFactor
	factors, ok := to.Claims["amr"]
	if ok {
		factorsArr, ok := factors.([]any)
		if ok {
			for i := range factorsArr {
				af, ok := factorsArr[i].(string)
				if ok {
					afs = append(afs, AuthFactor(af))
				} else {
					logger.LogInfo("Unknown auth-factor type [%T]", factorsArr[i]) //notest
				}
			}
		} else {
			logger.LogInfo("Unknown amr value type [%T]", factors) //notest
		}
	}
	// cases of no factors are not interesting, so not going to log them
	return afs
}

func (to *Token) IsMFA() bool {
	return len(to.AuthFactors()) > 1
}

type LoginOptions struct {
	Stepup                   bool              `json:"stepup,omitempty"`
	MFA                      bool              `json:"mfa,omitempty"`
	RevokeOtherSessions      bool              `json:"revokeOtherSessions,omitempty"`
	RevokeOtherSessionsTypes []string          `json:"revokeOtherSessionsTypes,omitempty"`
	CustomClaims             map[string]any    `json:"customClaims,omitempty"`
	TemplateID               string            `json:"templateId,omitempty"`      // for overriding the default messaging template
	TemplateOptions          map[string]string `json:"templateOptions,omitempty"` // for providing messaging template options (templates that are being sent via email / text message)
}

func (lo *LoginOptions) IsJWTRequired() bool {
	return lo != nil && (lo.Stepup || lo.MFA)
}

type AccessKeyLoginOptions struct {
	CustomClaims   map[string]any `json:"customClaims,omitempty"`
	SelectedTenant string         `json:"selectedTenant,omitempty"`
}

type SignUpOptions struct {
	CustomClaims    map[string]any    `json:"customClaims,omitempty"`
	TemplateID      string            `json:"templateId,omitempty"`      // for overriding the default messaging template
	TemplateOptions map[string]string `json:"templateOptions,omitempty"` // for providing messaging template options (templates that are being sent via email / text message)
}

type EmbeddedLinkLoginOptions struct {
	LoginOptions
	Timeout int64 `json:"timeout,omitempty"` // timeout in seconds for the embedded link to be valid, default is 60 seconds
}

type JWTResponse struct {
	SessionJwt       string        `json:"sessionJwt,omitempty"`
	RefreshJwt       string        `json:"refreshJwt,omitempty"`
	CookieDomain     string        `json:"cookieDomain,omitempty"`
	CookiePath       string        `json:"cookiePath,omitempty"`
	CookieMaxAge     int32         `json:"cookieMaxAge,omitempty"`
	CookieExpiration int32         `json:"cookieExpiration,omitempty"`
	User             *UserResponse `json:"user,omitempty"`
	FirstSeen        bool          `json:"firstSeen,omitempty"`
}

type EnchantedLinkResponse struct {
	PendingRef  string `json:"pendingRef,omitempty"`  // Pending referral code used to poll enchanted link authentication status
	LinkID      string `json:"linkId,omitempty"`      // Link id, on which link the user should click
	MaskedEmail string `json:"maskedEmail,omitempty"` // Masked email to which the email was sent
}

func NewAuthenticationInfo(jRes *JWTResponse, sessionToken, refreshToken *Token) *AuthenticationInfo {
	if jRes == nil {
		jRes = &JWTResponse{}
	}

	if sessionToken == nil || refreshToken == nil {
		logger.LogDebug("Building new authentication info object with empty sessionToken(%t)/refreshToken(%t)", sessionToken == nil, refreshToken == nil)
	}

	return &AuthenticationInfo{
		SessionToken: sessionToken,
		RefreshToken: refreshToken,
		User:         jRes.User,
		FirstSeen:    jRes.FirstSeen,
	}
}

func NewToken(JWT string, token jwt.Token) *Token {
	if token == nil {
		return nil
	}

	parts := strings.Split(token.Issuer(), "/")
	projectID := parts[len(parts)-1]
	sub := token.Subject()
	subRaw, ok := token.PrivateClaims()["dsub"]
	if ok {
		subStr, ok := subRaw.(string)
		if ok {
			sub = subStr
		}
	}
	return &Token{
		JWT:        JWT,
		ID:         sub,
		ProjectID:  projectID,
		Expiration: token.Expiration().Unix(),
		Claims:     token.PrivateClaims(),
	}
}

type InviteOptions struct {
	InviteURL       string            `json:"inviteUrl,omitempty"`
	SendMail        *bool             `json:"sendMail,omitempty"`        // send invite via mail, default is according to project settings
	SendSMS         *bool             `json:"sendSMS,omitempty"`         // send invite via text message, default is according to project settings
	TemplateOptions map[string]string `json:"templateOptions,omitempty"` // for providing messaging template options (templates that are being sent via email / text message)
	TemplateID      string            `json:"-"`
}

type User struct {
	Name       string `json:"name,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
	MiddleName string `json:"middleName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
	Phone      string `json:"phone,omitempty"`
	Email      string `json:"email,omitempty"`
}

type UserRequest struct {
	User               `json:",inline"`
	Roles              []string            `json:"roles,omitempty"`
	Tenants            []*AssociatedTenant `json:"tenants,omitempty"`
	CustomAttributes   map[string]any      `json:"customAttributes,omitempty"`
	Picture            string              `json:"picture,omitempty"`
	VerifiedEmail      *bool               `json:"verifiedEmail,omitempty"`
	VerifiedPhone      *bool               `json:"verifiedPhone,omitempty"`
	AdditionalLoginIDs []string            `json:"additionalLoginIds,omitempty"`
	SSOAppIDs          []string            `json:"ssoAppIDs,omitempty"`
}

type PatchUserRequest struct {
	Name             *string              `json:"name,omitempty"`
	GivenName        *string              `json:"givenName,omitempty"`
	MiddleName       *string              `json:"middleName,omitempty"`
	FamilyName       *string              `json:"familyName,omitempty"`
	Phone            *string              `json:"phone,omitempty"`
	Email            *string              `json:"email,omitempty"`
	Roles            *[]string            `json:"roles,omitempty"`
	Tenants          *[]*AssociatedTenant `json:"tenants,omitempty"`
	CustomAttributes map[string]any       `json:"customAttributes,omitempty"`
	Picture          *string              `json:"picture,omitempty"`
	VerifiedEmail    *bool                `json:"verifiedEmail,omitempty"`
	VerifiedPhone    *bool                `json:"verifiedPhone,omitempty"`
	SSOAppIDs        *[]string            `json:"ssoAppIds,omitempty"`
	SCIM             *bool                `json:"scim,omitempty"`
	Status           *UserStatus          `json:"status,omitempty"`
}

type PatchUserBatchRequest struct {
	LoginID           string `json:"loginId,omitempty"`
	*PatchUserRequest `json:",inline"`
}

type BatchUser struct {
	LoginID     string             `json:"loginId,omitempty"`
	Password    *BatchUserPassword `json:"password,omitempty"`
	Seed        *string            `json:"seed,omitempty"`
	Status      UserStatus         `json:"status,omitempty"`
	UserRequest `json:",inline"`
}

// Set a cleartext or prehashed password for a new user (only one should be set).
type BatchUserPassword struct {
	Cleartext string
	Hashed    *BatchUserPasswordHashed
}

// Set the kind of prehashed password for a user (only one should be set).
type BatchUserPasswordHashed struct {
	Bcrypt   *BatchUserPasswordBcrypt   `json:"bcrypt,omitempty"`
	Firebase *BatchUserPasswordFirebase `json:"firebase,omitempty"`
	Pbkdf2   *BatchUserPasswordPbkdf2   `json:"pbkdf2,omitempty"`
	Django   *BatchUserPasswordDjango   `json:"django,omitempty"`
	Phpass   *BatchUserPasswordPhpass   `json:"phpass,omitempty"`
	Md5      *BatchUserPasswordMd5      `json:"md5,omitempty"`
	Sha      *BatchUserPasswordSha      `json:"sha,omitempty"`
	Argon2   *BatchUserPasswordArgon2   `json:"argon2,omitempty"`
}

type BatchUserPasswordBcrypt struct {
	Hash string `json:"hash"` // the bcrypt hash in plaintext format, for example "$2a$..."
}

type BatchUserPasswordFirebase struct {
	Hash          []byte `json:"hash"`          // the hash in raw bytes (base64 strings should be decoded first)
	Salt          []byte `json:"salt"`          // the salt in raw bytes (base64 strings should be decoded first)
	SaltSeparator []byte `json:"saltSeparator"` // the salt separator (usually 1 byte long)
	SignerKey     []byte `json:"signerKey"`     // the signer key (base64 strings should be decoded first)
	Memory        int    `json:"memory"`        // the memory cost value (usually between 12 to 17)
	Rounds        int    `json:"rounds"`        // the rounds cost value (usually between 6 to 10)
}

type BatchUserPasswordPbkdf2 struct {
	Hash       []byte `json:"hash"`       // the hash in raw bytes (base64 strings should be decoded first)
	Salt       []byte `json:"salt"`       // the salt in raw bytes (base64 strings should be decoded first)
	Iterations int    `json:"iterations"` // the iterations cost value (usually in the thousands)
	Type       string `json:"type"`       // the hash name (sha1, sha256, sha512)
}

type BatchUserPasswordDjango struct {
	Hash string `json:"hash"` // the django hash in plaintext format, for example "pbkdf2_sha256$..."
}

type BatchUserPasswordPhpass struct {
	Hash       string `json:"hash"`       // the hash as base64 encoded string with . and / characters
	Salt       string `json:"salt"`       // the salt as base64 encoded string with . and / characters
	Iterations int    `json:"iterations"` // the iterations cost value (usually in the tens of thousands)
	Type       string `json:"type"`       // the hash name (md5, sha512)
}

type BatchUserPasswordMd5 struct {
	Hash string `json:"hash"` // the md5 hash in hex format, for example "68f724c9ad..."
}

type BatchUserPasswordSha struct {
	Hash string `json:"hash"` // the SHA hash in hex format, for example "68f724c9ad..."
	Type string `json:"type"` // the type of SHA hash (sha1, sha256, sha512)
}

type BatchUserPasswordArgon2 struct {
	Hash       []byte `json:"hash"`       // the hash in raw bytes (base64 strings should be decoded first)
	Salt       []byte `json:"salt"`       // the salt in raw bytes (base64 strings should be decoded first)
	Iterations int    `json:"iterations"` // the memory cost value (usually between 1 to 10)
	Memory     int    `json:"memory"`     // the memory cost value in kilobytes (usually between 1,000 to 1,000,000)
	Threads    int    `json:"threads"`    // the threads cost value (usually between 1 to 10)
}

type UserResponse struct {
	User             `json:",inline"`
	UserID           string                          `json:"userId,omitempty"`
	LoginIDs         []string                        `json:"loginIds,omitempty"`
	VerifiedEmail    bool                            `json:"verifiedEmail,omitempty"`
	VerifiedPhone    bool                            `json:"verifiedPhone,omitempty"`
	RoleNames        []string                        `json:"roleNames,omitempty"`
	UserTenants      []*UserResponseAssociatedTenant `json:"userTenants,omitempty"`
	Status           string                          `json:"status,omitempty"`
	Picture          string                          `json:"picture,omitempty"`
	Test             bool                            `json:"test,omitempty"`
	CustomAttributes map[string]any                  `json:"customAttributes,omitempty"`
	CreatedTime      int32                           `json:"createdTime,omitempty"`
	TOTP             bool                            `json:"totp,omitempty"`
	WebAuthn         bool                            `json:"webauthn,omitempty"`
	Password         bool                            `json:"password,omitempty"`
	SAML             bool                            `json:"saml,omitempty"`
	SCIM             bool                            `json:"scim,omitempty"`
	OAuth            map[string]bool                 `json:"oauth,omitempty"`
	SSOAppIDs        []string                        `json:"ssoAppIds,omitempty"`
}

type MeTenant struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	CustomAttributes map[string]any `json:"customAttributes,omitempty"`
}

type TenantsResponse struct {
	Tenants []MeTenant `json:"tenants,omitempty"`
}

type UserHistoryResponse struct {
	UserID         string `json:"userId,omitempty"`
	LoginTime      int32  `json:"loginTime,omitempty"`
	City           string `json:"city,omitempty"`
	Country        string `json:"country,omitempty"`
	IP             string `json:"ip,omitempty"`
	SelectedTenant string `json:"selectedTenant,omitempty"`
}

type UsersFailedResponse struct {
	Failure string        `json:"failure,omitempty"`
	User    *UserResponse `json:"user,omitempty"`
}

type UsersBatchResponse struct {
	CreatedUsers     []*UserResponse        `json:"createdUsers,omitempty"`
	PatchedUsers     []*UserResponse        `json:"patchedUsers,omitempty"`
	FailedUsers      []*UsersFailedResponse `json:"failedUsers,omitempty"`
	AdditionalErrors map[string]string      `json:"additionalErrors,omitempty"`
}

func (ur *UserResponse) GetCreatedTime() time.Time {
	return time.Unix(int64(ur.CreatedTime), 0)
}

type ProviderTokenOptions struct {
	WithRefreshToken bool `json:"withRefreshToken,omitempty"`
	ForceRefresh     bool `json:"forceRefresh,omitempty"`
}

type ProviderTokenResponse struct {
	Provider       string   `json:"provider,omitempty"`
	ProviderUserID string   `json:"providerUserID,omitempty"`
	AccessToken    string   `json:"accessToken,omitempty"`
	Expiration     uint32   `json:"expiration,omitempty"`
	Scopes         []string `json:"scopes,omitempty"`
	RefreshToken   string   `json:"refreshToken,omitempty"`
}

type UpdateOptions struct {
	AddToLoginIDs      bool              `json:"addToLoginIDs,omitempty"`
	OnMergeUseExisting bool              `json:"onMergeUseExisting,omitempty"`
	TemplateOptions    map[string]string `json:"templateOptions,omitempty"` // for providing messaging template options (templates that are being sent via email / text message)
	TemplateID         string            `json:"templateId,omitempty"`
	ProviderID         string            `json:"providerId,omitempty"`
}

type NOTPTemplates struct {
	VerifyTemplateID  string `json:"verifyTemplateId,omitempty"`
	SuccessTemplateID string `json:"successTemplateId,omitempty"`
	ErrorTemplateID   string `json:"errorTemplateId,omitempty"`
}

type NOTPUpdateOptions struct {
	AddToLoginIDs      bool              `json:"addToLoginIDs,omitempty"`
	OnMergeUseExisting bool              `json:"onMergeUseExisting,omitempty"`
	TemplateOptions    map[string]string `json:"templateOptions,omitempty"` // for providing messaging template options (templates that are being sent via email / text message)
	ProviderID         string            `json:"providerId,omitempty"`
	Templates          *NOTPTemplates    `json:"templates,omitempty"`
	Locale             string            `json:"locale,omitempty"` // locale for the message
}

type AccessKeyResponse struct {
	ID               string              `json:"id,omitempty"`
	Name             string              `json:"name,omitempty"`
	RoleNames        []string            `json:"roleNames,omitempty"`
	KeyTenants       []*AssociatedTenant `json:"keyTenants,omitempty"`
	Status           string              `json:"status,omitempty"`
	CreatedTime      int32               `json:"createdTime,omitempty"`
	ExpireTime       int32               `json:"expireTime,omitempty"`
	CreatedBy        string              `json:"createdBy,omitempty"`
	ClientID         string              `json:"clientId,omitempty"`
	UserID           string              `json:"boundUserId,omitempty"`
	CustomClaims     map[string]any      `json:"customClaims,omitempty"`
	Description      string              `json:"description,omitempty"`
	PermittedIPs     []string            `json:"permittedIps,omitempty"`
	CustomAttributes map[string]any      `json:"customAttributes,omitempty"`
}

// Represents a tenant association for a User or an Access Key. The tenant ID is required
// to denote which tenant the user / access key belongs to. Roles is an optional list of
// roles for the user / access key in this specific tenant.
type AssociatedTenant struct {
	TenantID   string   `json:"tenantId"`
	TenantName string   `json:"tenantName"`
	Roles      []string `json:"roleNames,omitempty"`
}

type UserResponseAssociatedTenant struct {
	AssociatedTenant `json:",inline"`
	Permissions      []string `json:"permissions,omitempty"`
}

// Represents a mapping between a set of groups of users and a role that will be assigned to them.
type RoleMapping struct {
	Groups []string
	Role   string
}

// Represents a SAML mapping between Descope and IDP user attributes
type AttributeMapping struct {
	Name             string            `json:"name,omitempty"`
	GivenName        string            `json:"givenName,omitempty"`
	MiddleName       string            `json:"middleName,omitempty"`
	FamilyName       string            `json:"familyName,omitempty"`
	Picture          string            `json:"picture,omitempty"`
	Email            string            `json:"email,omitempty"`
	PhoneNumber      string            `json:"phoneNumber,omitempty"`
	Group            string            `json:"group,omitempty"`
	CustomAttributes map[string]string `json:"customAttributes,omitempty"`
}

type RoleInheritance string

const RoleInheritanceDefault RoleInheritance = ""
const RoleInheritanceNone RoleInheritance = "none"
const RoleInheritanceUserOnly RoleInheritance = "userOnly"

type Tenant struct {
	ID                      string          `json:"id"`
	Name                    string          `json:"name"`
	SelfProvisioningDomains []string        `json:"selfProvisioningDomains"`
	CustomAttributes        map[string]any  `json:"customAttributes,omitempty"`
	AuthType                string          `json:"authType,omitempty"`
	Domains                 []string        `json:"domains,omitempty"`
	CreatedTime             int32           `json:"createdTime,omitempty"`
	EnforceSSO              bool            `json:"enforceSSO,omitempty"`
	Disabled                bool            `json:"disabled,omitempty"`
	EnforceSSOExclusions    []string        `json:"enforceSSOExclusions,omitempty"`
	RoleInheritance         RoleInheritance `json:"roleInheritance,omitempty"`
}

type TenantRequest struct {
	Name                    string          `json:"name"`
	SelfProvisioningDomains []string        `json:"selfProvisioningDomains"`
	CustomAttributes        map[string]any  `json:"customAttributes,omitempty"`
	EnforceSSO              bool            `json:"enforceSSO,omitempty"`
	Disabled                bool            `json:"disabled,omitempty"`
	ParentTenantID          string          `json:"parentId,omitempty"` // applicable only for creation request
	EnforceSSOExclusions    []string        `json:"enforceSSOExclusions,omitempty"`
	RoleInheritance         RoleInheritance `json:"roleInheritance,omitempty"`
}

type TenantSearchOptions struct {
	IDs                     []string
	Names                   []string
	SelfProvisioningDomains []string
	CustomAttributes        map[string]any
	AuthType                string
}

type TenantSettings struct {
	Domains                    []string `json:"domains,omitempty"`
	SelfProvisioningDomains    []string `json:"selfProvisioningDomains,omitempty"`
	AuthType                   string   `json:"authType,omitempty"`
	SessionSettingsEnabled     bool     `json:"sessionSettingsEnabled,omitempty"`
	RefreshTokenExpiration     int32    `json:"refreshTokenExpiration,omitempty"`
	RefreshTokenExpirationUnit string   `json:"refreshTokenExpirationUnit,omitempty"`
	SessionTokenExpiration     int32    `json:"sessionTokenExpiration,omitempty"`
	SessionTokenExpirationUnit string   `json:"sessionTokenExpirationUnit,omitempty"`
	StepupTokenExpiration      int32    `json:"stepupTokenExpiration,omitempty"`
	StepupTokenExpirationUnit  string   `json:"stepupTokenExpirationUnit,omitempty"`
	EnableInactivity           bool     `json:"enableInactivity,omitempty"`
	InactivityTime             int32    `json:"inactivityTime,omitempty"`
	InactivityTimeUnit         string   `json:"inactivityTimeUnit,omitempty"`
	JITDisabled                bool     `json:"JITDisabled,omitempty"`
}

type SAMLIDPAttributeMappingInfo struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

type SAMLIDPRoleGroupMappingInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type SAMLIDPGroupsMappingInfo struct {
	Name       string                        `json:"name"`
	Type       string                        `json:"type"`
	FilterType string                        `json:"filterType"`
	Value      string                        `json:"value"`
	Roles      []SAMLIDPRoleGroupMappingInfo `json:"roles"`
}

type SSOApplicationSAMLSettings struct {
	LoginPageURL        string                        `json:"loginPageUrl"`
	IdpCert             string                        `json:"idpCert"`
	UseMetadataInfo     bool                          `json:"useMetadataInfo"`
	MetadataURL         string                        `json:"metadataUrl"`
	EntityID            string                        `json:"entityId"`
	AcsURL              string                        `json:"acsUrl"`
	Certificate         string                        `json:"certificate"`
	AttributeMapping    []SAMLIDPAttributeMappingInfo `json:"attributeMapping"`
	GroupsMapping       []SAMLIDPGroupsMappingInfo    `json:"groupsMapping"`
	IdpMetadataURL      string                        `json:"idpMetadataUrl"`
	IdpEntityID         string                        `json:"idpEntityId"`
	IdpSSOURL           string                        `json:"idpSsoUrl"`
	AcsAllowedCallbacks []string                      `json:"acsAllowedCallbacks"`
	DefaultRelayState   string                        `json:"defaultRelayState"`
	IdpInitiatedURL     string                        `json:"idpInitiatedUrl"`
	SubjectNameIDType   string                        `json:"subjectNameIdType"`
	SubjectNameIDFormat string                        `json:"subjectNameIdFormat"`
	ForceAuthentication bool                          `json:"forceAuthentication"`
	IdpLogoutURL        string                        `json:"idpLogoutUrl"`
	LogoutRedirectURL   string                        `json:"logoutRedirectUrl"`
}

type SSOApplicationOIDCSettings struct {
	LoginPageURL         string             `json:"loginPageUrl"`
	Issuer               string             `json:"issuer"`
	DiscoveryURL         string             `json:"discoveryUrl"`
	ForceAuthentication  bool               `json:"forceAuthentication"`
	JWTBearerSettings    *JWTBearerSettings `json:"jwtBearerSettings,omitempty"`
	BackChannelLogoutURL string             `json:"backChannelLogoutUrl,omitempty"`
}

type SSOApplication struct {
	ID           string                      `json:"id"`
	Name         string                      `json:"name"`
	Description  string                      `json:"description"`
	Enabled      bool                        `json:"enabled"`
	Logo         string                      `json:"logo"`
	AppType      string                      `json:"appType"`
	SAMLSettings *SSOApplicationSAMLSettings `json:"samlSettings"`
	OIDCSettings *SSOApplicationOIDCSettings `json:"oidcSettings"`
}

type OIDCApplicationRequest struct {
	ID                   string             `json:"id"`
	Name                 string             `json:"name"`
	Description          string             `json:"description"`
	Enabled              bool               `json:"enabled"`
	Logo                 string             `json:"logo"`
	LoginPageURL         string             `json:"loginPageUrl"`
	ForceAuthentication  bool               `json:"forceAuthentication"`
	JWTBearerSettings    *JWTBearerSettings `json:"jwtBearerSettings,omitempty"`
	BackChannelLogoutURL string             `json:"backChannelLogoutUrl,omitempty"`
}

type SAMLApplicationRequest struct {
	ID                  string                        `json:"id"`
	Name                string                        `json:"name"`
	Description         string                        `json:"description"`
	Enabled             bool                          `json:"enabled"`
	Logo                string                        `json:"logo"`
	LoginPageURL        string                        `json:"loginPageUrl"`
	UseMetadataInfo     bool                          `json:"useMetadataInfo"`
	MetadataURL         string                        `json:"metadataUrl"`
	EntityID            string                        `json:"entityId"`
	AcsURL              string                        `json:"acsUrl"`
	Certificate         string                        `json:"certificate"`
	AttributeMapping    []SAMLIDPAttributeMappingInfo `json:"attributeMapping"`
	GroupsMapping       []SAMLIDPGroupsMappingInfo    `json:"groupsMapping"`
	AcsAllowedCallbacks []string                      `json:"acsAllowedCallbacks"`
	DefaultRelayState   string                        `json:"defaultRelayState"`
	SubjectNameIDType   string                        `json:"subjectNameIdType"`
	SubjectNameIDFormat string                        `json:"subjectNameIdFormat"`
	ForceAuthentication bool                          `json:"forceAuthentication"`
	LogoutRedirectURL   string                        `json:"logoutRedirectUrl"`
}

type SSOApplicationSearchOptions struct {
	IDs     []string
	Names   []string
	AppType string
}

type Permission struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

type Role struct {
	Name            string   `json:"name"`
	Description     string   `json:"description,omitempty"`
	PermissionNames []string `json:"permissionNames,omitempty"`
	CreatedTime     int32    `json:"createdTime,omitempty"`
	TenantID        string   `json:"tenantId,omitempty"`
	Default         bool     `json:"default,omitempty"`
	Private         bool     `json:"private,omitempty"`
}

func (r *Role) GetCreatedTime() time.Time {
	return time.Unix(int64(r.CreatedTime), 0)
}

type RoleSearchOptions struct {
	TenantIDs           []string `json:"tenantIds,omitempty"`
	RoleNames           []string `json:"roleNames,omitempty"`
	RoleNameLike        string   `json:"roleNameLike,omitempty"`
	PermissionNames     []string `json:"permissionNames,omitempty"`
	IncludeProjectRoles *bool    `json:"includeProjectRoles,omitempty"`
}

// Options for searching and filtering users
//
// Limit - limits the number of returned users. Leave at 0 to return the default amount.
// Page - allows to paginate over the results. Pages start at 0 and must non-negative.
// Sort - allows to sort by fields.
// Text - allows free text search among all user's attributes.
// TenantIDs - filter by tenant IDs.
// Roles - filter by role names.
// CustomAttributes map is an optional filter for custom attributes:
// where the keys are the attribute names and the values are either a value we are searching for or list of these values in a slice.
// We currently support string, int and bool values
type UserSearchOptions struct {
	Page              int32
	Limit             int32
	Sort              []UserSearchSort
	Text              string
	Emails            []string
	Phones            []string
	Statuses          []UserStatus
	Roles             []string
	TenantIDs         []string
	SSOAppIDs         []string
	CustomAttributes  map[string]any
	WithTestUsers     bool
	TestUsersOnly     bool
	LoginIDs          []string
	UserIDs           []string
	FromCreatedTime   int64
	ToCreatedTime     int64
	FromModifiedTime  int64
	ToModifiedTime    int64
	TenantRoleIDs     map[string]*RoleList
	TenantRoleNames   map[string]*RoleList
	IncludeSubTenants bool
}

type UserSearchSort struct {
	Field string `json:"field"`
	Desc  bool   `json:"desc"`
}

type RoleList struct {
	Values []string `json:"values,omitempty"`
	And    bool     `json:"and,omitempty"`
}

type UserStatus string

const (
	UserStatusEnabled  UserStatus = "enabled"
	UserStatusDisabled UserStatus = "disabled"
	UserStatusInvited  UserStatus = "invited"
	UserStatusExpired  UserStatus = "expired"
)

type UserImportResponse struct {
	Users    []*UserResponse      `json:"users,omitempty"`
	Failures []*UserImportFailure `json:"failures,omitempty"`
}

type UserImportFailure struct {
	User   string `json:"user"`
	Reason string `json:"reason"`
}

type GroupMember struct {
	LoginID string `json:"loginID,omitempty"`
	UserID  string `json:"userId,omitempty"`
	Display string `json:"display,omitempty"`
}

type Group struct {
	ID      string        `json:"id"`
	Display string        `json:"display,omitempty"`
	Members []GroupMember `json:"members,omitempty"`
}

type FlowList struct {
	Flows []*FlowListEnty `json:"flows"`
}

type FlowListEnty struct {
	FlowID      string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Disabled    bool   `json:"disabled,omitempty"`
}

type AuditRecord struct {
	ProjectID     string    `json:"projectId,omitempty"`
	UserID        string    `json:"userId,omitempty"`
	Action        string    `json:"action,omitempty"`
	Type          string    `json:"type,omitempty"`
	ActorID       string    `json:"actorId,omitempty"`
	Occurred      time.Time `json:"occurred,omitempty"`
	Device        string    `json:"device,omitempty"`
	Method        string    `json:"method,omitempty"`
	Geo           string    `json:"geo,omitempty"`
	RemoteAddress string    `json:"remoteAddress,omitempty"`
	LoginIDs      []string  `json:"loginIds,omitempty"`
	Tenants       []string
	Data          map[string]any `json:"data,omitempty"`
}

// AuditSearchOptions to filter which audits we should retrieve.
// All parameters are optional.
// `From` is currently limited to 30 days
type AuditSearchOptions struct {
	UserIDs         []string  `json:"userIds,omitempty"`         // List of user IDs to filter by
	Actions         []string  `json:"actions,omitempty"`         // List of actions to filter by
	ExcludedActions []string  `json:"excludedActions,omitempty"` // List of actions to exclude
	From            time.Time `json:"from,omitempty"`            // Retrieve records newer than given time. Limited to no older than 30 days.
	To              time.Time `json:"to,omitempty"`              // Retrieve records older than given time.
	Devices         []string  `json:"devices,omitempty"`         // List of devices to filter by. Current devices supported are "Bot"/"Mobile"/"Desktop"/"Tablet"/"Unknown"
	Methods         []string  `json:"methods,omitempty"`         // List of methods to filter by. Current auth methods are "otp"/"totp"/"magiclink"/"oauth"/"saml"/"password"
	Geos            []string  `json:"geos,omitempty"`            // List of geos to filter by. Geo is currently country code like "US", "IL", etc.
	RemoteAddresses []string  `json:"remoteAddresses,omitempty"` // List of remote addresses to filter by
	LoginIDs        []string  `json:"loginIds,omitempty"`        // List of login IDs to filter by
	Tenants         []string  `json:"tenants,omitempty"`         // List of tenants to filter by
	NoTenants       bool      `json:"noTenants"`                 // Should audits without any tenants always be included
	Text            string    `json:"text,omitempty"`            // Free text search across all fields
	Limit           int32     `json:"limit,omitempty"`           // Number of results to include per retrieved page. Current default, and max value, is 1000
	Page            int32     `json:"page,omitempty"`            // Page number of results to retrieve, zero-based. Default is 0.
}

type AuditCreateOptions struct {
	UserID   string         `json:"userId,omitempty"`
	Action   string         `json:"action,omitempty"`
	Type     string         `json:"type,omitempty"` // info/warn/error
	ActorID  string         `json:"actorId,omitempty"`
	Data     map[string]any `json:"data,omitempty"`
	TenantID string         `json:"tenantId,omitempty"`
}

type AnalyticRecord struct {
	ProjectID string    `json:"projectId,omitempty"`
	Action    string    `json:"action,omitempty"`
	Created   time.Time `json:"created,omitempty"`
	Device    string    `json:"device,omitempty"`
	Method    string    `json:"method,omitempty"`
	Geo       string    `json:"geo,omitempty"`
	Tenant    string    `json:"tenant,omitempty"`
	Referrer  string    `json:"referrer,omitempty"`
	Cnt       int       `json:"cnt,omitempty"`
}

// AnalyticsSearchOptions to filter which analytics we should retrieve.
// All parameters are optional.
// `From` is currently limited up to 12 months
type AnalyticsSearchOptions struct {
	Actions         []string  `json:"actions,omitempty"`         // List of actions to filter by
	ExcludedActions []string  `json:"excludedActions,omitempty"` // List of actions to exclude
	From            time.Time `json:"from,omitempty"`            // Retrieve analytics newer than given time. Limited to no older than 12 months.
	To              time.Time `json:"to,omitempty"`              // Retrieve records older than given time.
	Devices         []string  `json:"devices,omitempty"`         // List of devices to filter by. Current devices supported are "Bot"/"Mobile"/"Desktop"/"Tablet"/"Unknown"
	Methods         []string  `json:"methods,omitempty"`         // List of methods to filter by. Current auth methods are "otp"/"totp"/"magiclink"/"oauth"/"saml"/"password"
	Geos            []string  `json:"geos,omitempty"`            // List of geos to filter by. Geo is currently country code like "US", "IL", etc.
	Tenants         []string  `json:"tenants,omitempty"`         // List of tenants to filter by
	GroupByAction   bool      `json:"groupByAction"`             // Should we group summarized results by action
	GroupByDevice   bool      `json:"groupByDevice"`             // Should we group summarized results by device
	GroupByMethod   bool      `json:"groupByMethod"`             // Should we group summarized results by method
	GroupByGeo      bool      `json:"groupByGeo"`                // Should we group summarized results by geo
	GroupByTenant   bool      `json:"groupByTenant"`             // Should we group summarized results by tenant
	GroupByReferrer bool      `json:"groupByReferrer"`           // Should we group summarized results by referrer
	GroupByCreated  string    `json:"groupByCreated,omitempty"`  // How should we group the dates. Possible values are "h" for hour, "d" for day, "w" for week, "m" for month and "q" for quarter
}

type AuditWebhook struct {
	Name           string                       `json:"name,omitempty"`
	Description    string                       `json:"description,omitempty"`
	URL            string                       `json:"url,omitempty"`
	Authentication *ConnectorHTTPAuthentication `json:"authentication,omitempty"`
	HmacSecret     string                       `json:"hmacSecret,omitempty"`
	Headers        map[string]string            `json:"headers,omitempty"`
	Insecure       bool                         `json:"insecure,omitempty"`
	Filters        []*AuditFilters              `json:"filters,omitempty"`
}

type ConnectorHTTPAuthentication struct {
	BearerToken string                             `json:"bearerToken,omitempty"`
	Basic       *ConnectorHTTPBasicAuthentication  `json:"basic,omitempty"`
	APIKey      *ConnectorHTTPAPIKeyAuthentication `json:"apiKey,omitempty"`
}

type ConnectorHTTPBasicAuthentication struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

type ConnectorHTTPAPIKeyAuthentication struct {
	Key   string `json:"key,omitempty"`
	Token string `json:"token,omitempty"`
}

type FilterType string

const FilterTypeAll FilterType = "all"
const FilterTypeActions FilterType = "actions"
const FilterTypeTenants FilterType = "tenants"

type Operator string

const OperatorIncludes Operator = "includes"
const OperatorExcludes Operator = "excludes"

type AuditFilters struct {
	FilterType FilterType `json:"filterType,omitempty"`
	Operator   Operator   `json:"operator,omitempty"`
	Values     []string   `json:"values,omitempty"`
}

type ExportSnapshotRequest struct {
	// An optional string to set the output format (leave empty for default)
	Format string `json:"format"`
}

type ExportSnapshotResponse struct {
	// All project settings and configurations represented as JSON files
	Files map[string]any `json:"files"`
}

type ImportSnapshotRequest struct {
	// All project settings and configurations represented as JSON files
	Files map[string]any `json:"files"`
	// An optional map of project entities and their secrets that will be
	// injected into the snapshot before import (see below)
	InputSecrets *SnapshotSecrets `json:"inputSecrets,omitempty"`
}

type ValidateSnapshotRequest struct {
	// All project settings and configurations represented as JSON files
	Files map[string]any `json:"files"`
	// An optional map of project entities and their secrets that will be
	// injected into the snapshot before validation (see below)
	InputSecrets *SnapshotSecrets `json:"inputSecrets,omitempty"`
}

type ValidateSnapshotResponse struct {
	// Whether the validation passed or not (true if and only if Failures is empty)
	Ok bool `json:"ok"`
	// A string representation of any validation failures that were found
	Failures []string `json:"failures,omitempty"`
	// An optional object that lists which if any secret values need to be provided in
	// the request for an ImportSnapshot call so it doesn't fail (see below)
	MissingSecrets *SnapshotSecrets `json:"missingSecrets,omitempty"`
}

type SnapshotSecrets struct {
	// Any missing or input secrets for connectors in a snapshot
	Connectors []*SnapshotSecret `json:"connectors,omitempty"`
	// Any missing or input secrets for OAuth providers in a snapshot
	OAuthProviders []*SnapshotSecret `json:"oauthProviders,omitempty"`
	// Any missing or input secrets for outbound applications in a snapshot
	OutboundApps []*SnapshotSecret `json:"outboundApps,omitempty"`
}

type SnapshotSecret struct {
	// The id of the project entity that requires this secret
	ID string `json:"id"`
	// The name of the project entity that requires this secret
	Name string `json:"name"`
	// The type of secret, e.g., "bearertoken", "password"
	Type string `json:"type"`
	// The cleartext value of the secret. This value must not be empty when used in
	// request objects when calling ValidateSnapshot and ImportSnapshot. Conversely,
	// this value is an empty string when returned in ValidateSnapshotResponse to
	// signify that this is a missing secret.
	Value string `json:"value,omitempty"`
}

type Project struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Environment string   `json:"environment"`
	Tags        []string `json:"tags"`
}

type CloneProjectResponse struct {
	ProjectID   string   `json:"projectId"`
	ProjectName string   `json:"projectName"`
	Environment string   `json:"environment"`
	Tags        []string `json:"tags"`
}

type DeliveryMethod string

type OAuthProvider string

type ContextKey string

type ProjectEnvironment string

const (
	MethodWhatsApp DeliveryMethod = "whatsapp"
	MethodSMS      DeliveryMethod = "sms"
	MethodVoice    DeliveryMethod = "voice"
	MethodEmail    DeliveryMethod = "email"
	MethodEmbedded DeliveryMethod = "Embedded"

	OAuthFacebook  OAuthProvider = "facebook"
	OAuthGithub    OAuthProvider = "github"
	OAuthGoogle    OAuthProvider = "google"
	OAuthMicrosoft OAuthProvider = "microsoft"
	OAuthGitlab    OAuthProvider = "gitlab"
	OAuthApple     OAuthProvider = "apple"
	OAuthSlack     OAuthProvider = "slack"
	OAuthDiscord   OAuthProvider = "discord"
	OAuthLinkedIn  OAuthProvider = "linkedin"

	ProjectEnvironmentNone       ProjectEnvironment = ""
	ProjectEnvironmentProduction ProjectEnvironment = "production"

	SessionCookieName = "DS"
	RefreshCookieName = "DSR"

	RedirectLocationCookieName = "Location"

	ContextUserIDProperty                       = "DESCOPE_USER_ID"
	ContextUserIDPropertyKey         ContextKey = ContextUserIDProperty
	ClaimAuthorizedTenants                      = "tenants"
	ClaimAuthorizedGlobalPermissions            = "permissions"
	ClaimDescopeCurrentTenant                   = "dct"

	EnvironmentVariableProjectID         = "DESCOPE_PROJECT_ID"
	EnvironmentVariablePublicKey         = "DESCOPE_PUBLIC_KEY"
	EnvironmentVariableManagementKey     = "DESCOPE_MANAGEMENT_KEY"
	EnvironmentVariableAuthManagementKey = "DESCOPE_AUTH_MANAGEMENT_KEY" // gitleaks:allow
	EnvironmentVariableBaseURL           = "DESCOPE_BASE_URL"
)

type AccessType string

const AccessTypeOffline AccessType = "offline"
const AccessTypeOnline AccessType = "online"

type PromptType string

const PromptTypeNone PromptType = "none"
const PromptTypeLogin PromptType = "login"
const PromptTypeConsent PromptType = "consent"
const PromptTypeSelectAccount PromptType = "select_account"

type URLParam struct {
	Key   string `json:"key,omitempty"`
	Value string `json:"value,omitempty"`
}

type OutboundApp struct {
	ID                     string       `json:"id,omitempty"`
	Name                   string       `json:"name,omitempty"`
	Description            string       `json:"description,omitempty"`
	TemplateID             string       `json:"templateId,omitempty"`
	ClientID               string       `json:"clientId,omitempty"`
	Logo                   string       `json:"logo,omitempty"`
	DiscoveryURL           string       `json:"discoveryUrl,omitempty"`
	AuthorizationURL       string       `json:"authorizationUrl,omitempty"`
	AuthorizationURLParams []URLParam   `json:"authorizationUrlParams,omitempty"`
	TokenURL               string       `json:"tokenUrl,omitempty"`
	TokenURLParams         []URLParam   `json:"tokenUrlParams,omitempty"`
	RevocationURL          string       `json:"revocationUrl,omitempty"`
	DefaultScopes          []string     `json:"defaultScopes,omitempty"`
	DefaultRedirectURL     string       `json:"defaultRedirectUrl,omitempty"`
	CallbackDomain         string       `json:"callbackDomain,omitempty"`
	Pkce                   bool         `json:"pkce,omitempty"`
	AccessType             AccessType   `json:"accessType,omitempty"`
	Prompt                 []PromptType `json:"prompt,omitempty"`
}

type CreateOutboundAppRequest struct {
	OutboundApp
	ClientSecret string `json:"clientSecret,omitempty"`
}

// FetchOutboundAppUserTokenRequest represents a request to fetch an outbound app user token
type FetchOutboundAppUserTokenRequest struct {
	AppID    string                       `json:"appId"`
	UserID   string                       `json:"userId"`
	Scopes   []string                     `json:"scopes"`
	Options  *OutboundAppUserTokenOptions `json:"options,omitempty"`
	TenantID string                       `json:"tenantId,omitempty"`
}

// OutboundAppUserTokenOptions represents options for fetching a user token
type OutboundAppUserTokenOptions struct {
	WithRefreshToken bool `json:"withRefreshToken,omitempty"`
	ForceRefresh     bool `json:"forceRefresh,omitempty"`
}

// OutboundAppUserToken represents an outbound app user token
type OutboundAppUserToken struct {
	ID                string   `json:"id"`
	AppID             string   `json:"appId"`
	UserID            string   `json:"userId"`
	TokenSub          string   `json:"tokenSub"`
	AccessToken       string   `json:"accessToken"`
	AccessTokenType   string   `json:"accessTokenType"`
	AccessTokenExpiry string   `json:"accessTokenExpiry"`
	HasRefreshToken   bool     `json:"hasRefreshToken"`
	RefreshToken      string   `json:"refreshToken,omitempty"`
	LastRefreshTime   string   `json:"lastRefreshTime,omitempty"`
	LastRefreshError  string   `json:"lastRefreshError,omitempty"`
	Scopes            []string `json:"scopes"`
	TenantID          string   `json:"tenantId,omitempty"`
	GrantedBy         string   `json:"grantedBy,omitempty"`
}

// FetchOutboundAppUserTokenResponse represents the response from fetching a user token
type FetchOutboundAppUserTokenResponse struct {
	Token *OutboundAppUserToken `json:"token"`
}

type ThirdPartyApplicationScope struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Values      []string `json:"values"`
}

type IssuerSettings struct {
	JWKsURI             string `json:"jwksUri,omitempty"`
	SignAlgorithm       string `json:"signAlgorithm,omitempty"`
	UserInfoURI         string `json:"userInfoUri,omitempty"`
	ExternalIDFieldName string `json:"externalIdFieldName,omitempty"`
}

type JWTBearerSettings struct {
	Issuers map[string]*IssuerSettings `json:"issuers,omitempty"`
}

type ThirdPartyApplication struct {
	ID                   string                        `json:"id"`
	Name                 string                        `json:"name"`
	Description          string                        `json:"description"`
	Logo                 string                        `json:"logo"`
	LoginPageURL         string                        `json:"loginPageUrl"`
	ClientID             string                        `json:"clientId"`
	ApprovedCallbackUrls []string                      `json:"approvedCallbackUrls"`
	PermissionsScopes    []*ThirdPartyApplicationScope `json:"permissionsScopes"`
	AttributesScopes     []*ThirdPartyApplicationScope `json:"attributesScopes"`
	JWTBearerSettings    *JWTBearerSettings            `json:"jwtBearerSettings,omitempty"`
	CustomAttributes     map[string]any                `json:"customAttributes,omitempty"`
}

type ThirdPartyApplicationRequest struct {
	ID                   string                        `json:"id"`
	Name                 string                        `json:"name"`
	Description          string                        `json:"description"`
	Logo                 string                        `json:"logo"`
	LoginPageURL         string                        `json:"loginPageUrl"`
	ApprovedCallbackUrls []string                      `json:"approvedCallbackUrls"`
	PermissionsScopes    []*ThirdPartyApplicationScope `json:"permissionsScopes"`
	AttributesScopes     []*ThirdPartyApplicationScope `json:"attributesScopes"`
	JWTBearerSettings    *JWTBearerSettings            `json:"jwtBearerSettings,omitempty"`
	CustomAttributes     map[string]any                `json:"customAttributes,omitempty"`
}

// Options for loading third party applications
//
// Page - allows to paginate over the results. Pages start at 0 and must be non-negative.
// Limit - limits the number of returned applications. Leave at 0 to return the default amount.
type ThirdPartyApplicationSearchOptions struct {
	Page  int32 `json:"page"`
	Limit int32 `json:"limit"`
}

type ThirdPartyApplicationConsent struct {
	// Consent ID
	ID string `json:"id"`
	// Associated third party application ID
	AppID string `json:"appId"`
	// Associated user ID
	UserID string `json:"userId"`
	// Scopes granted by this user consent
	Scopes []string `json:"scopes"`
	// The user id the consent was granted by
	GrantedBy string `json:"grantedBy"`
	// The time the consent was granted in milliseconds since epoch
	CreatedTime int32 `json:"createdTime"`
	// The tenant id the consent was granted for
	TenantID string `json:"tenantId"`
	// The consent expiry time
	ExpireTime int32 `json:"expireTime,omitempty"`
	// The consent modified time in milliseconds since epoch
	ModifiedTime int32 `json:"modifiedTime,omitempty"`
}

// Options for deleting third party application consents. At least one of ConsentIDs, AppID or UserIDs must be provided.
//
// ConsentIDs - allows to delete any consents by their given id.
// AppID - allows to delete all consents by a given third party application id.
// UserID - allows to delete all consents of a given user by user id.
// TenantID - allows to delete all consents of a given tenant by tenant id.
type ThirdPartyApplicationConsentDeleteOptions struct {
	ConsentIDs []string `json:"consentIds"`
	AppID      string   `json:"appId"`
	UserIDs    []string `json:"userIds"`
	TenantID   string   `json:"tenantId"`
}

// Options for deleting third party application tenant level consents. At least one of ConsentIDs, AppID must be provided.
//
// ConsentIDs - allows to delete any consents by their given id.
// AppID - allows to delete all consents by a given third party application id.
// TenantID - allows to delete all consents of a given tenant by tenant id.
type ThirdPartyApplicationTenantConsentDeleteOptions struct {
	ConsentIDs []string `json:"consentIds"`
	AppID      string   `json:"appId"`
	TenantID   string   `json:"tenantId"`
}

// Options for searching and filtering third party application consents
//
// AppID - allows to filter consents by a given third party application id.
// UserID - allows to filter by a given user id.
// ConsentID - search a specific consent by id.
// Page - allows to paginate over the results. Pages start at 0 and must non-negative.
// TenantID - allows to filter by a given tenant id.
type ThirdPartyApplicationConsentSearchOptions struct {
	AppID     string `json:"appId"`
	UserID    string `json:"userId"`
	ConsentID string `json:"consentId"`
	Page      int32  `json:"page"`
	Limit     int32  `json:"limit"`
	TenantID  string `json:"tenantId"`
}

func (c *ThirdPartyApplicationConsent) GetCreatedTime() time.Time {
	return time.Unix(int64(c.CreatedTime), 0)
}

type MgmSignUpOptions struct {
	CustomClaims    map[string]any `json:"customClaims,omitempty"`
	RefreshDuration int32          `json:"refreshDuration,omitempty"`
}
type MgmLoginOptions struct {
	Stepup                   bool           `json:"stepup,omitempty"`
	MFA                      bool           `json:"mfa,omitempty"`
	RevokeOtherSessions      bool           `json:"revokeOtherSessions,omitempty"`
	RevokeOtherSessionsTypes []string       `json:"revokeOtherSessionsTypes,omitempty"`
	CustomClaims             map[string]any `json:"customClaims,omitempty"`
	JWT                      string         `json:"jwt,omitempty"`
	RefreshDuration          int32          `json:"refreshDuration,omitempty"`
}

func (mlo *MgmLoginOptions) IsJWTRequired() bool {
	return mlo != nil && (mlo.Stepup || mlo.MFA)
}

type MgmtUserRequest struct {
	User          `json:",inline"`
	EmailVerified bool   `json:"emailVerified"`
	PhoneVerified bool   `json:"phoneVerified"`
	SsoAppID      string `json:"ssoAppId"`
}

type MgmtFlowOptions struct {
	Input   map[string]any `json:"input,omitempty"`
	Preview bool           `json:"preview,omitempty"`
	Tenant  string         `json:"tenant,omitempty"`
}

type MgmtKeyStatus string

const (
	MgmtKeyActive   MgmtKeyStatus = "active"
	MgmtKeyInactive MgmtKeyStatus = "inactive"
)

type MgmtKey struct {
	ID           string        `json:"id,omitempty"`
	Name         string        `json:"name,omitempty"`
	Description  string        `json:"description,omitempty"`
	Status       MgmtKeyStatus `json:"status,omitempty"`
	CreatedTime  int64         `json:"createdTime,omitempty"`
	ExpireTime   int64         `json:"expireTime,omitempty"`
	PermittedIPs []string      `json:"permittedIps,omitempty"`
	ReBac        *MgmtKeyReBac `json:"reBac,omitempty"`
	Version      int64         `json:"version,omitempty"`
	AuthzVersion int64         `json:"authzVersion,omitempty"`
}

type MgmtKeyReBac struct {
	CompanyRoles []string              `json:"companyRoles,omitempty"`
	ProjectRoles []*MgmtKeyProjectRole `json:"projectRoles,omitempty"`
	TagRoles     []*MgmtKeyTagRole     `json:"tagRoles,omitempty"`
}

type MgmtKeyTagRole struct {
	Tags  []string `json:"tags,omitempty"`
	Roles []string `json:"roles,omitempty"`
}

type MgmtKeyProjectRole struct {
	ProjectIDs []string `json:"projectIds,omitempty"`
	Roles      []string `json:"roles,omitempty"`
}

type MgmtKeySearchOptions struct {
}

type DescoperRole string

const (
	DescoperRoleAdmin     DescoperRole = "admin"
	DescoperRoleDeveloper DescoperRole = "developer"
	DescoperRoleSupport   DescoperRole = "support"
	DescoperRoleAuditor   DescoperRole = "auditor"
)

type DescoperAttributes struct {
	DisplayName string `json:"displayName,omitempty"`
	Email       string `json:"email,omitempty"`
	Phone       string `json:"phone,omitempty"`
	// custom attributes are unsupported
}

type DescoperTagRole struct {
	Tags []string     `json:"tags,omitempty"`
	Role DescoperRole `json:"role,omitempty"`
}

type DescoperProjectRole struct {
	ProjectIDs []string     `json:"projectIds,omitempty"`
	Role       DescoperRole `json:"role,omitempty"`
}

type DescoperRBAC struct {
	IsCompanyAdmin bool                   `json:"isCompanyAdmin,omitempty"`
	Tags           []*DescoperTagRole     `json:"tags,omitempty"`
	Projects       []*DescoperProjectRole `json:"projects,omitempty"`
}

type Descoper struct {
	ID         string              `json:"id,omitempty"`
	LoginIDs   []string            `json:"loginIDs,omitempty"`
	Attributes *DescoperAttributes `json:"attributes,omitempty"`
	ReBac      *DescoperRBAC       `json:"rbac,omitempty"`
	Status     string              `json:"status,omitempty"`
}

type DescoperCreate struct {
	LoginID    string              `json:"loginId,omitempty"`
	Attributes *DescoperAttributes `json:"attributes,omitempty"`
	SendInvite bool                `json:"sendInvite,omitempty"`
	ReBac      *DescoperRBAC       `json:"rbac,omitempty"`
}

type DescoperLoadOptions struct {
}

type AccessKeysSearchOptions struct {
	Sort             []UserSearchSort `json:"sort,omitempty"`
	TenantIDs        []string         `json:"tenantIds,omitempty"`
	BoundUserID      *string          `json:"boundUserId,omitempty"`
	CreatingUser     *string          `json:"creatingUser,omitempty"`
	CustomAttributes map[string]any   `json:"customAttributes,omitempty"`
}

// List types

type ListType string

const (
	ListTypeTexts ListType = "texts"
	ListTypeIPs   ListType = "ips"
	ListTypeJSON  ListType = "json"
)

type List struct {
	ID          string   `json:"id,omitempty"`
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	Type        ListType `json:"type,omitempty"`
	Data        any      `json:"data,omitempty"`
}

type ListRequest struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Type        ListType `json:"type"`
	Data        any      `json:"data,omitempty"`
}

type ListUpdateRequest struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Type        ListType `json:"type"`
	Data        any      `json:"data,omitempty"`
}

type ListIDRequest struct {
	ID string `json:"id"`
}

type ListImportRequest struct {
	Lists []*List `json:"lists"`
}

type ListIPsRequest struct {
	ID  string   `json:"id"`
	IPs []string `json:"ips"`
}

type ListCheckIPRequest struct {
	ID string `json:"id"`
	IP string `json:"ip"`
}

type ListTextsRequest struct {
	ID    string   `json:"id"`
	Texts []string `json:"texts"`
}

type ListCheckTextRequest struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}
