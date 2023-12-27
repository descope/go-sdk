package descope

import (
	"strings"
	"time"

	"github.com/descope/go-sdk/descope/logger"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"golang.org/x/exp/maps"
)

// TOTPResponse - returns all relevant data to complete a TOTP registration
// One can select which method of registration to use for handshaking with an Authenticator app
type TOTPResponse struct {
	ProvisioningURL string `json:"provisioningURL,omitempty"`
	Image           string `json:"image,omitempty"`
	Key             string `json:"key,omitempty"`
}

type AuthenticationInfo struct {
	SessionToken *Token        `json:"token,omitempty"`
	RefreshToken *Token        `json:"refreshToken,omitempty"`
	User         *UserResponse `json:"user,omitempty"`
	FirstSeen    bool          `json:"firstSeen,omitempty"`
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

type PasswordSettingsResponse struct {
	Enabled               bool   `protobuf:"varint,1,opt,name=enabled,proto3" json:"enabled,omitempty"`
	MinLength             int32  `protobuf:"varint,4,opt,name=minLength,proto3" json:"minLength,omitempty"`
	Lowercase             bool   `protobuf:"varint,5,opt,name=lowercase,proto3" json:"lowercase,omitempty"`
	Uppercase             bool   `protobuf:"varint,6,opt,name=uppercase,proto3" json:"uppercase,omitempty"`
	Number                bool   `protobuf:"varint,7,opt,name=number,proto3" json:"number,omitempty"`
	NonAlphanumeric       bool   `protobuf:"varint,8,opt,name=nonAlphanumeric,proto3" json:"nonAlphanumeric,omitempty"`
	Expiration            bool   `protobuf:"varint,9,opt,name=expiration,proto3" json:"expiration,omitempty"`
	ExpirationWeeks       int32  `protobuf:"varint,10,opt,name=expirationWeeks,proto3" json:"expirationWeeks,omitempty"`
	Reuse                 bool   `protobuf:"varint,11,opt,name=reuse,proto3" json:"reuse,omitempty"`
	ReuseAmount           int32  `protobuf:"varint,12,opt,name=reuseAmount,proto3" json:"reuseAmount,omitempty"`
	Lock                  bool   `protobuf:"varint,13,opt,name=lock,proto3" json:"lock,omitempty"`
	LockAttempts          int32  `protobuf:"varint,14,opt,name=lockAttempts,proto3" json:"lockAttempts,omitempty"`
	EmailServiceProvider  string `protobuf:"bytes,15,opt,name=emailServiceProvider,proto3" json:"emailServiceProvider,omitempty"` // must be type:providerID or Descope
	EmailSubject          string `protobuf:"bytes,16,opt,name=emailSubject,proto3" json:"emailSubject,omitempty"`                 // (optional as for Descope provider it will be set our defaults)
	EmailBody             string `protobuf:"bytes,17,opt,name=emailBody,proto3" json:"emailBody,omitempty"`                       // 1 * 1024 * 1024 = 1048576 = 1MB (optional as for Descope provider it will be set our defaults)
	ResetAuthMethod       string `protobuf:"bytes,18,opt,name=resetAuthMethod,proto3" json:"resetAuthMethod,omitempty"`
	EmailBodyPlainText    string `protobuf:"bytes,19,opt,name=emailBodyPlainText,proto3" json:"emailBodyPlainText,omitempty"` // 1 * 1024 * 1024 = 1048576 = 1MB (optional as for Descope provider it will be set our defaults)
	UseEmailBodyPlainText bool   `protobuf:"varint,20,opt,name=useEmailBodyPlainText,proto3" json:"useEmailBodyPlainText,omitempty"`
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
	RefreshExpiration int64                  `json:"refreshExpiration,omitempty"`
	Expiration        int64                  `json:"expiration,omitempty"`
	JWT               string                 `json:"jwt,omitempty"`
	ID                string                 `json:"id,omitempty"`
	ProjectID         string                 `json:"projectId,omitempty"`
	Claims            map[string]interface{} `json:"claims,omitempty"`
}

func (to *Token) GetTenants() []string {
	tenants := to.getTenants()
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

func (to *Token) CustomClaim(value string) interface{} {
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
		factorsArr, ok := factors.([]interface{})
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
	Stepup       bool                   `json:"stepup,omitempty"`
	MFA          bool                   `json:"mfa,omitempty"`
	CustomClaims map[string]interface{} `json:"customClaims,omitempty"`
}

func (lo *LoginOptions) IsJWTRequired() bool {
	return lo != nil && (lo.Stepup || lo.MFA)
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

	return &Token{
		JWT:        JWT,
		ID:         token.Subject(),
		ProjectID:  projectID,
		Expiration: token.Expiration().Unix(),
		Claims:     token.PrivateClaims(),
	}
}

type InviteOptions struct {
	InviteURL string `json:"inviteUrl,omitempty"`
	SendMail  *bool  `json:"sendMail,omitempty"` // send invite via mail, default is according to project settings
	SendSMS   *bool  `json:"sendSMS,omitempty"`  // send invite via text message, default is according to project settings
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
}

type BatchUser struct {
	LoginID     string             `json:"loginId,omitempty"`
	Password    *BatchUserPassword `json:"password,omitempty"`
	UserRequest `json:",inline"`
}

type BatchUserPassword struct {
	Cleartext string
	Hashed    *BatchUserPasswordHashed
}

type BatchUserPasswordHashed struct {
	Algorithm  BatchUserPasswordAlgorithm
	Hash       []byte
	Salt       []byte
	Iterations int
}

type BatchUserPasswordAlgorithm string

const (
	BatchUserPasswordAlgorithmBcrypt       BatchUserPasswordAlgorithm = "bcrypt"
	BatchUserPasswordAlgorithmPBKDF2SHA1   BatchUserPasswordAlgorithm = "pbkdf2sha1"
	BatchUserPasswordAlgorithmPBKDF2SHA256 BatchUserPasswordAlgorithm = "pbkdf2sha256"
	BatchUserPasswordAlgorithmPBKDF2SHA512 BatchUserPasswordAlgorithm = "pbkdf2sha512"
)

type UserResponse struct {
	User             `json:",inline"`
	UserID           string              `json:"userId,omitempty"`
	LoginIDs         []string            `json:"loginIds,omitempty"`
	VerifiedEmail    bool                `json:"verifiedEmail,omitempty"`
	VerifiedPhone    bool                `json:"verifiedPhone,omitempty"`
	RoleNames        []string            `json:"roleNames,omitempty"`
	UserTenants      []*AssociatedTenant `json:"userTenants,omitempty"`
	Status           string              `json:"status,omitempty"`
	Picture          string              `json:"picture,omitempty"`
	Test             bool                `json:"test,omitempty"`
	CustomAttributes map[string]any      `json:"customAttributes,omitempty"`
	CreatedTime      int32               `json:"createdTime,omitempty"`
	TOTP             bool                `json:"totp,omitempty"`
	WebAuthn         bool                `json:"webauthn,omitempty"`
	Password         bool                `json:"password,omitempty"`
	SAML             bool                `json:"saml,omitempty"`
	OAuth            map[string]bool     `json:"oauth,omitempty"`
}

type UsersFailedResponse struct {
	Failure string        `json:"failure,omitempty"`
	User    *UserResponse `json:"user,omitempty"`
}

type UsersBatchResponse struct {
	CreatedUsers []*UserResponse        `json:"createdUsers,omitempty"`
	FailedUsers  []*UsersFailedResponse `json:"failedUsers,omitempty"`
}

func (ur *UserResponse) GetCreatedTime() time.Time {
	return time.Unix(int64(ur.CreatedTime), 0)
}

type ProviderTokenResponse struct {
	Provider       string   `json:"provider,omitempty"`
	ProviderUserID string   `json:"providerUserID,omitempty"`
	AccessToken    string   `json:"accessToken,omitempty"`
	Expiration     uint32   `json:"expiration,omitempty"`
	Scopes         []string `json:"scopes,omitempty"`
}

type UpdateOptions struct {
	AddToLoginIDs      bool `json:"addToLoginIDs,omitempty"`
	OnMergeUseExisting bool `json:"onMergeUseExisting,omitempty"`
}

type AccessKeyResponse struct {
	ID          string              `json:"id,omitempty"`
	Name        string              `json:"name,omitempty"`
	RoleNames   []string            `json:"roleNames,omitempty"`
	KeyTenants  []*AssociatedTenant `json:"keyTenants,omitempty"`
	Status      string              `json:"status,omitempty"`
	CreatedTime int32               `json:"createdTime,omitempty"`
	ExpireTime  int32               `json:"expireTime,omitempty"`
	CreatedBy   string              `json:"createdBy,omitempty"`
	ClientID    string              `json:"clientId,omitempty"`
}

// Represents a tenant association for a User or an Access Key. The tenant ID is required
// to denote which tenant the user / access key belongs to. Roles is an optional list of
// roles for the user / access key in this specific tenant.
type AssociatedTenant struct {
	TenantID   string   `json:"tenantId"`
	TenantName string   `json:"tenantName"`
	Roles      []string `json:"roleNames,omitempty"`
}

// Represents a mapping between a set of groups of users and a role that will be assigned to them.
type RoleMapping struct {
	Groups []string
	Role   string
}

// Represents a mapping between Descope and IDP user attributes
type AttributeMapping struct {
	Name        string `json:"name,omitempty"`
	GivenName   string `json:"givenName,omitempty"`
	MiddleName  string `json:"middleName,omitempty"`
	FamilyName  string `json:"familyName,omitempty"`
	Picture     string `json:"picture,omitempty"`
	Email       string `json:"email,omitempty"`
	PhoneNumber string `json:"phoneNumber,omitempty"`
	Group       string `json:"group,omitempty"`
}

type Tenant struct {
	ID                      string         `json:"id"`
	Name                    string         `json:"name"`
	SelfProvisioningDomains []string       `json:"selfProvisioningDomains"`
	CustomAttributes        map[string]any `json:"customAttributes,omitempty"`
}

type TenantRequest struct {
	Name                    string         `json:"name"`
	SelfProvisioningDomains []string       `json:"selfProvisioningDomains"`
	CustomAttributes        map[string]any `json:"customAttributes,omitempty"`
}

type TenantSearchOptions struct {
	IDs                     []string
	Names                   []string
	SelfProvisioningDomains []string
	CustomAttributes        map[string]any
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
}

func (r *Role) GetCreatedTime() time.Time {
	return time.Unix(int64(r.CreatedTime), 0)
}

// Options for searching and filtering users
//
// The TenantIDs parameter is an optional array of tenant IDs to filter by.
//
// The roles parameter is an optional array of role names to filter by.
//
// The limit parameter limits the number of returned users. Leave at 0 to return the
// default amount.
//
// The page parameter allow to paginate over the results. Pages start at 0 and must non-negative.
//
// The customAttributes map is an optional filter for custom attributes
// where the keys are the attribute names and the values are either a value we are searching for or list of these values in a slice.
// We currently support string, int and bool values
type UserSearchOptions struct {
	TenantIDs        []string
	Roles            []string
	Statuses         []UserStatus
	Limit            int32
	Page             int32
	WithTestUsers    bool
	TestUsersOnly    bool
	CustomAttributes map[string]any
	Emails           []string
	Phones           []string
}

type UserStatus string

const (
	UserStatusEnabled  UserStatus = "enabled"
	UserStatusDisabled UserStatus = "disabled"
	UserStatusInvited  UserStatus = "invited"
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

type Flow struct {
	FlowMetadata
	DSL  any    `json:"dsl"`
	ETag string `json:"etag,omitempty"`
}

type FlowMetadata struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Disabled    bool   `json:"disabled"`
}

type Screen struct {
	ID           string `json:"id"`
	FlowID       string `json:"flowId"`
	Inputs       any    `json:"inputs,omitempty"`
	Interactions any    `json:"interactions,omitempty"`
	HTMLTemplate any    `json:"htmlTemplate"`
}

type FlowResponse struct {
	Flow    *Flow     `json:"flow"`
	Screens []*Screen `json:"screens"`
}

type FlowsResponse struct {
	Flows []*FlowMetadata `json:"flows"`
	Total int             `json:"total"`
}

type Theme struct {
	ID          string `json:"id"`
	CSSTemplate any    `json:"cssTemplate,omitempty"`
}

type AuditRecord struct {
	ProjectID     string    `json:"projectId,omitempty"`
	UserID        string    `json:"userId,omitempty"`
	Action        string    `json:"action,omitempty"`
	Occurred      time.Time `json:"occurred,omitempty"`
	Device        string    `json:"device,omitempty"`
	Method        string    `json:"method,omitempty"`
	Geo           string    `json:"geo,omitempty"`
	RemoteAddress string    `json:"remoteAddress,omitempty"`
	LoginIDs      []string  `json:"loginIds,omitempty"`
	Tenants       []string
	Data          map[string]interface{} `json:"data,omitempty"`
}

// AuditSearchOptions to filter which audits we should retrieve.
// All parameters are optional.
// `From` is currently limited to 30 days
type AuditSearchOptions struct {
	UserIDs         []string  `json:"userIds,omitempty"`         // List of user IDs to filter by
	Actions         []string  `json:"actions,omitempty"`         // List of actions to filter by
	ExcludedActions []string  `json:"excludedActions"`           // List of actions to exclude
	From            time.Time `json:"from,omitempty"`            // Retrieve records newer than given time. Limited to no older than 30 days.
	To              time.Time `json:"to,omitempty"`              // Retrieve records older than given time.
	Devices         []string  `json:"devices,omitempty"`         // List of devices to filter by. Current devices supported are "Bot"/"Mobile"/"Desktop"/"Tablet"/"Unknown"
	Methods         []string  `json:"methods,omitempty"`         // List of methods to filter by. Current auth methods are "otp"/"totp"/"magiclink"/"oauth"/"saml"/"password"
	Geos            []string  `json:"geos,omitempty"`            // List of geos to filter by. Geo is currently country code like "US", "IL", etc.
	RemoteAddresses []string  `json:"remoteAddresses,omitempty"` // List of remote addresses to filter by
	LoginIDs        []string  `json:"loginIds,omitempty"`        // List of login IDs to filter by
	Tenants         []string  `json:"tenants"`                   // List of tenants to filter by
	NoTenants       bool      `json:"noTenants"`                 // Should audits without any tenants always be included
	Text            string    `json:"text"`                      // Free text search across all fields
}

type NewProjectResponse struct {
	ProjectID                string         `json:"projectId"`
	ProjectName              string         `json:"projectName"`
	ProjectSettingsWeb       map[string]any `json:"projectSettingsWeb"`
	AuthMethodsMagicLink     map[string]any `json:"authMethodsMagicLink"`
	AuthMethodsOTP           map[string]any `json:"authMethodsOTP"`
	AuthMethodsSAML          map[string]any `json:"authMethodsSAML"`
	AuthMethodsOAuth         map[string]any `json:"authMethodsOAuth"`
	AuthMethodsWebAuthn      map[string]any `json:"authMethodsWebAuthn"`
	AuthMethodsTOTP          map[string]any `json:"authMethodsTOTP"`
	MessagingProvidersWeb    map[string]any `json:"messagingProvidersWeb"`
	AuthMethodsEnchantedLink map[string]any `json:"authMethodsEnchantedLink"`
	AuthMethodsPassword      map[string]any `json:"authMethodsPassword"`
	AuthMethodsOIDCIDP       map[string]any `json:"authMethodsOIDCIDP"`
	AuthMethodsEmbeddedLink  map[string]any `json:"authMethodsEmbeddedLink"`
	Tag                      string         `json:"tag"`
}

type DeliveryMethod string

type OAuthProvider string

type ContextKey string

type ProjectTag string

const (
	MethodWhatsApp DeliveryMethod = "whatsapp"
	MethodSMS      DeliveryMethod = "sms"
	MethodEmail    DeliveryMethod = "email"
	MethodEmbedded DeliveryMethod = "Embedded"

	OAuthFacebook  OAuthProvider = "facebook"
	OAuthGithub    OAuthProvider = "github"
	OAuthGoogle    OAuthProvider = "google"
	OAuthMicrosoft OAuthProvider = "microsoft"
	OAuthGitlab    OAuthProvider = "gitlab"
	OAuthApple     OAuthProvider = "apple"

	ProjectTagNone       ProjectTag = ""
	ProjectTagProduction ProjectTag = "production"

	SessionCookieName = "DS"
	RefreshCookieName = "DSR"

	RedirectLocationCookieName = "Location"

	ContextUserIDProperty                       = "DESCOPE_USER_ID"
	ContextUserIDPropertyKey         ContextKey = ContextUserIDProperty
	ClaimAuthorizedTenants                      = "tenants"
	ClaimAuthorizedGlobalPermissions            = "permissions"

	EnvironmentVariableProjectID     = "DESCOPE_PROJECT_ID"
	EnvironmentVariablePublicKey     = "DESCOPE_PUBLIC_KEY"
	EnvironmentVariableManagementKey = "DESCOPE_MANAGEMENT_KEY"
	EnvironmentVariableBaseURL       = "DESCOPE_BASE_URL"
)
