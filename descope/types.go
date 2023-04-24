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

type User struct {
	Name  string `json:"name,omitempty"`
	Phone string `json:"phone,omitempty"`
	Email string `json:"email,omitempty"`
}

type UserRequest struct {
	User             `json:",inline"`
	Roles            []string            `json:"roles,omitempty"`
	Tenants          []*AssociatedTenant `json:"tenants,omitempty"`
	CustomAttributes map[string]any      `json:"customAttributes,omitempty"`
}

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
}

func (ur *UserResponse) GetCreatedTime() time.Time {
	return time.Unix(int64(ur.CreatedTime), 0)
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
}

// Represents a tenant association for a User or an Access Key. The tenant ID is required
// to denote which tenant the user / access key belongs to. Roles is an optional list of
// roles for the user / access key in this specific tenant.
type AssociatedTenant struct {
	TenantID string   `json:"tenantId"`
	Roles    []string `json:"roleNames,omitempty"`
}

// Represents a mapping between a set of groups of users and a role that will be assigned to them.
type RoleMapping struct {
	Groups []string
	Role   string
}

// Represents a mapping between Descope and IDP user attributes
type AttributeMapping struct {
	Name        string `json:"name,omitempty"`
	Email       string `json:"email,omitempty"`
	PhoneNumber string `json:"phoneNumber,omitempty"`
	Group       string `json:"group,omitempty"`
}

type Tenant struct {
	ID                      string   `json:"id"`
	Name                    string   `json:"name"`
	SelfProvisioningDomains []string `json:"selfProvisioningDomains"`
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
	Limit            int32
	Page             int32
	WithTestUsers    bool
	TestUsersOnly    bool
	CustomAttributes map[string]any
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
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	DSL         any    `json:"dsl"`
	Disabled    bool   `json:"disabled"`
	ETag        string `json:"etag,omitempty"`
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

type Theme struct {
	ID          string `json:"id"`
	CSSTemplate any    `json:"cssTemplate,omitempty"`
}

type DeliveryMethod string

type OAuthProvider string

type ContextKey string

const (
	MethodWhatsApp DeliveryMethod = "whatsapp"
	MethodSMS      DeliveryMethod = "sms"
	MethodEmail    DeliveryMethod = "email"

	OAuthFacebook  OAuthProvider = "facebook"
	OAuthGithub    OAuthProvider = "github"
	OAuthGoogle    OAuthProvider = "google"
	OAuthMicrosoft OAuthProvider = "microsoft"
	OAuthGitlab    OAuthProvider = "gitlab"
	OAuthApple     OAuthProvider = "apple"

	SessionCookieName = "DS"
	RefreshCookieName = "DSR"

	RedirectLocationCookieName = "Location"

	ContextUserIDProperty               = "DESCOPE_USER_ID"
	ContextUserIDPropertyKey ContextKey = ContextUserIDProperty
	ClaimAuthorizedTenants              = "tenants"

	EnvironmentVariableProjectID     = "DESCOPE_PROJECT_ID"
	EnvironmentVariablePublicKey     = "DESCOPE_PUBLIC_KEY"
	EnvironmentVariableManagementKey = "DESCOPE_MANAGEMENT_KEY"
)
