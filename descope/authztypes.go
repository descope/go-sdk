package descope

type AuthzNodeExpressionType string

const (
	AuthzNodeExpressionTypeSelf          AuthzNodeExpressionType = "self"
	AuthzNodeExpressionTypeTargetSet     AuthzNodeExpressionType = "targetSet"
	AuthzNodeExpressionTypeRelationLeft  AuthzNodeExpressionType = "relationLeft"
	AuthzNodeExpressionTypeRelationRight AuthzNodeExpressionType = "relationRight"
)

type AuthzNodeType string

const (
	AuthzNodeTypeChild     AuthzNodeType = "child"
	AuthzNodeTypeUnion     AuthzNodeType = "union"
	AuthzNodeTypeIntersect AuthzNodeType = "intersect"
	AuthzNodeTypeSub       AuthzNodeType = "sub"
)

// AuthzNodeExpression holds the definition of a child node
type AuthzNodeExpression struct {
	NEType                            AuthzNodeExpressionType `json:"neType"`
	RelationDefinition                string                  `json:"relationDefinition,omitempty"`
	RelationDefinitionNamespace       string                  `json:"relationDefinitionNamespace,omitempty"`
	TargetRelationDefinition          string                  `json:"targetRelationDefinition,omitempty"`
	TargetRelationDefinitionNamespace string                  `json:"targetRelationDefinitionNamespace,omitempty"`
}

// AuthzNode holds the definition of a complex relation definition
type AuthzNode struct {
	NType      AuthzNodeType        `json:"nType"`
	Children   []*AuthzNode         `json:"children,omitempty"`
	Expression *AuthzNodeExpression `json:"expression,omitempty"`
}

// AuthzRelationDefinition defines a relation within a namespace
type AuthzRelationDefinition struct {
	Name              string     `json:"name"`
	ComplexDefinition *AuthzNode `json:"complexDefinition,omitempty"`
}

// AuthzNamespace defines an entity in the authorization schema
type AuthzNamespace struct {
	Name                string                     `json:"name"`
	RelationDefinitions []*AuthzRelationDefinition `json:"relationDefinitions"`
}

// AuthzSchema holds the full schema (all namespaces) for a project
type AuthzSchema struct {
	Name       string            `json:"name,omitempty"`
	Namespaces []*AuthzNamespace `json:"namespaces"`
}

// AuthzUserQuery represents a target of a relation for ABAC (query on users)
type AuthzUserQuery struct {
	Tenants          []string       `json:"tenants,omitempty"`
	Roles            []string       `json:"roles,omitempty"`
	Text             string         `json:"text,omitempty"`
	Statuses         []UserStatus   `json:"userStatus,omitempty"`
	SSOOnly          bool           `json:"ssoOnly"`
	WithTestUser     bool           `json:"withTestUser,omitempty"`
	CustomAttributes map[string]any `json:"customAttributes,omitempty"`
}

// AuthzRelation defines a relation between resource and target
type AuthzRelation struct {
	Resource                             string          `json:"resource"`
	RelationDefinition                   string          `json:"relationDefinition"`
	Namespace                            string          `json:"namespace"`
	Target                               string          `json:"target,omitempty"`
	TargetSetResource                    string          `json:"targetSetResource,omitempty"`
	TargetSetRelationDefinition          string          `json:"targetSetRelationDefinition,omitempty"`
	TargetSetRelationDefinitionNamespace string          `json:"targetSetRelationDefinitionNamespace,omitempty"`
	Query                                *AuthzUserQuery `json:"query,omitempty"`
}

// AuthzRelationQuery queries the service if a given relation exists
type AuthzRelationQuery struct {
	Resource           string `json:"resource"`
	RelationDefinition string `json:"relationDefinition"`
	Namespace          string `json:"namespace"`
	Target             string `json:"target"`
	HasRelation        bool   `json:"hasRelation"`
}

// AuthzModified resources and targets since given timestamp
type AuthzModified struct {
	Resources     []string `json:"resources"`
	Targets       []string `json:"targets"`
	SchemaChanged bool     `json:"schemaChanged"`
}

// FGA

// FGASchema holds the schema for a project
type FGASchema struct {
	Schema string `json:"schema"`
}

// FGARelation defines a relation between resource and target
type FGARelation struct {
	Resource     string `json:"resource"`
	ResourceType string `json:"resourceType"`
	Relation     string `json:"relation"`
	Target       string `json:"target"`
	TargetType   string `json:"targetType"`
}

// FGACheck holds the result of a check
type FGACheck struct {
	Allowed  bool          `json:"allowed"`
	Relation *FGARelation  `json:"relation"`
	Info     *FGACheckInfo `json:"info"`
}

type FGACheckInfo struct {
	// A relation is considered "direct" if, based solely on the schema, its "allowed" state can only be
	// changed by creating or deleting relations involving its resource, its target, or both (including itself)
	Direct bool `json:"direct,omitempty"`
}

type FGAMappableResourcesOptions struct {
	ResourcesLimit int32
}

type FGAMappableSchema struct {
	Schema            *AuthzSchema            `json:"schema,omitempty"`
	MappableResources []*FGAMappableResources `json:"mappableResources,omitempty"`
}

type FGAMappableResource struct {
	Resource string `json:"resource"`
}

type FGAMappableResources struct {
	Type      string                 `json:"type"`
	Resources []*FGAMappableResource `json:"resources"`
}

type FGAMappableResourcesQuery struct {
	Type    string   `json:"type"`
	Queries []string `json:"queries"`
}

type ResourceIdentifier struct {
	ResourceID   string `json:"resourceId"`
	ResourceType string `json:"resourceType"`
}

type ResourceDetails struct {
	ResourceID   string `json:"resourceId"`
	ResourceType string `json:"resourceType"`
	DisplayName  string `json:"displayName"`
}

type FGASchemaDryRunResponse struct {
	DeletesPreview *FGASchemaDryDeletes `json:"deletesPreview,omitempty"`
}

type FGASchemaDryDeletes struct {
	HasDeletes bool     `json:"hasDeletes"`
	Relations  []string `json:"relations,omitempty"`
	Types      []string `json:"types,omitempty"`
}
