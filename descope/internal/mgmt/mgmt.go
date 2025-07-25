package mgmt

import (
	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/auth"
	"github.com/descope/go-sdk/descope/logger"
	"github.com/descope/go-sdk/descope/sdk"
)

type ManagementParams struct {
	ProjectID     string
	ManagementKey string
	FGACacheURL   string
}

type managementBase struct {
	client *api.Client
	conf   *ManagementParams
}

type managementService struct {
	managementBase

	tenant                sdk.Tenant
	ssoApplication        sdk.SSOApplication
	user                  sdk.User
	accessKey             sdk.AccessKey
	sso                   sdk.SSO
	password              sdk.PasswordManagement
	jwt                   sdk.JWT
	permission            sdk.Permission
	role                  sdk.Role
	group                 sdk.Group
	flow                  sdk.Flow
	project               sdk.Project
	audit                 sdk.Audit
	analytics             sdk.Analytics
	authz                 sdk.Authz
	fga                   sdk.FGA
	thirdPartyApplication sdk.ThirdPartyApplication
	outboundApplication   sdk.OutboundApplication
}

func NewManagement(conf ManagementParams, provider *auth.Provider, c *api.Client) *managementService {
	base := managementBase{conf: &conf, client: c}
	service := &managementService{managementBase: base}
	service.tenant = &tenant{managementBase: base}
	service.ssoApplication = &ssoApplication{managementBase: base}
	service.thirdPartyApplication = &thirdPartyApplication{managementBase: base}
	service.outboundApplication = &outboundApplication{managementBase: base}
	service.user = &user{managementBase: base}
	service.accessKey = &accessKey{managementBase: base}
	service.sso = &sso{managementBase: base}
	service.jwt = &jwt{managementBase: base, provider: provider}
	service.permission = &permission{managementBase: base}
	service.role = &role{managementBase: base}
	service.group = &group{managementBase: base}
	service.flow = &flow{managementBase: base}
	service.project = &project{managementBase: base}
	service.audit = &audit{managementBase: base}
	service.authz = &authz{managementBase: base}
	service.password = &passwordManagement{managementBase: base}
	service.fga = &fga{managementBase: base, fgaCacheURL: conf.FGACacheURL}
	service.analytics = &analytics{managementBase: base}
	return service
}

func (mgmt *managementService) Tenant() sdk.Tenant {
	mgmt.ensureManagementKey()
	return mgmt.tenant
}

func (mgmt *managementService) SSOApplication() sdk.SSOApplication {
	mgmt.ensureManagementKey()
	return mgmt.ssoApplication
}

func (mgmt *managementService) User() sdk.User {
	mgmt.ensureManagementKey()
	return mgmt.user
}

func (mgmt *managementService) AccessKey() sdk.AccessKey {
	mgmt.ensureManagementKey()
	return mgmt.accessKey
}

func (mgmt *managementService) SSO() sdk.SSO {
	mgmt.ensureManagementKey()
	return mgmt.sso
}

func (mgmt *managementService) Password() sdk.PasswordManagement {
	mgmt.ensureManagementKey()
	return mgmt.password
}

func (mgmt *managementService) JWT() sdk.JWT {
	mgmt.ensureManagementKey()
	return mgmt.jwt
}

func (mgmt *managementService) Permission() sdk.Permission {
	mgmt.ensureManagementKey()
	return mgmt.permission
}

func (mgmt *managementService) Role() sdk.Role {
	mgmt.ensureManagementKey()
	return mgmt.role
}

func (mgmt *managementService) Group() sdk.Group {
	mgmt.ensureManagementKey()
	return mgmt.group
}

func (mgmt *managementService) Flow() sdk.Flow {
	mgmt.ensureManagementKey()
	return mgmt.flow
}

func (mgmt *managementService) Project() sdk.Project {
	mgmt.ensureManagementKey()
	return mgmt.project
}

func (mgmt *managementService) Audit() sdk.Audit {
	mgmt.ensureManagementKey()
	return mgmt.audit
}

func (mgmt *managementService) Analytics() sdk.Analytics {
	mgmt.ensureManagementKey()
	return mgmt.analytics
}

func (mgmt *managementService) Authz() sdk.Authz {
	mgmt.ensureManagementKey()
	return mgmt.authz
}

func (mgmt *managementService) FGA() sdk.FGA {
	mgmt.ensureManagementKey()
	return mgmt.fga
}

func (mgmt *managementService) ThirdPartyApplication() sdk.ThirdPartyApplication {
	mgmt.ensureManagementKey()
	return mgmt.thirdPartyApplication
}

func (mgmt *managementService) OutboundApplication() sdk.OutboundApplication {
	mgmt.ensureManagementKey()
	return mgmt.outboundApplication
}

func (mgmt *managementService) ensureManagementKey() {
	if mgmt.conf.ManagementKey == "" {
		logger.LogInfo("Management key is missing, make sure to add it in the Config struct or the environment variable \"%s\"", descope.EnvironmentVariableManagementKey) // notest
	}
}
