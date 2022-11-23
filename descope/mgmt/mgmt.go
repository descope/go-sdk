package mgmt

import (
	"github.com/descope/go-sdk/descope/api"
)

type MgmtParams struct {
	ProjectID string
}

type managementBase struct {
	client *api.Client
	conf   *MgmtParams
}

type managementService struct {
	managementBase

	tenant Tenant
	user   User
	sso    SSO
}

func NewManagement(conf MgmtParams, c *api.Client) *managementService {
	base := managementBase{conf: &conf, client: c}
	service := &managementService{managementBase: base}
	service.tenant = &tenant{managementBase: base}
	service.user = &user{managementBase: base}
	service.sso = &sso{managementBase: base}
	return service
}

func (mgmt *managementService) Tenant() Tenant {
	return mgmt.tenant
}

func (mgmt *managementService) User() User {
	return mgmt.user
}

func (mgmt *managementService) SSO() SSO {
	return mgmt.sso
}
