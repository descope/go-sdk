package mgmt

import "github.com/descope/go-sdk/v2/descope"

func makeAssociatedTenantList(tenants []*descope.AssociatedTenant) []map[string]any {
	res := []map[string]any{}
	for _, tenant := range tenants {
		res = append(res, map[string]any{
			"tenantId":  tenant.TenantID,
			"roleNames": tenant.Roles,
		})
	}
	return res
}
