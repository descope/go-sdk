package mgmt

import "github.com/descope/go-sdk/descope"

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

func makeAssociatedFamilyList(families []*descope.AssociatedFamily) []map[string]any {
	res := []map[string]any{}
	for _, af := range families {
		entry := map[string]any{"familyId": af.FamilyID}
		if af.Roles != nil {
			entry["roleNames"] = af.Roles
		}
		if af.FamilyScopedAttributes != nil {
			entry["familyScopedAttributes"] = af.FamilyScopedAttributes
		}
		res = append(res, entry)
	}
	return res
}
