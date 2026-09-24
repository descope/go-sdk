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
	for _, family := range families {
		entry := map[string]any{"familyId": family.FamilyID}
		if family.Roles != nil {
			entry["roleNames"] = family.Roles
		}
		if family.FamilyScopedAttributes != nil {
			entry["familyScopedAttributes"] = family.FamilyScopedAttributes
		}
		res = append(res, entry)
	}
	return res
}
