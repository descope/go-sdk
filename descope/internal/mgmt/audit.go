package mgmt

import (
	"time"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
)

type audit struct {
	managementBase
}

func (a *audit) Search(options *descope.AuditSearchOptions) ([]*descope.AuditRecord, error) {
	body := map[string]any{
		"userIds":         options.UserIDs,
		"actions":         options.Actions,
		"excludedActions": options.ExcludedActions,
		"from":            options.From.UnixMilli(),
		"to":              options.To.UnixMilli(),
		"devices":         options.Devices,
		"methods":         options.Methods,
		"geos":            options.Geos,
		"remoteAddresses": options.RemoteAddresses,
		"externalIds":     options.LoginIDs,
		"tenants":         options.Tenants,
		"noTenants":       options.NoTenants,
		"text":            options.Text,
	}
	res, err := a.client.DoPostRequest(api.Routes.ManagementAuditSearch(), body, nil, a.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalAuditRecords(res)
}

type apiAuditRecord struct {
	ProjectID     string   `json:"projectId,omitempty"`
	UserID        string   `json:"userId,omitempty"`
	Action        string   `json:"action,omitempty"`
	Occurred      int64    `json:"occurred,omitempty"`
	Device        string   `json:"device,omitempty"`
	Method        string   `json:"method,omitempty"`
	Geo           string   `json:"geo,omitempty"`
	RemoteAddress string   `json:"remoteAddress,omitempty"`
	ExternalIDs   []string `json:"externalIds,omitempty"`
	Tenants       []string
	Data          map[string]interface{} `json:"data,omitempty"`
}

type apiSearchAuditResponse struct {
	Audits []*apiAuditRecord
}

func unmarshalAuditRecords(res *api.HTTPResponse) ([]*descope.AuditRecord, error) {
	var auditRes *apiSearchAuditResponse
	err := utils.Unmarshal([]byte(res.BodyStr), &auditRes)
	if err != nil {
		// notest
		return nil, err
	}
	var records []*descope.AuditRecord
	for _, rec := range auditRes.Audits {
		records = append(records, &descope.AuditRecord{
			ProjectID:     rec.ProjectID,
			UserID:        rec.UserID,
			Action:        rec.Action,
			Occurred:      time.UnixMilli(rec.Occurred),
			Device:        rec.Device,
			Method:        rec.Method,
			Geo:           rec.Geo,
			RemoteAddress: rec.RemoteAddress,
			LoginIDs:      rec.ExternalIDs,
			Tenants:       rec.Tenants,
			Data:          rec.Data,
		})
	}
	return records, nil
}
