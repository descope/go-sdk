package mgmt

import (
	"context"
	"strconv"
	"time"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/sdk"
)

type audit struct {
	managementBase
}

var _ sdk.Audit = &audit{}

func (a *audit) SearchAll(ctx context.Context, options *descope.AuditSearchOptions) ([]*descope.AuditRecord, int, error) {
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
		"size":            options.Limit,
		"page":            options.Page,
	}
	res, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAuditSearch(), body, nil, "")
	if err != nil {
		return nil, 0, err
	}
	return unmarshalAuditRecords(res)
}

// Deprecated: replaced by audit.SearchAll
func (a *audit) Search(ctx context.Context, options *descope.AuditSearchOptions) ([]*descope.AuditRecord, error) {
	records, _, err := a.SearchAll(ctx, options)
	return records, err
}

func (a *audit) CreateEvent(ctx context.Context, options *descope.AuditCreateOptions) error {
	if options.Action == "" {
		return utils.NewInvalidArgumentError("Action")
	}
	if options.TenantID == "" {
		return utils.NewInvalidArgumentError("TenantID")
	}
	if options.Type == "" || (options.Type != "info" && options.Type != "warn" && options.Type != "error") {
		return utils.NewInvalidArgumentError("Type")
	}
	if options.ActorID == "" {
		return utils.NewInvalidArgumentError("ActorID")
	}
	body := map[string]any{
		"userId":   options.UserID,
		"action":   options.Action,
		"type":     options.Type,
		"actorId":  options.ActorID,
		"data":     options.Data,
		"tenantId": options.TenantID,
	}
	_, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAuditCreate(), body, nil, "")
	if err != nil {
		return err
	}
	return nil
}

type apiAuditRecord struct {
	ProjectID     string   `json:"projectId,omitempty"`
	UserID        string   `json:"userId,omitempty"`
	Action        string   `json:"action,omitempty"`
	Type          string   `json:"type,omitempty"`
	ActorID       string   `json:"actorId,omitempty"`
	Occurred      string   `json:"occurred,omitempty"`
	Device        string   `json:"device,omitempty"`
	Method        string   `json:"method,omitempty"`
	Geo           string   `json:"geo,omitempty"`
	RemoteAddress string   `json:"remoteAddress,omitempty"`
	ExternalIDs   []string `json:"externalIds,omitempty"`
	Tenants       []string
	Data          map[string]any `json:"data,omitempty"`
}

type apiSearchAuditResponse struct {
	Audits []*apiAuditRecord
	Total  int
}

func unmarshalAuditRecords(res *api.HTTPResponse) ([]*descope.AuditRecord, int, error) {
	var auditRes *apiSearchAuditResponse
	err := utils.Unmarshal([]byte(res.BodyStr), &auditRes)
	if err != nil {
		// notest
		return nil, 0, err
	}
	var records []*descope.AuditRecord
	for _, rec := range auditRes.Audits {
		occurred, err := strconv.ParseInt(rec.Occurred, 10, 64)
		if err != nil {
			return nil, 0, err
		}
		records = append(records, &descope.AuditRecord{
			ProjectID:     rec.ProjectID,
			UserID:        rec.UserID,
			Action:        rec.Action,
			Occurred:      time.UnixMilli(occurred),
			Device:        rec.Device,
			Method:        rec.Method,
			Geo:           rec.Geo,
			RemoteAddress: rec.RemoteAddress,
			LoginIDs:      rec.ExternalIDs,
			Tenants:       rec.Tenants,
			Data:          rec.Data,
			ActorID:       rec.ActorID,
			Type:          rec.Type,
		})
	}
	return records, auditRes.Total, nil
}

func (a *audit) CreateAuditWebhook(ctx context.Context, options *descope.AuditWebhook) error {
	if options == nil {
		return utils.NewInvalidArgumentError("AuditWebhook")
	}
	if options.Name == "" {
		return utils.NewInvalidArgumentError("AuditWebhook.Name")
	}
	_, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAuditWebhookCreate(), options, nil, "")
	if err != nil {
		return err
	}
	return nil
}
