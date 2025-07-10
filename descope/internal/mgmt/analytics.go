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

type analytics struct {
	managementBase
}

var _ sdk.Analytics = &analytics{}

func (a *analytics) Search(ctx context.Context, options *descope.AnalyticsSearchOptions) ([]*descope.AnalyticRecord, error) {
	body := map[string]any{
		"actions":         options.Actions,
		"excludedActions": options.ExcludedActions,
		"from":            options.From.UnixMilli(),
		"to":              options.To.UnixMilli(),
		"devices":         options.Devices,
		"methods":         options.Methods,
		"geos":            options.Geos,
		"tenants":         options.Tenants,
		"groupByAction":   options.GroupByAction,
		"groupByDevice":   options.GroupByDevice,
		"groupByMethod":   options.GroupByMethod,
		"groupByGeo":      options.GroupByGeo,
		"groupByTenant":   options.GroupByTenant,
		"groupByReferrer": options.GroupByReferrer,
		"groupByCreated":  options.GroupByCreated,
	}
	res, err := a.client.DoPostRequest(ctx, api.Routes.ManagementAnalyticsSearch(), body, nil, a.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalAnalyticsRecords(res)
}

type apiAnalyticsRecord struct {
	ProjectID string `json:"projectId,omitempty"`
	Action    string `json:"action,omitempty"`
	Created   string `json:"created,omitempty"`
	Device    string `json:"device,omitempty"`
	Method    string `json:"method,omitempty"`
	Geo       string `json:"geo,omitempty"`
	Tenant    string `json:"tenant,omitempty"`
	Referrer  string `json:"referrer,omitempty"`
	Cnt       int64  `json:"cnt,omitempty"`
}

type apiSearchAnalyticsResponse struct {
	Analytics []*apiAnalyticsRecord `json:"analytics"`
}

func unmarshalAnalyticsRecords(res *api.HTTPResponse) ([]*descope.AnalyticRecord, error) {
	var aRes *apiSearchAnalyticsResponse
	err := utils.Unmarshal([]byte(res.BodyStr), &aRes)
	if err != nil {
		// notest
		return nil, err
	}
	var records []*descope.AnalyticRecord
	for _, rec := range aRes.Analytics {
		created, err := strconv.ParseInt(rec.Created, 10, 64)
		if err != nil {
			return nil, err
		}
		records = append(records, &descope.AnalyticRecord{
			ProjectID: rec.ProjectID,
			Action:    rec.Action,
			Created:   time.UnixMilli(created),
			Device:    rec.Device,
			Method:    rec.Method,
			Geo:       rec.Geo,
			Tenant:    rec.Tenant,
			Referrer:  rec.Referrer,
			Cnt:       int(rec.Cnt),
		})
	}
	return records, nil
}
