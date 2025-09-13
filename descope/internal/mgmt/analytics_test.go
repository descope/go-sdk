package mgmt

import (
	"context"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/tests/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAnalyticsSearch(t *testing.T) {
	called := false
	response := &apiSearchAnalyticsResponse{Analytics: []*apiAnalyticsRecord{
		{
			ProjectID: "p1",
			Action:    "a1",
			Created:   strconv.FormatInt(time.Now().AddDate(0, 0, -1).UnixMilli(), 10),
			Device:    "d1",
			Method:    "m1",
			Geo:       "US",
			Tenant:    "t1",
			Referrer:  "ref1",
			Cnt:       "5",
		},
		{
			ProjectID: "p1",
			Action:    "a1",
			Created:   strconv.FormatInt(time.Now().AddDate(0, 0, -1).UnixMilli(), 10),
			Device:    "d1",
			Method:    "m1",
			Geo:       "US",
			Tenant:    "t1",
			Referrer:  "ref1",
			Cnt:       "3",
		},
	}}
	searchOptions := &descope.AnalyticsSearchOptions{
		From:            time.Now().AddDate(0, 0, -30),
		To:              time.Now().AddDate(0, 0, 30),
		Actions:         []string{"a1", "a2"},
		ExcludedActions: []string{"a3"},
		Devices:         []string{"d1", "d2"},
		Methods:         []string{"m1", "m2"},
		Geos:            []string{"US"},
		Tenants:         []string{"t1"},
		GroupByAction:   true,
		GroupByDevice:   true,
		GroupByMethod:   true,
		GroupByGeo:      true,
		GroupByTenant:   true,
		GroupByReferrer: true,
		GroupByCreated:  "d",
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		called = true
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.EqualValues(t, []any{searchOptions.Actions[0], searchOptions.Actions[1]}, req["actions"])
		require.EqualValues(t, []any{searchOptions.ExcludedActions[0]}, req["excludedActions"])
		require.EqualValues(t, searchOptions.From.UnixMilli(), req["from"])
		require.EqualValues(t, searchOptions.To.UnixMilli(), req["to"])
		require.EqualValues(t, []any{searchOptions.Devices[0], searchOptions.Devices[1]}, req["devices"])
		require.EqualValues(t, []any{searchOptions.Methods[0], searchOptions.Methods[1]}, req["methods"])
		require.EqualValues(t, []any{searchOptions.Geos[0]}, req["geos"])
		require.EqualValues(t, []any{searchOptions.Tenants[0]}, req["tenants"])
		require.EqualValues(t, searchOptions.GroupByAction, req["groupByAction"])
		require.EqualValues(t, searchOptions.GroupByDevice, req["groupByDevice"])
		require.EqualValues(t, searchOptions.GroupByMethod, req["groupByMethod"])
		require.EqualValues(t, searchOptions.GroupByGeo, req["groupByGeo"])
		require.EqualValues(t, searchOptions.GroupByTenant, req["groupByTenant"])
		require.EqualValues(t, searchOptions.GroupByReferrer, req["groupByReferrer"])
		require.EqualValues(t, searchOptions.GroupByCreated, req["groupByCreated"])
	}, response))
	doAsserts := func(res []*descope.AnalyticRecord, err error) {
		require.NoError(t, err)
		require.Len(t, res, 2)
		assert.Equal(t, response.Analytics[0].ProjectID, res[0].ProjectID)
		assert.Equal(t, response.Analytics[0].Action, res[0].Action)
		assert.Equal(t, response.Analytics[0].Created, strconv.FormatInt(res[0].Created.UnixMilli(), 10))
		assert.Equal(t, response.Analytics[0].Device, res[0].Device)
		assert.Equal(t, response.Analytics[0].Method, res[0].Method)
		assert.Equal(t, response.Analytics[0].Geo, res[0].Geo)
		assert.Equal(t, response.Analytics[0].Tenant, res[0].Tenant)
		assert.Equal(t, response.Analytics[0].Referrer, res[0].Referrer)
		assert.Equal(t, response.Analytics[0].Cnt, strconv.FormatInt(int64(res[0].Cnt), 10))
		assert.True(t, called)
	}
	//run test for Deprecated Search API
	res, err := mgmt.Analytics().Search(context.Background(), searchOptions)
	doAsserts(res, err)
}
