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

func TestAuditSearch(t *testing.T) {
	response := &apiSearchAuditResponse{Audits: []*apiAuditRecord{
		{
			ProjectID:     "p1",
			UserID:        "u1",
			Action:        "a1",
			Occurred:      strconv.FormatInt(time.Now().AddDate(0, 0, -1).UnixMilli(), 10),
			Device:        "d1",
			Method:        "m1",
			Geo:           "US",
			RemoteAddress: "1.1.1.1",
			ExternalIDs:   []string{"id1", "id2"},
			Tenants:       []string{"t1"},
			Data:          map[string]interface{}{"x": "y", "z": 1},
		},
		{
			ProjectID:     "p1",
			UserID:        "u2",
			Action:        "a2",
			Occurred:      strconv.FormatInt(time.Now().AddDate(0, 0, -1).UnixMilli(), 10),
			Device:        "d2",
			Method:        "m2",
			Geo:           "US",
			RemoteAddress: "1.1.1.1",
			ExternalIDs:   []string{"id3", "id4"},
			Tenants:       []string{"t1"},
			Data:          map[string]interface{}{"x": "y1", "z": 2},
		},
	}}
	searchOptions := &descope.AuditSearchOptions{
		UserIDs:         []string{"u1", "u2"},
		Actions:         []string{"a1", "a2"},
		ExcludedActions: []string{"a3"},
		From:            time.Now().AddDate(0, 0, -30),
		Devices:         []string{"d1", "d2"},
		Methods:         []string{"m1", "m2"},
		Geos:            []string{"US"},
		RemoteAddresses: []string{"1.1.1.1"},
		LoginIDs:        []string{"id1", "id3"},
		Tenants:         []string{"t1"},
		NoTenants:       true,
		Text:            "kuku",
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.EqualValues(t, []interface{}{searchOptions.UserIDs[0], searchOptions.UserIDs[1]}, req["userIds"])
		require.EqualValues(t, []interface{}{searchOptions.Actions[0], searchOptions.Actions[1]}, req["actions"])
		require.EqualValues(t, []interface{}{searchOptions.ExcludedActions[0]}, req["excludedActions"])
		require.EqualValues(t, searchOptions.From.UnixMilli(), req["from"])
		require.True(t, time.UnixMilli(int64(req["to"].(float64))).IsZero())
		require.EqualValues(t, []interface{}{searchOptions.Devices[0], searchOptions.Devices[1]}, req["devices"])
		require.EqualValues(t, []interface{}{searchOptions.Methods[0], searchOptions.Methods[1]}, req["methods"])
		require.EqualValues(t, []interface{}{searchOptions.Geos[0]}, req["geos"])
		require.EqualValues(t, []interface{}{searchOptions.RemoteAddresses[0]}, req["remoteAddresses"])
		require.EqualValues(t, []interface{}{searchOptions.LoginIDs[0], searchOptions.LoginIDs[1]}, req["externalIds"])
		require.EqualValues(t, []interface{}{searchOptions.Tenants[0]}, req["tenants"])
		require.EqualValues(t, searchOptions.NoTenants, req["noTenants"])
		require.EqualValues(t, searchOptions.Text, req["text"])
	}, response))
	res, err := mgmt.Audit().Search(context.Background(), searchOptions)
	require.NoError(t, err)
	require.Len(t, res, 2)
	assert.Equal(t, response.Audits[0].ProjectID, res[0].ProjectID)
	assert.Equal(t, response.Audits[0].UserID, res[0].UserID)
	assert.Equal(t, response.Audits[0].Action, res[0].Action)
	assert.Equal(t, response.Audits[0].Occurred, strconv.FormatInt(res[0].Occurred.UnixMilli(), 10))
	assert.Equal(t, response.Audits[0].Device, res[0].Device)
	assert.Equal(t, response.Audits[0].Method, res[0].Method)
	assert.Equal(t, response.Audits[0].Geo, res[0].Geo)
	assert.Equal(t, response.Audits[0].RemoteAddress, res[0].RemoteAddress)
	assert.EqualValues(t, response.Audits[0].ExternalIDs, res[0].LoginIDs)
	assert.EqualValues(t, response.Audits[0].Tenants, res[0].Tenants)
	assert.EqualValues(t, response.Audits[0].Data["x"], res[0].Data["x"])
}
