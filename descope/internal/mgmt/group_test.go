package mgmt

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/tests/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadAllGroupsSuccess(t *testing.T) {
	tenantID := "abc"
	response := []*descope.Group{
		{
			ID:      "some-id",
			Display: "some-display",
			Members: []descope.GroupMember{
				{
					LoginID: "some-loginID",
					UserID:  "some-userID",
					Display: "some-display",
					Source:  "jit",
				},
			},
		},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, tenantID, req["tenantId"])
		// no ssoId filter given: the field must be absent so the request stays compatible with
		// backends that reject unknown fields
		_, found := req["ssoId"]
		require.False(t, found)
	}, response))
	res, err := mgmt.Group().LoadAllGroups(context.Background(), tenantID)
	require.NoError(t, err)
	assert.EqualValues(t, response, res)
}

// The round-trip tests above marshal the SDK's own structs, so they pass whatever the json tags say.
// Decoding a literal server body is what actually pins the wire names.
func TestLoadAllGroupsDecodesServerFieldNames(t *testing.T) {
	body := json.RawMessage(`[{
		"id": "g1",
		"display": "Engineering",
		"source": "scim",
		"ssoId": "sso-1",
		"members": [
			{"loginId": "alice@example.com", "userId": "U1", "display": "Alice", "source": "jit"},
			{"loginId": "bob@example.com", "userId": "U2", "display": "Bob", "source": "scim"}
		]
	}]`)
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(nil, body))

	res, err := mgmt.Group().LoadAllGroups(context.Background(), "abc")
	require.NoError(t, err)
	require.Len(t, res, 1)
	assert.Equal(t, "g1", res[0].ID)
	assert.Equal(t, "scim", res[0].Source)
	require.Len(t, res[0].Members, 2)
	assert.Equal(t, "alice@example.com", res[0].Members[0].LoginID)
	assert.Equal(t, "U1", res[0].Members[0].UserID)
	// a JIT member inside a SCIM-owned group is the case this field exists for
	assert.Equal(t, "jit", res[0].Members[0].Source)
	assert.Equal(t, "scim", res[0].Members[1].Source)
}

func TestLoadAllGroupsWithSSOIDSuccess(t *testing.T) {
	tenantID := "abc"
	ssoID := "sso-config-1"
	response := []*descope.Group{
		{
			ID:      "some-id",
			Display: "some-display",
			Source:  "scim",
			SSOID:   ssoID,
		},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, tenantID, req["tenantId"])
		require.Equal(t, ssoID, req["ssoId"])
	}, response))
	res, err := mgmt.Group().LoadAllGroupsWithSSOID(context.Background(), tenantID, ssoID)
	require.NoError(t, err)
	assert.EqualValues(t, response, res)
}

func TestLoadAllGroupsWithSSOIDMissingArgument(t *testing.T) {
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.Group().LoadAllGroupsWithSSOID(context.Background(), "", "sso-config-1")
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("tenantID").Message)
	assert.Nil(t, res)
}

func TestLoadAllGroupsMissingArgument(t *testing.T) {
	tenantID := ""
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.Group().LoadAllGroups(context.Background(), tenantID)
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("tenantID").Message)
	assert.Nil(t, res)
}

func TestLoadAllGroupsError(t *testing.T) {
	tenantID := "abc"
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.Group().LoadAllGroups(context.Background(), tenantID)
	require.Error(t, err)
	assert.Nil(t, res)
}

func TestLoadAllGroupsForMembersSuccess(t *testing.T) {
	tenantID := "abc"
	userIDs := []string{"one", "two"}
	loginIDs := []string{"three", "four"}
	response := []*descope.Group{
		{
			ID:      "some-id",
			Display: "some-display",
			Members: []descope.GroupMember{
				{
					LoginID: "some-loginID",
					UserID:  "some-userIDs",
					Display: "some-display",
				},
			},
		},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, []any{"one", "two"}, req["userIds"])
		require.Equal(t, []any{"three", "four"}, req["loginIds"])
	}, response))
	res, err := mgmt.Group().LoadAllGroupsForMembers(context.Background(), tenantID, userIDs, loginIDs)
	require.NoError(t, err)
	assert.EqualValues(t, response, res)
}

func TestLoadAllGroupsForMembersWithSSOIDSuccess(t *testing.T) {
	tenantID := "abc"
	ssoID := "sso-config-1"
	userIDs := []string{"one", "two"}
	loginIDs := []string{"three", "four"}
	response := []*descope.Group{{ID: "some-id", Display: "some-display", SSOID: ssoID}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, []any{"one", "two"}, req["userIds"])
		require.Equal(t, []any{"three", "four"}, req["loginIds"])
		require.Equal(t, ssoID, req["ssoId"])
	}, response))
	res, err := mgmt.Group().LoadAllGroupsForMembersWithSSOID(context.Background(), tenantID, userIDs, loginIDs, ssoID)
	require.NoError(t, err)
	assert.EqualValues(t, response, res)
}

func TestLoadAllGroupsForMembersMissingArgumentUserIDs(t *testing.T) {
	tenantID := "abc"
	var userIDs []string
	var loginIDs []string
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.Group().LoadAllGroupsForMembers(context.Background(), tenantID, userIDs, loginIDs)
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("userIDs and loginIDs").Message)
	assert.Nil(t, res)
}

func TestLoadAllGroupsForMembersMissingArgumentTenantID(t *testing.T) {
	tenantID := ""
	userIDs := []string{"one", "two"}
	loginIDs := []string{"three", "four"}
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.Group().LoadAllGroupsForMembers(context.Background(), tenantID, userIDs, loginIDs)
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("tenantID").Message)
	assert.Nil(t, res)
}

func TestLoadAllGroupsForMembersError(t *testing.T) {
	tenantID := "abc"
	userIDs := []string{"one", "two"}
	loginIDs := []string{"three", "four"}
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.Group().LoadAllGroupsForMembers(context.Background(), tenantID, userIDs, loginIDs)
	require.Error(t, err)
	assert.Nil(t, res)
}

func TestLoadAllGroupMembersSuccess(t *testing.T) {
	tenantID := "abc"
	groupID := "abc"
	response := []*descope.Group{
		{
			ID:      "some-id",
			Display: "some-display",
			Members: []descope.GroupMember{
				{
					LoginID: "some-loginID",
					UserID:  "some-userIDs",
					Display: "some-display",
				},
			},
		},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, groupID, req["groupId"])
	}, response))
	res, err := mgmt.Group().LoadAllGroupMembers(context.Background(), tenantID, groupID)
	require.NoError(t, err)
	assert.EqualValues(t, response, res)
}

func TestLoadAllGroupMembersDecodesServerFieldNames(t *testing.T) {
	body := json.RawMessage(`[{"id":"g1","display":"Engineering","source":"scim",
		"members":[{"loginId":"alice@example.com","userId":"U1","display":"Alice","source":"jit"}]}]`)
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(nil, body))

	res, err := mgmt.Group().LoadAllGroupMembers(context.Background(), "abc", "g1")
	require.NoError(t, err)
	require.Len(t, res, 1)
	require.Len(t, res[0].Members, 1)
	assert.Equal(t, "alice@example.com", res[0].Members[0].LoginID)
	assert.Equal(t, "U1", res[0].Members[0].UserID)
	assert.Equal(t, "jit", res[0].Members[0].Source)
}

func TestLoadAllGroupMembersWithSSOIDSuccess(t *testing.T) {
	tenantID := "abc"
	groupID := "abc"
	ssoID := "sso-config-1"
	response := []*descope.Group{{ID: "some-id", Display: "some-display", SSOID: ssoID}}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, groupID, req["groupId"])
		require.Equal(t, ssoID, req["ssoId"])
	}, response))
	res, err := mgmt.Group().LoadAllGroupMembersWithSSOID(context.Background(), tenantID, groupID, ssoID)
	require.NoError(t, err)
	assert.EqualValues(t, response, res)
}

func TestLoadAllGroupMembersMissingArgument(t *testing.T) {
	tenantID := "abc"
	groupID := ""
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.Group().LoadAllGroupMembers(context.Background(), tenantID, groupID)
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("groupID").Message)
	assert.Nil(t, res)
}

func TestLoadAllGroupMembersMissingTenantID(t *testing.T) {
	tenantID := ""
	groupID := "abc"
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.Group().LoadAllGroupMembers(context.Background(), tenantID, groupID)
	require.ErrorContains(t, err, utils.NewInvalidArgumentError("tenantID").Message)
	assert.Nil(t, res)
}

func TestLoadAllGroupMembersError(t *testing.T) {
	tenantID := "abc"
	groupID := "abc"
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.Group().LoadAllGroupMembers(context.Background(), tenantID, groupID)
	require.Error(t, err)
	assert.Nil(t, res)
}
