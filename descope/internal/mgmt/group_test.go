package mgmt

import (
	"context"
	"net/http"
	"testing"

	"github.com/descope/go-sdk/v2/descope"
	"github.com/descope/go-sdk/v2/descope/internal/utils"
	"github.com/descope/go-sdk/v2/descope/tests/helpers"
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
				},
			},
		},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, tenantID, req["tenantId"])
	}, response))
	res, err := mgmt.Group().LoadAllGroups(context.Background(), tenantID)
	require.NoError(t, err)
	assert.EqualValues(t, response, res)
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
		require.Equal(t, []interface{}{"one", "two"}, req["userIds"])
		require.Equal(t, []interface{}{"three", "four"}, req["loginIds"])
	}, response))
	res, err := mgmt.Group().LoadAllGroupsForMembers(context.Background(), tenantID, userIDs, loginIDs)
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
