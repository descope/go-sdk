package mgmt

import (
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope/auth"
	"github.com/descope/go-sdk/descope/errors"
	"github.com/descope/go-sdk/descope/tests/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadAllGroupsSuccess(t *testing.T) {
	tenantID := "abc"
	response := []*auth.Group{
		{
			ID:      "some-id",
			Display: "some-display",
			Members: []auth.GroupMember{
				{
					Identifier: "some-identifier",
					JwtSubject: "some-jwtSubject",
					Display:    "some-display",
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
	res, err := mgmt.Group().LoadAllGroups(tenantID)
	require.NoError(t, err)
	assert.EqualValues(t, response, res)
}

func TestLoadAllGroupsMissingArgument(t *testing.T) {
	tenantID := ""
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.Group().LoadAllGroups(tenantID)
	require.ErrorContains(t, err, errors.NewInvalidArgumentError("tenantID").Message)
	assert.Nil(t, res)
}

func TestLoadAllGroupsError(t *testing.T) {
	tenantID := "abc"
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.Group().LoadAllGroups(tenantID)
	require.Error(t, err)
	assert.Nil(t, res)
}

func TestLoadAllGroupsForMembersSuccess(t *testing.T) {
	tenantID := "abc"
	jwtSubjects := []string{"one", "two"}
	identifiers := []string{"three", "four"}
	response := []*auth.Group{
		{
			ID:      "some-id",
			Display: "some-display",
			Members: []auth.GroupMember{
				{
					Identifier: "some-identifier",
					JwtSubject: "some-jwtSubject",
					Display:    "some-display",
				},
			},
		},
	}
	mgmt := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
		require.Equal(t, r.Header.Get("Authorization"), "Bearer a:key")
		req := map[string]any{}
		require.NoError(t, helpers.ReadBody(r, &req))
		require.Equal(t, []interface{}{"one", "two"}, req["userIds"])
		require.Equal(t, []interface{}{"three", "four"}, req["externalIds"])
	}, response))
	res, err := mgmt.Group().LoadAllGroupsForMembers(tenantID, jwtSubjects, identifiers)
	require.NoError(t, err)
	assert.EqualValues(t, response, res)
}

func TestLoadAllGroupsForMembersMissingArgumentJwtSubjects(t *testing.T) {
	tenantID := "abc"
	var jwtSubjects []string
	var identifiers []string
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.Group().LoadAllGroupsForMembers(tenantID, jwtSubjects, identifiers)
	require.ErrorContains(t, err, errors.NewInvalidArgumentError("jwtSubjects and identifiers").Message)
	assert.Nil(t, res)
}

func TestLoadAllGroupsForMembersMissingArgumentTenantID(t *testing.T) {
	tenantID := ""
	jwtSubjects := []string{"one", "two"}
	identifiers := []string{"three", "four"}
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.Group().LoadAllGroupsForMembers(tenantID, jwtSubjects, identifiers)
	require.ErrorContains(t, err, errors.NewInvalidArgumentError("tenantID").Message)
	assert.Nil(t, res)
}

func TestLoadAllGroupsForMembersError(t *testing.T) {
	tenantID := "abc"
	jwtSubjects := []string{"one", "two"}
	identifiers := []string{"three", "four"}
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.Group().LoadAllGroupsForMembers(tenantID, jwtSubjects, identifiers)
	require.Error(t, err)
	assert.Nil(t, res)
}

func TestLoadAllGroupMembersSuccess(t *testing.T) {
	tenantID := "abc"
	groupID := "abc"
	response := []*auth.Group{
		{
			ID:      "some-id",
			Display: "some-display",
			Members: []auth.GroupMember{
				{
					Identifier: "some-identifier",
					JwtSubject: "some-jwtSubject",
					Display:    "some-display",
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
	res, err := mgmt.Group().LoadAllGroupMembers(tenantID, groupID)
	require.NoError(t, err)
	assert.EqualValues(t, response, res)
}

func TestLoadAllGroupMembersMissingArgument(t *testing.T) {
	tenantID := "abc"
	groupID := ""
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.Group().LoadAllGroupMembers(tenantID, groupID)
	require.ErrorContains(t, err, errors.NewInvalidArgumentError("groupID").Message)
	assert.Nil(t, res)
}

func TestLoadAllGroupMembersMissingTenantID(t *testing.T) {
	tenantID := ""
	groupID := "abc"
	mgmt := newTestMgmt(nil, helpers.DoOk(nil))
	res, err := mgmt.Group().LoadAllGroupMembers(tenantID, groupID)
	require.ErrorContains(t, err, errors.NewInvalidArgumentError("tenantID").Message)
	assert.Nil(t, res)
}

func TestLoadAllGroupMembersError(t *testing.T) {
	tenantID := "abc"
	groupID := "abc"
	mgmt := newTestMgmt(nil, helpers.DoBadRequest(nil))
	res, err := mgmt.Group().LoadAllGroupMembers(tenantID, groupID)
	require.Error(t, err)
	assert.Nil(t, res)
}
