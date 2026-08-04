package mgmt

import (
	"context"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/sdk"
)

type group struct {
	managementBase
}

var _ sdk.Group = &group{}

func (r *group) LoadAllGroups(ctx context.Context, tenantID string) ([]*descope.Group, error) {
	return r.LoadAllGroupsWithSSOID(ctx, tenantID, "")
}

func (r *group) LoadAllGroupsWithSSOID(ctx context.Context, tenantID, ssoID string) ([]*descope.Group, error) {
	if tenantID == "" {
		return nil, utils.NewInvalidArgumentError("tenantID")
	}
	body := map[string]any{
		"tenantId": tenantID,
	}
	addSSOIDToGroupRequest(body, ssoID)
	res, err := r.client.DoPostRequest(ctx, api.Routes.ManagementGroupLoadAllGroups(), body, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalGroupsResponse(res)
}

func (r *group) LoadAllGroupsForMembers(ctx context.Context, tenantID string, userIDs, loginIDs []string) ([]*descope.Group, error) {
	return r.LoadAllGroupsForMembersWithSSOID(ctx, tenantID, userIDs, loginIDs, "")
}

func (r *group) LoadAllGroupsForMembersWithSSOID(ctx context.Context, tenantID string, userIDs, loginIDs []string, ssoID string) ([]*descope.Group, error) {
	if tenantID == "" {
		return nil, utils.NewInvalidArgumentError("tenantID")
	}
	if len(userIDs) == 0 && len(loginIDs) == 0 {
		return nil, utils.NewInvalidArgumentError("userIDs and loginIDs")
	}
	body := map[string]any{
		"tenantId": tenantID,
		"loginIds": loginIDs,
		"userIds":  userIDs,
	}
	addSSOIDToGroupRequest(body, ssoID)
	res, err := r.client.DoPostRequest(ctx, api.Routes.ManagementGroupLoadAllGroupsForMember(), body, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalGroupsResponse(res)
}

func (r *group) LoadAllGroupMembers(ctx context.Context, tenantID, groupID string) ([]*descope.Group, error) {
	return r.LoadAllGroupMembersWithSSOID(ctx, tenantID, groupID, "")
}

func (r *group) LoadAllGroupMembersWithSSOID(ctx context.Context, tenantID, groupID, ssoID string) ([]*descope.Group, error) {
	if tenantID == "" {
		return nil, utils.NewInvalidArgumentError("tenantID")
	}
	if groupID == "" {
		return nil, utils.NewInvalidArgumentError("groupID")
	}
	body := map[string]any{
		"tenantId": tenantID,
		"groupId":  groupID,
	}
	addSSOIDToGroupRequest(body, ssoID)
	res, err := r.client.DoPostRequest(ctx, api.Routes.ManagementGroupLoadAllGroupMembers(), body, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalGroupsResponse(res)
}

// addSSOIDToGroupRequest sets the ssoId filter only when one was given: the management gateway
// rejects unknown request fields, so omitting it keeps the unfiltered methods compatible with
// backends that predate the ssoId filter.
func addSSOIDToGroupRequest(body map[string]any, ssoID string) {
	if ssoID != "" {
		body["ssoId"] = ssoID
	}
}

func unmarshalGroupsResponse(res *api.HTTPResponse) ([]*descope.Group, error) {
	var groups []*descope.Group
	err := utils.Unmarshal([]byte(res.BodyStr), &groups)
	if err != nil {
		// notest
		return nil, err
	}
	return groups, nil
}
