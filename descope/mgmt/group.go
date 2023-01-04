package mgmt

import (
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/auth"
	"github.com/descope/go-sdk/descope/errors"
	"github.com/descope/go-sdk/descope/utils"
)

type group struct {
	managementBase
}

func (r *group) LoadAllGroups(tenantID string) ([]*auth.Group, error) {
	if tenantID == "" {
		return nil, errors.NewInvalidArgumentError("tenantID")
	}
	body := map[string]any{
		"tenantId": tenantID,
	}
	res, err := r.client.DoPostRequest(api.Routes.ManagementGroupLoadAllGroups(), body, nil, r.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalGroupsResponse(res)
}

func (r *group) LoadAllGroupsForMembers(tenantID string, userIDs, identifiers []string) ([]*auth.Group, error) {
	if tenantID == "" {
		return nil, errors.NewInvalidArgumentError("tenantID")
	}
	if len(userIDs) == 0 && len(identifiers) == 0 {
		return nil, errors.NewInvalidArgumentError("userIds and identifiers")
	}
	body := map[string]any{
		"tenantId":    tenantID,
		"identifiers": identifiers,
		"userIds":     userIDs,
	}
	res, err := r.client.DoPostRequest(api.Routes.ManagementGroupLoadAllGroupsForMember(), body, nil, r.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalGroupsResponse(res)
}

func (r *group) LoadAllGroupMembers(tenantID, groupID string) ([]*auth.Group, error) {
	if tenantID == "" {
		return nil, errors.NewInvalidArgumentError("tenantID")
	}
	if groupID == "" {
		return nil, errors.NewInvalidArgumentError("groupID")
	}
	body := map[string]any{
		"tenantId": tenantID,
		"groupId":  groupID,
	}
	res, err := r.client.DoPostRequest(api.Routes.ManagementGroupLoadAllGroupMembers(), body, nil, r.conf.ManagementKey)
	if err != nil {
		return nil, err
	}
	return unmarshalGroupsResponse(res)
}

func unmarshalGroupsResponse(res *api.HTTPResponse) ([]*auth.Group, error) {
	var groups []*auth.Group
	err := utils.Unmarshal([]byte(res.BodyStr), &groups)
	if err != nil {
		// notest
		return nil, err
	}
	return groups, nil
}
