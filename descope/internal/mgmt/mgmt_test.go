package mgmt

import (
	"github.com/descope/go-sdk/v2/descope/api"
	"github.com/descope/go-sdk/v2/descope/tests/mocks"
)

func newTestMgmt(clientParams *api.ClientParams, callback mocks.Do) *managementService {
	return newTestMgmtConf(nil, clientParams, callback)
}

func newTestMgmtConf(mgmtParams *ManagementParams, clientParams *api.ClientParams, callback mocks.Do) *managementService {
	if clientParams == nil {
		clientParams = &api.ClientParams{ProjectID: "a"}
	}
	if mgmtParams == nil {
		mgmtParams = &ManagementParams{ProjectID: "a", ManagementKey: "key"}
	}
	clientParams.DefaultClient = mocks.NewTestClient(callback)
	return NewManagement(*mgmtParams, api.NewClient(*clientParams))
}
