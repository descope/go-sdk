package mgmt

import (
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/tests/mocks"
)

func newTestMgmt(clientParams *api.ClientParams, callback mocks.Do) *managementService {
	return newTestMgmtConf(nil, clientParams, callback)
}

func newTestMgmtConf(mgmtParams *MgmtParams, clientParams *api.ClientParams, callback mocks.Do) *managementService {
	if clientParams == nil {
		clientParams = &api.ClientParams{ProjectID: "a"}
	}
	if mgmtParams == nil {
		mgmtParams = &MgmtParams{ProjectID: "a"}
	}
	clientParams.DefaultClient = mocks.NewTestClient(callback)
	return NewManagement(*mgmtParams, api.NewClient(*clientParams))
}
