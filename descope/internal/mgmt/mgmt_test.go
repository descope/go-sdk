package mgmt

import (
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/auth"
	"github.com/descope/go-sdk/descope/tests/mocks"
)

const publicKey = `{"alg":"ES384","crv":"P-384","kid":"testkey","kty":"EC","use":"sig","x":"fcK-QcFhZooWoMPU2qIfkwBXfLIKkGm2plbS35jEQ53JqgnCaHDzLpyGaWWaIKfg","y":"IJS9pIQl3ZHh3GXi166DZgDieWGEypG9zaE3mEQrjgU-9F4qJWYDo4Fk0XS-ZJXr"}`

func newTestMgmt(clientParams *api.ClientParams, callback mocks.Do) *managementService {
	return newTestMgmtConf(nil, clientParams, callback)
}

func newTestMgmtConf(mgmtParams *ManagementParams, clientParams *api.ClientParams, callback mocks.Do) *managementService {
	if clientParams == nil {
		clientParams = &api.ClientParams{ProjectID: "a", ManagementKey: "key"}
	}
	if mgmtParams == nil {
		mgmtParams = &ManagementParams{ProjectID: "a"}
	}
	clientParams.DefaultClient = mocks.NewTestClient(callback)
	client := api.NewClient(*clientParams)
	return NewManagement(*mgmtParams, auth.NewProvider(client, &auth.AuthParams{ProjectID: clientParams.ProjectID, PublicKey: publicKey}), client)
}
