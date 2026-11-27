package mgmt

import (
	"context"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/sdk"
)

type mcpServer struct {
	managementBase
}

var _ sdk.MCPServer = &mcpServer{}

func (m *mcpServer) Create(ctx context.Context, server *descope.MCPServer) (*descope.MCPServer, error) {
	if server == nil {
		return nil, utils.NewInvalidArgumentError("server")
	}
	res, err := m.client.DoPostRequest(ctx, api.Routes.ManagementMCPServerCreate(), server, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalMCPServerResponse(res)
}

func (m *mcpServer) Update(ctx context.Context, server *descope.MCPServer) (*descope.MCPServer, error) {
	if server == nil {
		return nil, utils.NewInvalidArgumentError("server")
	}
	if server.ID == "" {
		return nil, utils.NewInvalidArgumentError("server.ID")
	}
	body := map[string]any{"server": server}
	res, err := m.client.DoPostRequest(ctx, api.Routes.ManagementMCPServerUpdate(), body, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalMCPServerResponse(res)
}

func (m *mcpServer) Delete(ctx context.Context, id string) error {
	if id == "" {
		return utils.NewInvalidArgumentError("id")
	}
	body := map[string]any{"id": id}
	_, err := m.client.DoPostRequest(ctx, api.Routes.ManagementMCPServerDelete(), body, nil, "")
	return err
}

func (m *mcpServer) DeleteBatch(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return utils.NewInvalidArgumentError("ids")
	}
	body := map[string]any{"ids": ids}
	_, err := m.client.DoPostRequest(ctx, api.Routes.ManagementMCPServersDelete(), body, nil, "")
	return err
}

func (m *mcpServer) Load(ctx context.Context, id string) (*descope.MCPServer, error) {
	if id == "" {
		return nil, utils.NewInvalidArgumentError("id")
	}
	body := map[string]any{"id": id}
	res, err := m.client.DoPostRequest(ctx, api.Routes.ManagementMCPServerLoad(), body, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalMCPServerResponse(res)
}

func (m *mcpServer) LoadAll(ctx context.Context) ([]*descope.MCPServer, error) {
	res, err := m.client.DoPostRequest(ctx, api.Routes.ManagementMCPServersLoadAll(), map[string]any{}, nil, "")
	if err != nil {
		return nil, err
	}
	lres := struct {
		Servers []*descope.MCPServer
	}{}
	if err := utils.Unmarshal([]byte(res.BodyStr), &lres); err != nil {
		return nil, err
	}
	return lres.Servers, nil
}

func (m *mcpServer) CreateClient(ctx context.Context, client *descope.MCPServerClientRequest) (*descope.MCPServerClientCreateResponse, error) {
	if client == nil {
		return nil, utils.NewInvalidArgumentError("client")
	}
	if client.MCPServerID == "" {
		return nil, utils.NewInvalidArgumentError("client.MCPServerID")
	}
	res, err := m.client.DoPostRequest(ctx, api.Routes.ManagementMCPServerClientCreate(), client, nil, "")
	if err != nil {
		return nil, err
	}
	cres := &descope.MCPServerClientCreateResponse{}
	if err := utils.Unmarshal([]byte(res.BodyStr), cres); err != nil {
		return nil, err
	}
	return cres, nil
}

func (m *mcpServer) UpdateClient(ctx context.Context, client *descope.MCPServerClientRequest) (*descope.MCPServerClient, error) {
	if client == nil {
		return nil, utils.NewInvalidArgumentError("client")
	}
	if client.ID == "" {
		return nil, utils.NewInvalidArgumentError("client.ID")
	}
	if client.MCPServerID == "" {
		return nil, utils.NewInvalidArgumentError("client.MCPServerID")
	}
	res, err := m.client.DoPostRequest(ctx, api.Routes.ManagementMCPServerClientUpdate(), client, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalMCPServerClientResponse(res)
}

func (m *mcpServer) DeleteClient(ctx context.Context, mcpServerID, id string) error {
	if mcpServerID == "" {
		return utils.NewInvalidArgumentError("mcpServerID")
	}
	if id == "" {
		return utils.NewInvalidArgumentError("id")
	}
	body := map[string]any{"id": id, "mcpServerId": mcpServerID}
	_, err := m.client.DoPostRequest(ctx, api.Routes.ManagementMCPServerClientDelete(), body, nil, "")
	return err
}

func (m *mcpServer) DeleteClients(ctx context.Context, mcpServerID string, ids []string) error {
	if mcpServerID == "" {
		return utils.NewInvalidArgumentError("mcpServerID")
	}
	if len(ids) == 0 {
		return utils.NewInvalidArgumentError("ids")
	}
	body := map[string]any{"ids": ids, "mcpServerId": mcpServerID}
	_, err := m.client.DoPostRequest(ctx, api.Routes.ManagementMCPServerClientsDelete(), body, nil, "")
	return err
}

func (m *mcpServer) LoadClient(ctx context.Context, mcpServerID, id, clientID string) (*descope.MCPServerClient, error) {
	if mcpServerID == "" {
		return nil, utils.NewInvalidArgumentError("mcpServerID")
	}
	if id == "" && clientID == "" {
		return nil, utils.NewInvalidArgumentError("id")
	}
	body := map[string]any{"id": id, "clientId": clientID, "mcpServerId": mcpServerID}
	res, err := m.client.DoPostRequest(ctx, api.Routes.ManagementMCPServerClientLoad(), body, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalMCPServerClientResponse(res)
}

func (m *mcpServer) GetClientSecret(ctx context.Context, mcpServerID, id string) (string, error) {
	if mcpServerID == "" {
		return "", utils.NewInvalidArgumentError("mcpServerID")
	}
	if id == "" {
		return "", utils.NewInvalidArgumentError("id")
	}
	body := map[string]any{"id": id, "mcpServerId": mcpServerID}
	res, err := m.client.DoPostRequest(ctx, api.Routes.ManagementMCPServerClientSecret(), body, nil, "")
	if err != nil {
		return "", err
	}
	return unmarshalMCPServerClientSecret(res)
}

func (m *mcpServer) RotateClientSecret(ctx context.Context, mcpServerID, id string) (string, error) {
	if mcpServerID == "" {
		return "", utils.NewInvalidArgumentError("mcpServerID")
	}
	if id == "" {
		return "", utils.NewInvalidArgumentError("id")
	}
	body := map[string]any{"id": id, "mcpServerId": mcpServerID}
	res, err := m.client.DoPostRequest(ctx, api.Routes.ManagementMCPServerClientSecretRotate(), body, nil, "")
	if err != nil {
		return "", err
	}
	return unmarshalMCPServerClientSecret(res)
}

func (m *mcpServer) SearchClients(ctx context.Context, options *descope.MCPServerClientSearchOptions) ([]*descope.MCPServerClient, int, error) {
	if options == nil {
		options = &descope.MCPServerClientSearchOptions{}
	}
	if options.MCPServerID == "" {
		return nil, 0, utils.NewInvalidArgumentError("options.MCPServerID")
	}
	res, err := m.client.DoPostRequest(ctx, api.Routes.ManagementMCPServerClientsSearch(), options, nil, "")
	if err != nil {
		return nil, 0, err
	}
	sres := struct {
		Clients []*descope.MCPServerClient
		Total   int
	}{}
	if err := utils.Unmarshal([]byte(res.BodyStr), &sres); err != nil {
		return nil, 0, err
	}
	return sres.Clients, sres.Total, nil
}

func unmarshalMCPServerResponse(res *api.HTTPResponse) (*descope.MCPServer, error) {
	sres := struct {
		Server *descope.MCPServer
	}{}
	if err := utils.Unmarshal([]byte(res.BodyStr), &sres); err != nil {
		return nil, err
	}
	return sres.Server, nil
}

func unmarshalMCPServerClientResponse(res *api.HTTPResponse) (*descope.MCPServerClient, error) {
	cres := struct {
		Client *descope.MCPServerClient
	}{}
	if err := utils.Unmarshal([]byte(res.BodyStr), &cres); err != nil {
		return nil, err
	}
	return cres.Client, nil
}

func unmarshalMCPServerClientSecret(res *api.HTTPResponse) (string, error) {
	sres := struct {
		Cleartext string
	}{}
	if err := utils.Unmarshal([]byte(res.BodyStr), &sres); err != nil {
		return "", err
	}
	return sres.Cleartext, nil
}
