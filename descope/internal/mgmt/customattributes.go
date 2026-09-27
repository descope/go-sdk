package mgmt

import (
	"context"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
)

// The user, family-scoped user and family custom attribute schemas share the same request and
// response shapes and differ only in their URLs.

func getCustomAttributes(ctx context.Context, client *api.Client, url string) ([]*descope.CustomAttribute, error) {
	res, err := client.DoGetRequest(ctx, url, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalCustomAttributesResponse(res)
}

func createCustomAttributes(ctx context.Context, client *api.Client, url string, attributes []*descope.CustomAttribute) ([]*descope.CustomAttribute, error) {
	if len(attributes) == 0 {
		return nil, utils.NewInvalidArgumentError("attributes")
	}
	res, err := client.DoPostRequest(ctx, url, map[string]any{"attributes": attributes}, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalCustomAttributesResponse(res)
}

func deleteCustomAttributes(ctx context.Context, client *api.Client, url string, names []string) ([]*descope.CustomAttribute, error) {
	if len(names) == 0 {
		return nil, utils.NewInvalidArgumentError("names")
	}
	res, err := client.DoPostRequest(ctx, url, map[string]any{"names": names}, nil, "")
	if err != nil {
		return nil, err
	}
	return unmarshalCustomAttributesResponse(res)
}

func unmarshalCustomAttributesResponse(res *api.HTTPResponse) ([]*descope.CustomAttribute, error) {
	cres := struct {
		Data []*descope.CustomAttribute
	}{}
	err := utils.Unmarshal([]byte(res.BodyStr), &cres)
	if err != nil {
		return nil, err
	}
	return cres.Data, nil
}
