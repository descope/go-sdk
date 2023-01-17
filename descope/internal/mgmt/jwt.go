package mgmt

import (
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/errors"
	"github.com/descope/go-sdk/descope/internal/utils"
)

type jwt struct {
	managementBase
}

type jwtRes struct {
	JWT string `json:"jwt,omitempty"`
}

func (j *jwt) UpdateJWTWithCustomClaims(jwt string, customClaims map[string]any) (string, error) {
	if jwt == "" {
		return "", errors.NewInvalidArgumentError("jwt")
	}
	// customClaims can be nil, it will mean that this JWT will be validated, and updated authz data will be set
	req := map[string]any{
		"jwt":          jwt,
		"customClaims": customClaims,
	}
	res, err := j.client.DoPostRequest(api.Routes.ManagementUpdateJWT(), req, nil, j.conf.ManagementKey)
	if err != nil {
		return "", err
	}
	jRes := &jwtRes{}
	err = utils.Unmarshal([]byte(res.BodyStr), jRes)
	if err != nil {
		return "", err //notest
	}
	return jRes.JWT, nil
}