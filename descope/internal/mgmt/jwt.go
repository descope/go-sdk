package mgmt

import (
	"context"

	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/sdk"
)

type jwt struct {
	managementBase
}

var _ sdk.JWT = &jwt{}

type jwtRes struct {
	JWT string `json:"jwt,omitempty"`
}

func (j *jwt) UpdateJWTWithCustomClaims(ctx context.Context, jwt string, customClaims map[string]any) (string, error) {
	if jwt == "" {
		return "", utils.NewInvalidArgumentError("jwt")
	}
	// customClaims can be nil, it will mean that this JWT will be validated, and updated authz data will be set
	req := map[string]any{
		"jwt":          jwt,
		"customClaims": customClaims,
	}
	res, err := j.client.DoPostRequest(ctx, api.Routes.ManagementUpdateJWT(), req, nil, j.conf.ManagementKey)
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

func (j *jwt) Impersonate(ctx context.Context, impersonatorID string, loginID string, validateConcent bool) (string, error) {
	if loginID == "" {
		return "", utils.NewInvalidArgumentError("loginID")
	}
	if impersonatorID == "" {
		return "", utils.NewInvalidArgumentError("impersonatorID")
	}
	req := map[string]any{
		"loginId":         loginID,
		"impersonatorId":  impersonatorID,
		"validateConsent": validateConcent,
	}
	res, err := j.client.DoPostRequest(ctx, api.Routes.ManagementImpersonate(), req, nil, j.conf.ManagementKey)
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
