package auth

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSignUpTOTP(t *testing.T) {
	externalID := "someID"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeSignUpTOTPURL(), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, externalID, body["externalID"])
		assert.EqualValues(t, "test", body["user"].(map[string]interface{})["externalID"])

		resp := &TOTPResponse{
			ProvisioningURL: "someurl.com",
			Image:           "image",
			Key:             "my key",
		}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	token, err := a.SignUpTOTP(externalID, &User{ExternalID: "test"})
	require.NoError(t, err)
	assert.NotNil(t, token)
}

func TestSignUpTOTPFailure(t *testing.T) {
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	_, err = a.SignUpTOTP("", &User{ExternalID: "test"})
	assert.Error(t, err)
}

func TestVerifyTOTP(t *testing.T) {
	externalID := "someID"
	code := "123456"
	a, err := newTestAuth(nil, func(r *http.Request) (*http.Response, error) {
		assert.EqualValues(t, composeVerifyTOTPCodeURL(), r.URL.RequestURI())

		body, err := readBodyMap(r)
		require.NoError(t, err)
		assert.EqualValues(t, externalID, body["externalID"])
		assert.EqualValues(t, code, body["code"])

		resp := &JWTResponse{
			JWTS: []string{jwtTokenValid},
			User: &User{
				ExternalID: externalID,
			},
			FirstSeen: true,
		}
		respBytes, err := utils.Marshal(resp)
		require.NoError(t, err)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBuffer(respBytes))}, nil
	})
	require.NoError(t, err)
	authInfo, err := a.VerifyTOTPCode(externalID, code, nil)
	require.NoError(t, err)
	assert.NotNil(t, authInfo)
	assert.True(t, authInfo.FirstSeen)
	assert.EqualValues(t, externalID, authInfo.User.ExternalID)
}

func TestVerifyTOTPFailure(t *testing.T) {
	a, err := newTestAuth(nil, nil)
	require.NoError(t, err)
	_, err = a.VerifyTOTPCode("", "code", nil)
	assert.Error(t, err)

}
