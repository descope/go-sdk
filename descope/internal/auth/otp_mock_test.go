package auth_test

import (
	"context"
	"net/http"
	"os"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newMockOTPClient(t *testing.T) *client.DescopeClient {
	url := os.Getenv("DESCOPE_MOCK_URL")
	if url == "" {
		t.Skip("DESCOPE_MOCK_URL is not set")
	}
	c, err := client.NewWithConfig(&client.Config{ProjectID: "P2placeholder", ManagementKey: "test", DescopeBaseURL: url})
	require.NoError(t, err)
	return c
}

func mockRefreshRequest() *http.Request {
	r := &http.Request{Header: http.Header{}}
	r.AddCookie(&http.Cookie{Name: descope.RefreshCookieName, Value: "refresh-jwt-placeholder"})
	return r
}

func TestMockOTPSignUpIM(t *testing.T) {
	c := newMockOTPClient(t)
	masked, err := c.Auth.OTP().SignUp(context.Background(), descope.MethodIM, "+15555555555", &descope.User{Name: "name", Email: "test@example.com"}, &descope.SignUpOptions{
		CustomClaims:    map[string]any{"k": "v"},
		TemplateOptions: map[string]string{"t": "o"},
		TenantID:        "tenant",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, masked)
}

func TestMockOTPSignInIM(t *testing.T) {
	c := newMockOTPClient(t)
	masked, err := c.Auth.OTP().SignIn(context.Background(), descope.MethodIM, "+15555555555", mockRefreshRequest(), &descope.LoginOptions{
		Stepup:                   true,
		MFA:                      true,
		RevokeOtherSessions:      true,
		RevokeOtherSessionsTypes: []string{"web"},
		CustomClaims:             map[string]any{"k": "v"},
		TemplateOptions:          map[string]string{"t": "o"},
		TenantID:                 "tenant",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, masked)
}

func TestMockOTPSignUpOrInIM(t *testing.T) {
	c := newMockOTPClient(t)
	masked, err := c.Auth.OTP().SignUpOrIn(context.Background(), descope.MethodIM, "+15555555555", &descope.SignUpOptions{
		CustomClaims:    map[string]any{"k": "v"},
		TemplateOptions: map[string]string{"t": "o"},
		TenantID:        "tenant",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, masked)
}

func TestMockOTPUpdateUserPhoneIM(t *testing.T) {
	c := newMockOTPClient(t)
	masked, err := c.Auth.OTP().UpdateUserPhone(context.Background(), descope.MethodIM, "login-id", "+15555555555", &descope.UpdateOptions{
		AddToLoginIDs:      true,
		OnMergeUseExisting: true,
		TemplateOptions:    map[string]string{"t": "o"},
		ProviderID:         "provider",
		MFA:                true,
	}, mockRefreshRequest())
	require.NoError(t, err)
	assert.NotEmpty(t, masked)
}
