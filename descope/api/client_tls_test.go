package api

import (
	"crypto/tls"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTLSEnforcement tests that TLS 1.2+ is enforced by default
func TestTLSEnforcement(t *testing.T) {
	t.Run("DefaultTLS12", func(t *testing.T) {
		c := NewClient(ClientParams{ProjectID: "test"})

		// Extract the transport and verify TLS config
		httpClient, ok := c.httpClient.(*http.Client)
		require.True(t, ok, "httpClient should be *http.Client")

		transport, ok := httpClient.Transport.(*http.Transport)
		require.True(t, ok, "Transport should be *http.Transport")
		require.NotNil(t, transport.TLSClientConfig, "TLS config should not be nil")

		// Verify TLS 1.2 is the minimum version
		assert.Equal(t, uint16(tls.VersionTLS12), transport.TLSClientConfig.MinVersion,
			"Default minimum TLS version should be TLS 1.2")
	})

	t.Run("CustomTLSVersion", func(t *testing.T) {
		c := NewClient(ClientParams{
			ProjectID:     "test",
			MinTLSVersion: tls.VersionTLS13,
		})

		httpClient, ok := c.httpClient.(*http.Client)
		require.True(t, ok)

		transport, ok := httpClient.Transport.(*http.Transport)
		require.True(t, ok)
		require.NotNil(t, transport.TLSClientConfig)

		// Verify custom TLS version is set
		assert.Equal(t, uint16(tls.VersionTLS13), transport.TLSClientConfig.MinVersion,
			"Custom minimum TLS version should be TLS 1.3")
	})

	t.Run("InsecureTLSWithWarning", func(t *testing.T) {
		// Test that insecure TLS versions below 1.2 are allowed but warned about
		c := NewClient(ClientParams{
			ProjectID:     "test",
			MinTLSVersion: tls.VersionTLS11,
		})

		httpClient, ok := c.httpClient.(*http.Client)
		require.True(t, ok)

		transport, ok := httpClient.Transport.(*http.Transport)
		require.True(t, ok)
		require.NotNil(t, transport.TLSClientConfig)

		// Verify insecure TLS version is set (for testing/debugging only)
		assert.Equal(t, uint16(tls.VersionTLS11), transport.TLSClientConfig.MinVersion,
			"Insecure TLS version should be allowed for testing/debugging")

		// Note: The warning is logged via logger.LogInfo, which is tested separately
	})

	t.Run("TLSConfigNilCreation", func(t *testing.T) {
		// Verify that TLS config is created even when nil
		c := NewClient(ClientParams{ProjectID: "test"})

		httpClient, ok := c.httpClient.(*http.Client)
		require.True(t, ok)

		transport, ok := httpClient.Transport.(*http.Transport)
		require.True(t, ok)

		// TLS config should be created automatically
		assert.NotNil(t, transport.TLSClientConfig, "TLS config should be created automatically")
	})

	t.Run("CertificateVerificationWithTLS", func(t *testing.T) {
		c := NewClient(ClientParams{
			ProjectID:         "test",
			CertificateVerify: CertificateVerifyAlways,
			MinTLSVersion:     tls.VersionTLS12,
		})

		httpClient, ok := c.httpClient.(*http.Client)
		require.True(t, ok)

		transport, ok := httpClient.Transport.(*http.Transport)
		require.True(t, ok)
		require.NotNil(t, transport.TLSClientConfig)

		// Verify both certificate verification and TLS version are set
		assert.False(t, transport.TLSClientConfig.InsecureSkipVerify,
			"Certificate verification should be enabled")
		assert.Equal(t, uint16(tls.VersionTLS12), transport.TLSClientConfig.MinVersion,
			"TLS 1.2 should be enforced")
	})

	t.Run("CustomClientNotModified", func(t *testing.T) {
		// When a custom client is provided, it should not be modified
		customClient := &http.Client{
			Timeout: 0,
		}

		c := NewClient(ClientParams{
			ProjectID:     "test",
			DefaultClient: customClient,
			MinTLSVersion: tls.VersionTLS13,
		})

		// The custom client should be used as-is
		assert.Equal(t, customClient, c.httpClient,
			"Custom client should be used without modification")
	})
}
