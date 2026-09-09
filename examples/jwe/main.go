// Command jwe is an end-to-end sample that proves the Go SDK can validate an *encrypted* (JWE)
// session token.
//
// It provisions a test user and OTP via the Descope CLI (descopecli), enables project-level JWT
// encryption via the management API (the CLI has no JWE command yet), signs the user in to obtain
// a real 5-part JWE session token, and then validates it through the patched go-sdk — which
// decrypts it with the configured private key before verifying the inner signed JWS.
//
// Usage:
//
//	go run . --project-id P2... --mgmt-key K... [--base-url https://api.descope.org] [--test-user a@b.com]
//
// The management key may also be supplied via DESCOPE_MANAGEMENT_KEY. Secrets are never hard-coded.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/client"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type config struct {
	projectID  string
	mgmtKey    string
	baseURL    string
	testUser   string
	descopeCLI string
}

func loadConfig() config {
	var c config
	flag.StringVar(&c.projectID, "project-id", "", "Descope project ID (e.g. P2...) [required]")
	flag.StringVar(&c.mgmtKey, "mgmt-key", "", "Descope management key (or set DESCOPE_MANAGEMENT_KEY) [required]")
	flag.StringVar(&c.baseURL, "base-url", "https://api.descope.org", "Descope API base URL")
	flag.StringVar(&c.testUser, "test-user", "jwe-sdk-test@example.com", "Test user login ID (email)")
	flag.StringVar(&c.descopeCLI, "descope-cli", "descope", "Path to the descopecli binary")
	flag.Parse()

	if c.mgmtKey == "" {
		c.mgmtKey = os.Getenv(descope.EnvironmentVariableManagementKey)
	}
	if c.projectID == "" || c.mgmtKey == "" {
		fmt.Fprintln(os.Stderr, "error: --project-id and --mgmt-key (or DESCOPE_MANAGEMENT_KEY) are required")
		flag.Usage()
		os.Exit(2)
	}
	c.baseURL = strings.TrimRight(c.baseURL, "/")
	return c
}

func main() {
	cfg := loadConfig()
	ctx := context.Background()

	fmt.Printf("== JWE SDK validation sample ==\n  project:  %s\n  base URL: %s\n  user:     %s\n\n",
		cfg.projectID, cfg.baseURL, cfg.testUser)

	// 1. Generate the recipient (this app's) encryption keypair. The public half is uploaded to
	//    Descope; the private half is handed to the SDK to decrypt incoming session tokens.
	step("Generating RSA-2048 encryption keypair")
	pubJWK, privJWK := mustGenerateEncryptionKeypair()

	// 2. Provision the test user + OTP via descopecli (its native domain).
	step("Creating test user via descopecli")
	mustRunCLI(cfg, "user", "test", "create", cfg.testUser)

	// 3. Enable project-level JWE via the management API (descopecli has no JWE command).
	step("Uploading encryption public key + enabling JWE (management API)")
	must("upload public key", mgmtUpdateJWE(cfg, map[string]any{"publicKey": pubJWK}))
	must("enable JWE", mgmtUpdateJWE(cfg, map[string]any{"enabled": true}))
	// Always clean up the project's encryption config on exit.
	defer func() {
		step("Cleanup: disabling + clearing JWE config")
		empty := ""
		if err := mgmtUpdateJWE(cfg, map[string]any{"publicKey": &empty, "enabled": false}); err != nil {
			fmt.Printf("  warning: cleanup failed: %v\n", err)
		}
	}()

	// 4. Sign the user in (raw OTP verify) to capture the *encrypted* session token.
	step("Generating OTP via descopecli")
	code := mustGenerateOTP(cfg)

	step("Verifying OTP -> capturing raw session token")
	encryptedJWT := mustVerifyOTP(cfg, code)
	dots := strings.Count(encryptedJWT, ".")
	if dots != 4 {
		fail(fmt.Sprintf("expected a 5-part JWE session token, got %d-part token — is JWE enabled on the project?", dots+1))
	}
	fmt.Printf("  session token is a 5-part JWE (%d chars) ✓\n", len(encryptedJWT))

	// 5. Validate the encrypted token through the patched SDK (decrypt-then-verify).
	step("Building SDK client with Config.PrivateKey set")
	descopeClient, err := client.NewWithConfig(&client.Config{
		ProjectID:      cfg.projectID,
		DescopeBaseURL: cfg.baseURL,
		PrivateKey:     privJWK,
	})
	must("create descope client", err)

	step("ValidateSessionWithToken on the encrypted JWE")
	ok, token, err := descopeClient.Auth.ValidateSessionWithToken(ctx, encryptedJWT)
	must("validate encrypted session token", err)
	if !ok {
		fail("ValidateSessionWithToken returned not-valid for the encrypted token")
	}
	fmt.Printf("  valid ✓  sub=%s  claims=%v\n", token.ID, claimKeys(token))

	// 6. Negative check: a client WITHOUT a decryption key must refuse the same token.
	step("Negative check: client without PrivateKey must reject the JWE")
	noKeyClient, err := client.NewWithConfig(&client.Config{ProjectID: cfg.projectID, DescopeBaseURL: cfg.baseURL})
	must("create no-key client", err)
	if _, _, nerr := noKeyClient.Auth.ValidateSessionWithToken(ctx, encryptedJWT); nerr == nil {
		fail("expected ErrJWEDecrypt when no decryption key is configured, got nil")
	} else {
		fmt.Printf("  correctly rejected: %v ✓\n", nerr)
	}

	fmt.Printf("\n✅ Success — the SDK decrypted and validated an encrypted (JWE) session token.\n")
}

// ─── Key generation ─────────────────────────────────────────────────────────────

func mustGenerateEncryptionKeypair() (publicJWKJSON, privateJWKJSON string) {
	raw, err := rsa.GenerateKey(rand.Reader, 2048)
	must("generate RSA key", err)

	priv, err := jwk.FromRaw(raw)
	must("build private JWK", err)
	privBytes, err := json.Marshal(priv)
	must("marshal private JWK", err)

	pub, err := priv.PublicKey()
	must("build public JWK", err)
	must("set use=enc", pub.Set(jwk.KeyUsageKey, jwk.ForEncryption))
	pubBytes, err := json.Marshal(pub)
	must("marshal public JWK", err)

	return string(pubBytes), string(privBytes)
}

// ─── descopecli integration ─────────────────────────────────────────────────────

func cliEnv(cfg config) []string {
	return append(os.Environ(),
		descope.EnvironmentVariableProjectID+"="+cfg.projectID,
		descope.EnvironmentVariableManagementKey+"="+cfg.mgmtKey,
		descope.EnvironmentVariableBaseURL+"="+cfg.baseURL,
	)
}

// runCLI executes a descopecli command with --json and returns its stdout.
func runCLI(cfg config, args ...string) ([]byte, error) {
	cmd := exec.Command(cfg.descopeCLI, append(args, "--json")...) //nolint:gosec
	cmd.Env = cliEnv(cfg)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", cfg.descopeCLI, strings.Join(args, " "), err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// mustRunCLI runs a CLI command, tolerating "already exists" so reruns are idempotent.
func mustRunCLI(cfg config, args ...string) {
	if _, err := runCLI(cfg, args...); err != nil {
		if strings.Contains(err.Error(), "already exists") {
			fmt.Printf("  (already exists — ok)\n")
			return
		}
		fail(err.Error())
	}
}

func mustGenerateOTP(cfg config) string {
	out, err := runCLI(cfg, "user", "test", "generate", "otp", "email", cfg.testUser)
	must("generate OTP", err)
	var resp struct {
		Code string `json:"code"`
	}
	must("parse OTP json", json.Unmarshal(out, &resp))
	if resp.Code == "" {
		fail("descopecli returned an empty OTP code")
	}
	return resp.Code
}

// ─── Raw HTTP (management API + OTP verify) ──────────────────────────────────────

func httpJSON(method, url, auth string, body any, out any) error {
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		return err
	}
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, raw)
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func mgmtUpdateJWE(cfg config, body map[string]any) error {
	return httpJSON(http.MethodPost, cfg.baseURL+"/v1/mgmt/project/jwt/encryption/update",
		cfg.projectID+":"+cfg.mgmtKey, body, nil)
}

func mustVerifyOTP(cfg config, code string) string {
	var resp struct {
		SessionJwt string `json:"sessionJwt"`
	}
	must("verify OTP", httpJSON(http.MethodPost, cfg.baseURL+"/v1/auth/otp/verify/email",
		cfg.projectID, map[string]any{"loginId": cfg.testUser, "code": code}, &resp))
	if resp.SessionJwt == "" {
		fail("OTP verify returned an empty sessionJwt")
	}
	return resp.SessionJwt
}

// ─── small helpers ──────────────────────────────────────────────────────────────

func claimKeys(t *descope.Token) []string {
	keys := make([]string, 0, len(t.Claims))
	for k := range t.Claims {
		keys = append(keys, k)
	}
	return keys
}

func step(msg string) { fmt.Printf("→ %s...\n", msg) }
func fail(msg string) { fmt.Fprintf(os.Stderr, "✗ %s\n", msg); os.Exit(1) }
func must(label string, err error) {
	if err != nil {
		fail(label + ": " + err.Error())
	}
}
