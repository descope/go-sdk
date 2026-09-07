package dpop

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

const (
	// HeaderProof carries the DPoP proof JWT (RFC 9449 §4).
	HeaderProof = "DPoP"
	// HeaderNonce carries the server-issued nonce (RFC 9449 §8).
	HeaderNonce = "DPoP-Nonce"
	// AuthorizationScheme replaces "Bearer" once a token is DPoP-bound (RFC 9449 §7.1).
	AuthorizationScheme = "DPoP"

	errUseDPoPNonce = "use_dpop_nonce"
	maxChallengeGap = 4096 // bytes of an error body inspected for the nonce challenge
)

// Transport signs every outgoing request with a DPoP proof.
//
// It covers the three things a DPoP client has to get right:
//   - a fresh single-use proof per request, bound to method and URL;
//   - the ath claim and the DPoP Authorization scheme whenever the request carries an
//     access token (Bearer is rewritten to DPoP);
//   - the nonce handshake. Descope's token endpoint always requires a nonce, so the first
//     request is answered with 400 use_dpop_nonce; Transport retries it once with the
//     nonce from the response and caches the rotated nonce for later requests.
//
// Wrap it in an http.Client and use that client for the token endpoint and for every
// resource request made with the resulting DPoP-bound access token.
type Transport struct {
	// Key signs the proofs. Required.
	Key *Key
	// Base is the underlying RoundTripper. Defaults to http.DefaultTransport.
	Base http.RoundTripper

	// ponytail: one nonce per host held in memory. A shared store only matters if several
	// client instances must reuse one nonce, which the retry already recovers from.
	mu     sync.Mutex
	nonces map[string]string
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.Key == nil {
		return nil, fmt.Errorf("dpop: Transport.Key is nil")
	}

	// Buffer the body so the nonce retry can replay it.
	body, err := bufferBody(req)
	if err != nil {
		return nil, err
	}

	res, err := t.attempt(req, body, t.nonce(req.URL.Host))
	if err != nil {
		return nil, err
	}
	t.rememberNonce(req.URL.Host, res.Header.Get(HeaderNonce))

	nonce := res.Header.Get(HeaderNonce)
	if nonce == "" || !isNonceChallenge(res) {
		return res, nil
	}

	// A nonce challenge is expected on the first call, so drop this response and retry once.
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	res, err = t.attempt(req, body, nonce)
	if err != nil {
		return nil, err
	}
	t.rememberNonce(req.URL.Host, res.Header.Get(HeaderNonce))
	return res, nil
}

func (t *Transport) attempt(req *http.Request, body []byte, nonce string) (*http.Response, error) {
	out := req.Clone(req.Context())
	if body != nil {
		out.Body = io.NopCloser(bytes.NewReader(body))
	}

	opts := []ProofOption{}
	if nonce != "" {
		opts = append(opts, WithNonce(nonce))
	}
	// A request that carries an access token needs the ath claim, and the token must be
	// presented under the DPoP scheme.
	if scheme, token, ok := splitAuthorization(out.Header.Get("Authorization")); ok {
		if scheme == "bearer" || scheme == "dpop" {
			out.Header.Set("Authorization", AuthorizationScheme+" "+token)
			opts = append(opts, WithAccessToken(token))
		}
	}

	proof, err := t.Key.Proof(out.Method, out.URL.String(), opts...)
	if err != nil {
		return nil, err
	}
	out.Header.Set(HeaderProof, proof)

	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(out)
}

func (t *Transport) nonce(host string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.nonces[host]
}

func (t *Transport) rememberNonce(host, nonce string) {
	if nonce == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.nonces == nil {
		t.nonces = map[string]string{}
	}
	t.nonces[host] = nonce
}

// isNonceChallenge reports whether res asks the client to retry with a nonce: a 400
// use_dpop_nonce from the token endpoint, or a 401 DPoP challenge from a resource server.
// The body is left readable for the caller when the answer is no.
func isNonceChallenge(res *http.Response) bool {
	if res.StatusCode != http.StatusBadRequest && res.StatusCode != http.StatusUnauthorized {
		return false
	}
	if strings.Contains(res.Header.Get("WWW-Authenticate"), errUseDPoPNonce) {
		return true
	}
	head, err := io.ReadAll(io.LimitReader(res.Body, maxChallengeGap))
	if err != nil {
		return false // notest
	}
	res.Body = readCloser{Reader: io.MultiReader(bytes.NewReader(head), res.Body), Closer: res.Body}
	return strings.Contains(string(head), errUseDPoPNonce)
}

type readCloser struct {
	io.Reader
	io.Closer
}

// bufferBody reads the request body so it can be sent twice, returning nil for a bodyless
// request.
func bufferBody(req *http.Request) ([]byte, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return nil, nil
	}
	body, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("dpop: read request body: %w", err) // notest
	}
	return body, nil
}

func splitAuthorization(header string) (scheme, token string, ok bool) {
	parts := strings.Fields(strings.TrimSpace(header))
	if len(parts) != 2 {
		return "", "", false
	}
	return strings.ToLower(parts[0]), parts[1], true
}
