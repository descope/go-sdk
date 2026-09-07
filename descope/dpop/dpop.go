// Package dpop creates DPoP proofs (RFC 9449) so a Go application can act as an
// OAuth client of a Descope inbound application that requires DPoP.
//
// The SDK already validates incoming proofs at the resource server
// (auth.ValidateSessionWithRequest); this package covers the client side: holding the
// proof-of-possession key, minting proofs, and answering the DPoP-Nonce challenge that
// Descope's token endpoint always issues.
//
//	key, _ := dpop.NewKey()
//	httpClient := &http.Client{Transport: &dpop.Transport{Key: key}}
//	// httpClient now signs every request; pass key.Thumbprint() as dpop_jkt at /authorize.
package dpop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

// Key is a DPoP proof-of-possession key. Safe for concurrent use.
type Key struct {
	priv jwk.Key
	pub  jwk.Key
	alg  jwa.SignatureAlgorithm
	jkt  string
}

// NewKey generates an ephemeral ES256 DPoP key. ES256 is accepted by Descope in every
// configuration, including FAPI 2.0, which rejects RS* proofs.
//
// The key must outlive the tokens bound to it: a DPoP-bound refresh token is unusable
// without it. Persist it with json.Marshal(key) and load it back with ParseKey.
func NewKey() (*Key, error) {
	raw, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil { // notest
		return nil, fmt.Errorf("generate DPoP key: %w", err)
	}
	return NewKeyFromRaw(raw)
}

// NewKeyFromRaw wraps an existing private key: *ecdsa.PrivateKey, *rsa.PrivateKey or
// ed25519.PrivateKey.
func NewKeyFromRaw(raw any) (*Key, error) {
	priv, err := jwk.FromRaw(raw)
	if err != nil {
		return nil, fmt.Errorf("import DPoP key: %w", err)
	}
	return newKey(priv)
}

// ParseKey loads a key previously serialized with json.Marshal.
func ParseKey(privateJWK []byte) (*Key, error) {
	priv, err := jwk.ParseKey(privateJWK)
	if err != nil {
		return nil, fmt.Errorf("parse DPoP key: %w", err)
	}
	return newKey(priv)
}

func newKey(priv jwk.Key) (*Key, error) {
	alg, err := algFor(priv)
	if err != nil {
		return nil, err
	}
	pub, err := priv.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("derive DPoP public key: %w", err)
	}
	// Only the key material belongs in the proof header; kid/use/alg would change the
	// thumbprint input in some implementations and carry no meaning to the server.
	for _, field := range []string{jwk.KeyIDKey, jwk.KeyUsageKey, jwk.AlgorithmKey, jwk.KeyOpsKey} {
		_ = pub.Remove(field)
	}
	tp, err := pub.Thumbprint(crypto.SHA256)
	if err != nil { // notest
		return nil, fmt.Errorf("compute DPoP thumbprint: %w", err)
	}
	return &Key{priv: priv, pub: pub, alg: alg, jkt: base64.RawURLEncoding.EncodeToString(tp)}, nil
}

// algFor picks the proof signing algorithm for the key type. RSA keys get PS256 rather
// than RS256 because FAPI 2.0 rejects RSASSA-PKCS1-v1_5 proofs.
func algFor(key jwk.Key) (jwa.SignatureAlgorithm, error) {
	if alg := key.Algorithm(); alg != nil && alg.String() != "" {
		return jwa.SignatureAlgorithm(alg.String()), nil
	}
	switch key.KeyType() {
	case jwa.OKP:
		return jwa.EdDSA, nil
	case jwa.RSA:
		return jwa.PS256, nil
	case jwa.EC:
		ec, ok := key.(jwk.ECDSAPrivateKey)
		if !ok {
			return "", fmt.Errorf("DPoP key must be a private key")
		}
		switch string(ec.Crv().String()) {
		case "P-256":
			return jwa.ES256, nil
		case "P-384":
			return jwa.ES384, nil
		case "P-521":
			return jwa.ES512, nil
		}
		// notest — jwx only builds EC keys on P-256/384/521, so no other curve reaches here
		return "", fmt.Errorf("unsupported DPoP curve %q", ec.Crv().String())
	}
	return "", fmt.Errorf("unsupported DPoP key type %q", key.KeyType())
}

// Thumbprint returns the base64url SHA-256 JWK thumbprint of the public key. This is the
// value to send as the dpop_jkt parameter at /authorize, /par, /device or the CIBA
// endpoint, and the value that appears as cnf.jkt in the issued access token.
func (k *Key) Thumbprint() string {
	return k.jkt
}

// Algorithm returns the JWS algorithm used to sign proofs.
func (k *Key) Algorithm() string {
	return k.alg.String()
}

// MarshalJSON serializes the private key as a JWK so it can be persisted. The output is
// key material: store it the way you store a client secret.
func (k *Key) MarshalJSON() ([]byte, error) {
	return json.Marshal(k.priv)
}

type proofOptions struct {
	accessToken string
	nonce       string
}

// ProofOption customizes a generated proof.
type ProofOption func(*proofOptions)

// WithAccessToken adds the ath claim, binding the proof to an access token. Required for
// every request to a resource server, and forbidden nowhere else, so pass it whenever the
// request carries an access token.
func WithAccessToken(accessToken string) ProofOption {
	return func(o *proofOptions) { o.accessToken = accessToken }
}

// WithNonce adds the nonce claim. Descope's token endpoint always requires one; the first
// request gets a 400 use_dpop_nonce carrying the nonce to use. Transport does this for you.
func WithNonce(nonce string) ProofOption {
	return func(o *proofOptions) { o.nonce = nonce }
}

// Proof mints a DPoP proof JWT for a single request. Proofs are single use: the server
// rejects a replayed jti.
func (k *Key) Proof(method, requestURL string, opts ...ProofOption) (string, error) {
	var o proofOptions
	for _, opt := range opts {
		opt(&o)
	}

	htu, err := htuFor(requestURL)
	if err != nil {
		return "", err
	}

	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil { // notest
		return "", fmt.Errorf("generate DPoP jti: %w", err)
	}

	token := jwt.New()
	claims := map[string]any{
		"jti": base64.RawURLEncoding.EncodeToString(jti),
		"htm": method,
		"htu": htu,
		"iat": time.Now().Unix(),
	}
	if o.accessToken != "" {
		hash := sha256.Sum256([]byte(o.accessToken))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(hash[:])
	}
	if o.nonce != "" {
		claims["nonce"] = o.nonce
	}
	for name, value := range claims {
		if err := token.Set(name, value); err != nil { // notest
			return "", fmt.Errorf("set DPoP claim %s: %w", name, err)
		}
	}

	headers := jws.NewHeaders()
	if err := headers.Set(jws.TypeKey, "dpop+jwt"); err != nil { // notest
		return "", err
	}
	if err := headers.Set(jws.JWKKey, k.pub); err != nil { // notest
		return "", err
	}

	proof, err := jwt.Sign(token, jwt.WithKey(k.alg, k.priv, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return "", fmt.Errorf("sign DPoP proof: %w", err)
	}
	return string(proof), nil
}

// htuFor strips the query and fragment, which RFC 9449 excludes from htu, and rejects a
// relative URL: htu must be absolute for the server to compare it.
func htuFor(requestURL string) (string, error) {
	u, err := url.Parse(requestURL)
	if err != nil {
		return "", fmt.Errorf("parse DPoP request URL: %w", err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("DPoP request URL must be absolute, got %q", requestURL)
	}
	u.RawQuery, u.Fragment, u.User = "", "", nil
	return u.String(), nil
}
