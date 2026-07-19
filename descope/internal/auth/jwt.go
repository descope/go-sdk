package auth

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"path"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/logger"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

type Provider struct {
	client      *api.Client
	conf        *AuthParams
	providedKey jwk.Key
	keySet      atomic.Value

	// JWE decryption keys parsed from conf.PrivateKey, keyed by JWK thumbprint (kid). Parsed once,
	// lazily, on first encrypted token; read-only afterwards.
	decryptOnce     sync.Once
	decryptKeys     map[string]jwk.Key
	decryptParseErr error
}

func NewProvider(client *api.Client, conf *AuthParams) *Provider {
	ks := atomic.Value{}
	ks.Store(map[string]jwk.Key{})
	return &Provider{client: client, conf: conf, keySet: ks}
}

func (p *Provider) keySetMap() map[string]jwk.Key {
	return p.keySet.Load().(map[string]jwk.Key)
}

func (p *Provider) publicKeyExists() bool {
	return len(p.keySetMap()) > 0 || p.providedKey != nil
}

func (p *Provider) selectKey(sink jws.KeySink, key jwk.Key) error {
	if usage := key.KeyUsage(); usage != "" && usage != jwk.ForSignature.String() {
		return nil // notest
	}

	if v := key.Algorithm(); v.String() != "" {
		var alg jwa.SignatureAlgorithm
		if err := alg.Accept(v); err != nil {
			return descope.ErrPublicKey.WithMessage("Invalid signature algorithm %s: %s", key.Algorithm(), err.Error())
		}

		sink.Key(alg, key)
		return nil
	}

	return descope.ErrPublicKey.WithMessage("Algorithm in the message does not match") // notest
}

func (p *Provider) requestKeys() error {
	projectID := p.conf.ProjectID
	keysWrapper := map[string][]map[string]any{}
	_, err := p.client.DoGetRequest(context.Background(), path.Join(api.Routes.GetKeys(), projectID), &api.HTTPRequest{ResBodyObj: &keysWrapper}, "")
	if err != nil {
		return err
	}
	keys := keysWrapper["keys"]
	tempKeySet := map[string]jwk.Key{}
	for i := range keys {
		b, err := utils.Marshal(keys[i])
		if err != nil { // notest
			logger.LogDebug("Validate failed to marshal key to bytes [%s]", err)
			continue
		}

		jk, err := jwk.ParseKey(b)
		if err != nil { // notest
			logger.LogDebug("Validate failed to parse key [%s]", err)
			continue
		}

		pk, err := jk.PublicKey()
		if err != nil { // notest
			logger.LogDebug("Validate failed to parse public key [%s]", err)
			continue
		}

		tempKeySet[pk.KeyID()] = pk
	}

	logger.LogDebug("Refresh keys set with %d key(s)", len(tempKeySet))
	p.keySet.Store(tempKeySet)
	return nil
}

func (p *Provider) providedPublicKey() (jwk.Key, error) {
	if p.providedKey != nil {
		return p.providedKey, nil
	}

	if p.conf.PublicKey != "" {
		jk, err := jwk.ParseKey([]byte(p.conf.PublicKey))
		if err != nil {
			logger.LogDebug("Unable to parse key")
			return nil, err
		}
		p.providedKey, _ = jk.PublicKey()
		return p.providedKey, nil
	}
	return nil, nil
}

func (p *Provider) findKey(kid string) (jwk.Key, error) {
	key, err := p.providedPublicKey()
	if err != nil {
		return nil, err
	}
	if key != nil {
		if key.KeyID() == kid {
			return key, nil
		}
		err = descope.ErrPublicKey.WithMessage("Provided public key does not match required public key")
		logger.LogInfo("Provided public key does not match required public key")
		return nil, err
	}

	if err := p.requestKeys(); err != nil {
		logger.LogDebug("Failed to retrieve public keys from API [%s]", err)
		return nil, err
	}

	key, ok := p.keySetMap()[kid]
	if !ok {
		err := descope.ErrPublicKey.WithMessage("Required public key does not exist in key set")
		logger.LogInfo("Required public key does not exist in key set (key set size [%d])", len(p.keySetMap()))
		return nil, err
	}

	return key, nil
}

func (p *Provider) FetchKeys(_ context.Context, sink jws.KeySink, sig *jws.Signature, _ *jws.Message) error {
	wantedKid := sig.ProtectedHeaders().KeyID()
	v, ok := p.keySetMap()[wantedKid]
	if !ok {
		logger.LogDebug("Key was not found, looking for key id [%s]", wantedKid)
		if key, err := p.findKey(wantedKid); key != nil {
			v = key
		} else {
			return err
		}
	}
	return p.selectKey(sink, v)
}

// ─── JWE decryption ─────────────────────────────────────────────────────────────
//
// When the project has JWT encryption enabled, the session token arrives as a 5-part JWE
// (sign-then-encrypt nested JWT). The recipient — this SDK — must decrypt it with the matching
// private key before the inner signed JWS can be verified. The encryption key belongs to the
// recipient, so the private key is supplied via Config.PrivateKey / Config.PrivateKeyProvider.

// decryptionConfigured reports whether the SDK has any way to decrypt an encrypted (JWE) token.
func (p *Provider) decryptionConfigured() bool {
	return p.conf != nil && (p.conf.PrivateKeyProvider != nil || p.conf.PrivateKey != "")
}

// parseDecryptKeys lazily parses conf.PrivateKey into a kid→key map. It accepts a JWK Set, a single
// JWK, or a PEM block. Each key is indexed by its RFC-7638 SHA-256 thumbprint, which equals the
// `kid` the server stamps on the JWE header (the thumbprint is computed over public members only,
// so a private key and its public counterpart share the same thumbprint).
func (p *Provider) parseDecryptKeys() (map[string]jwk.Key, error) {
	p.decryptOnce.Do(func() {
		raw := ""
		if p.conf != nil {
			raw = p.conf.PrivateKey
		}
		if raw == "" {
			p.decryptKeys = map[string]jwk.Key{}
			return
		}

		var keys []jwk.Key
		if set, err := jwk.Parse([]byte(raw)); err == nil && set.Len() > 0 {
			for it := set.Keys(context.Background()); it.Next(context.Background()); {
				keys = append(keys, it.Pair().Value.(jwk.Key))
			}
		} else if key, err := jwk.ParseKey([]byte(raw)); err == nil {
			keys = append(keys, key)
		} else if key, err := jwk.ParseKey([]byte(raw), jwk.WithPEM(true)); err == nil {
			keys = append(keys, key)
		} else {
			p.decryptParseErr = descope.ErrJWEDecrypt.WithMessage("Unable to parse private key: must be a JWK, JWK Set, or PEM")
			return
		}

		out := make(map[string]jwk.Key, len(keys))
		for _, key := range keys {
			kid := key.KeyID()
			if kid == "" {
				if tp, err := key.Thumbprint(crypto.SHA256); err == nil {
					kid = base64.RawURLEncoding.EncodeToString(tp)
					_ = key.Set(jwk.KeyIDKey, kid)
				}
			}
			out[kid] = key
		}
		p.decryptKeys = out
	})
	return p.decryptKeys, p.decryptParseErr
}

// jweHeader is the subset of the JWE protected header we need to route decryption.
type jweHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// decryptJWE opens a 5-part compact JWE and returns the inner compact JWS (the signed token).
func (p *Provider) decryptJWE(compact string) (string, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 5 {
		return "", descope.ErrJWEDecrypt.WithMessage("Token is not a compact JWE")
	}
	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", descope.ErrJWEDecrypt.WithMessage("Invalid JWE header encoding")
	}
	var hdr jweHeader
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		return "", descope.ErrJWEDecrypt.WithMessage("Invalid JWE header")
	}
	var keyAlg jwa.KeyEncryptionAlgorithm
	if err := keyAlg.Accept(hdr.Alg); err != nil {
		return "", descope.ErrJWEDecrypt.WithMessage("Unsupported JWE key algorithm %q", hdr.Alg)
	}

	key, err := p.resolveDecryptKey(hdr.Kid)
	if err != nil {
		return "", err
	}

	plaintext, err := jwe.Decrypt([]byte(compact), jwe.WithKey(keyAlg, key))
	if err != nil {
		return "", descope.ErrJWEDecrypt.WithMessage("%s", err.Error())
	}
	return string(plaintext), nil
}

// resolveDecryptKey returns the decryption key for a JWE header kid. The PrivateKeyProvider callback
// is consulted first; otherwise the key is taken from the parsed PrivateKey by kid, falling back to
// the single configured key when there is exactly one.
func (p *Provider) resolveDecryptKey(kid string) (any, error) {
	if p.conf != nil && p.conf.PrivateKeyProvider != nil {
		key, err := p.conf.PrivateKeyProvider(kid)
		if err != nil {
			return nil, descope.ErrJWEDecrypt.WithMessage("%s", err.Error())
		}
		if key != nil {
			return key, nil
		}
	}

	keys, err := p.parseDecryptKeys()
	if err != nil {
		return nil, err
	}
	if key, ok := keys[kid]; ok {
		return key, nil
	}
	if len(keys) == 1 {
		for _, key := range keys {
			return key, nil // lenient: a single configured key is used regardless of kid
		}
	}
	return nil, descope.ErrJWEDecrypt.WithMessage("No decryption key matches the token's key id %q", kid)
}
