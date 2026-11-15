package auth

import (
	"strings"

	"github.com/descope/go-sdk/descope"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwe"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

// A compact JWE has five dot separated parts where a signed JWT has three
const encryptedTokenDots = 4

const jweKeyBytes = 32

// loadEncryptionKeys parses the configured JWT encryption keys once, so a bad key fails at startup
func (p *Provider) loadEncryptionKeys() error {
	keys := make(map[string]jwk.Key, len(p.conf.JWTEncryptionKeys))
	for _, raw := range p.conf.JWTEncryptionKeys {
		// jwk.Parse accepts a single JWK or a JWK Set, so one entry (or the environment variable) can carry current and previous keys
		set, err := jwk.Parse([]byte(raw))
		if err != nil {
			return descope.ErrInvalidArguments.WithMessage("Invalid JWT encryption key: %s", err.Error())
		}
		if set.Len() == 0 {
			return descope.ErrInvalidArguments.WithMessage("Invalid JWT encryption key: the key set is empty")
		}
		for i := 0; i < set.Len(); i++ {
			key, _ := set.Key(i)
			if err := validateEncryptionKey(key); err != nil {
				return err
			}
			if _, exists := keys[key.KeyID()]; exists {
				return descope.ErrInvalidArguments.WithMessage("Invalid JWT encryption key: duplicate kid %s", key.KeyID())
			}
			keys[key.KeyID()] = key
		}
	}
	p.encryptionKeys = keys
	return nil
}

func validateEncryptionKey(key jwk.Key) error {
	symmetric, ok := key.(jwk.SymmetricKey)
	if !ok || len(symmetric.Octets()) != jweKeyBytes {
		return descope.ErrInvalidArguments.WithMessage("Invalid JWT encryption key: must be a 256-bit JWK with kty oct")
	}
	if key.KeyID() == "" {
		return descope.ErrInvalidArguments.WithMessage("Invalid JWT encryption key: kid is required to match the tokens it encrypted")
	}
	return nil
}

func isEncryptedToken(token string) bool {
	return strings.Count(token, ".") == encryptedTokenDots
}

// decryptToken returns the signed JWT inside an encrypted (JWE) token
func (p *Provider) decryptToken(token string) (string, error) {
	msg, err := jwe.Parse([]byte(token))
	if err != nil {
		return "", descope.ErrInvalidToken.WithMessage("Failed to parse encrypted token: %s", err.Error())
	}
	headers := msg.ProtectedHeaders()
	if headers.Algorithm() != jwa.A256KW || headers.ContentEncryption() != jwa.A256GCM || headers.Compression() != jwa.NoCompress {
		return "", descope.ErrInvalidToken.WithMessage("Encrypted token must use A256KW and A256GCM without compression")
	}
	key, ok := p.encryptionKeys[headers.KeyID()]
	if !ok {
		return "", descope.ErrInvalidToken.WithMessage("No JWT encryption key configured for the token key id")
	}
	signed, err := jwe.Decrypt([]byte(token), jwe.WithKey(jwa.A256KW, key))
	if err != nil {
		return "", descope.ErrInvalidToken.WithMessage("Failed to decrypt token: %s", err.Error())
	}
	return string(signed), nil
}
