package auth

import (
	"context"
	"path"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
)

type provider struct {
	client   *client
	conf     *Config
	knownKey jwk.Key
	keySet   map[string]jwk.Key
}

func newProvider(client *client, conf *Config) *provider {
	return &provider{client: client, conf: conf, keySet: make(map[string]jwk.Key)}
}

func (p *provider) publicKeyExists() bool {
	return len(p.keySet) > 0 || p.knownKey != nil
}

func (p *provider) selectKey(sink jws.KeySink, key jwk.Key) error {
	if usage := key.KeyUsage(); usage != "" && usage != jwk.ForSignature.String() {
		return nil
	}

	if v := key.Algorithm(); v.String() != "" {
		var alg jwa.SignatureAlgorithm
		if err := alg.Accept(v); err != nil {
			return NewValidationError(`invalid signature algorithm %s: %s`, key.Algorithm(), err)
		}

		sink.Key(alg, key)
		return nil
	}

	return NewValidationError("algorithm in the message does not match")
}

func (p *provider) requestKeys() error {
	projectID := p.conf.ProjectID
	keys := []map[string]interface{}{}
	_, err := p.client.DoGetRequest(path.Join(publicKeyPath, projectID), &HTTPRequest{resBodyObj: &keys, baseURL: "http://localhost:8152"})
	if err != nil {
		return err
	}
	tempKeySet := map[string]jwk.Key{}
	for i := range keys {
		b, err := Marshal(keys[i])
		if err != nil {
			p.conf.LogDebug("Validate failed to marshal key to bytes [%s]", err)
			continue
		}

		jk, err := jwk.ParseKey(b)
		if err != nil {
			p.conf.LogDebug("Validate failed to parse key [%s]", err)
			continue
		}

		pk, err := jk.PublicKey()
		if err != nil {
			p.conf.LogDebug("Validate failed to parse public key [%s]", err)
			continue
		}

		tempKeySet[pk.KeyID()] = pk
	}

	p.conf.LogDebug("refresh keys set with %d key(s)", len(tempKeySet))
	p.keySet = tempKeySet
	return nil
}

func (p *provider) providedPublicKey() (jwk.Key, error) {
	if p.knownKey != nil {
		return p.knownKey, nil
	}

	if p.conf.PublicKey != "" {
		jk, err := jwk.ParseKey([]byte(p.conf.PublicKey))
		if err != nil {
			p.conf.LogDebug("unable to parse key")
			return nil, err
		}
		p.knownKey, _ = jk.PublicKey()
		return p.knownKey, nil
	}
	return nil, nil
}

func (p *provider) findKey(kid string) (jwk.Key, error) {
	key, err := p.providedPublicKey()
	if err != nil {
		return nil, err
	}
	if key != nil {
		if key.KeyID() == kid {
			return key, nil
		}
		return nil, NewPublicKeyDoesNotMatchError()
	}

	if err := p.requestKeys(); err != nil {
		p.conf.LogDebug("failed to retreive public keys from API [%s]", err)
		return nil, err
	}

	return p.keySet[kid], nil
}

func (p *provider) FetchKeys(_ context.Context, sink jws.KeySink, sig *jws.Signature, _ *jws.Message) error {
	wantedKid := sig.ProtectedHeaders().KeyID()
	v, ok := p.keySet[wantedKid]
	if !ok {
		p.conf.LogDebug("key was not found, looking for key id [%s]", wantedKid)
		if key, err := p.findKey(wantedKid); key != nil {
			v = key
		} else {
			return err
		}
	}
	return p.selectKey(sink, v)
}
