package auth

import (
	"context"
	"fmt"
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

func (p *provider) isPublicKeyExist() bool {
	return len(p.keySet) > 0 || p.knownKey != nil
}

func (p *provider) selectKey(sink jws.KeySink, key jwk.Key) error {
	if usage := key.KeyUsage(); usage != "" && usage != jwk.ForSignature.String() {
		return nil
	}

	if v := key.Algorithm(); v.String() != "" {
		var alg jwa.SignatureAlgorithm
		if err := alg.Accept(v); err != nil {
			return fmt.Errorf(`invalid signature algorithm %s: %w`, key.Algorithm(), err)
		}

		sink.Key(alg, key)
		return nil
	}

	return fmt.Errorf("algorithm in the message does not match")
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

	if p.knownKey != nil {
		p.conf.LogDebug("adding existing key from configurations")
		tempKeySet[p.knownKey.KeyID()] = p.knownKey
	}

	p.conf.LogDebug("refresh keys set with %d key(s)", len(tempKeySet))
	p.keySet = tempKeySet
	return nil
}

func (p *provider) getAuthenticationKey() (jwk.Key, bool) {
	if p.knownKey != nil {
		return p.knownKey, true
	}

	existingPublicKey := p.conf.GetPublicKey()

	if existingPublicKey != "" {
		jk, err := jwk.ParseKey([]byte(existingPublicKey))
		if err != nil {
			p.conf.LogDebug("unable to parse key")
			return nil, false
		}
		p.knownKey, _ = jk.PublicKey()
		return p.knownKey, true
	}
	return nil, false
}

func (p *provider) findKey(kid string) (jwk.Key, error) {
	if key, ok := p.getAuthenticationKey(); ok && key.KeyID() == kid {
		return key, nil
	}

	if err := p.requestKeys(); err != nil {
		p.conf.LogDebug("failed to retreive public keys from API [%s]", err)
		return nil, err
	}

	return p.keySet[kid], nil
}

func (p *provider) FetchKeys(_ context.Context, sink jws.KeySink, sig *jws.Signature, _ *jws.Message) error {
	wantedKid := sig.ProtectedHeaders().KeyID()
	if wantedKid == "" {
		wantedKid = p.conf.GetProjectID()
	}
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
