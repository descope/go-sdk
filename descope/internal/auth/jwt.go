package auth

import (
	"context"
	"path"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/logger"
)

type provider struct {
	client      *api.Client
	conf        *AuthParams
	providedKey jwk.Key
	keySet      map[string]jwk.Key
}

func newProvider(client *api.Client, conf *AuthParams) *provider {
	return &provider{client: client, conf: conf, keySet: make(map[string]jwk.Key)}
}

func (p *provider) publicKeyExists() bool {
	return len(p.keySet) > 0 || p.providedKey != nil
}

func (p *provider) selectKey(sink jws.KeySink, key jwk.Key) error {
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

func (p *provider) requestKeys() error {
	projectID := p.conf.ProjectID
	keysWrapper := map[string][]map[string]interface{}{}
	_, err := p.client.DoGetRequest(path.Join(api.Routes.GetKeys(), projectID), &api.HTTPRequest{ResBodyObj: &keysWrapper}, "")
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
	p.keySet = tempKeySet
	return nil
}

func (p *provider) providedPublicKey() (jwk.Key, error) {
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

func (p *provider) findKey(kid string) (jwk.Key, error) {
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

	key, ok := p.keySet[kid]
	if !ok {
		err := descope.ErrPublicKey.WithMessage("Required public key does not exist in key set")
		logger.LogInfo("Required public key does not exist in key set (key set size [%d])", len(p.keySet))
		return nil, err
	}

	return key, nil
}

func (p *provider) FetchKeys(_ context.Context, sink jws.KeySink, sig *jws.Signature, _ *jws.Message) error {
	wantedKid := sig.ProtectedHeaders().KeyID()
	v, ok := p.keySet[wantedKid]
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
