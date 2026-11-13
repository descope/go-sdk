package auth

import (
	"context"
	"path"
	"sync"
	"sync/atomic"
	"time"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/internal/utils"
	"github.com/descope/go-sdk/descope/logger"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
)

const (
	// keySetTTL is how long a successfully fetched key set is used before it is refetched
	keySetTTL = 10 * time.Minute
	// keyFetchCooldown limits fetches for unknown key ids after a successful fetch,
	// and refresh retries of a cached key past keySetTTL after a fetch attempt
	keyFetchCooldown = 30 * time.Second
	// keyMaxStaleAge is how long after the last successful fetch cached keys may still be used when refreshes fail
	keyMaxStaleAge = time.Hour
)

type Provider struct {
	client         *api.Client
	conf           *AuthParams
	providedKey    jwk.Key
	keySet         atomic.Value
	fetchedAt      atomic.Pointer[time.Time] // last successful fetch, nil before the first one
	mu             sync.Mutex                // serializes fetches
	attemptedAt    time.Time                 // last fetch attempt, guarded by mu
	attempts       atomic.Uint64             // completed fetch attempts
	now            func() time.Time
	encryptionKeys map[string]jwk.Key
}

func NewProvider(client *api.Client, conf *AuthParams) *Provider {
	p := &Provider{client: client, conf: conf, now: time.Now}
	p.keySet.Store(map[string]jwk.Key{})
	return p
}

// cachedKey returns the key from the cached key set, as long as the set is not older than keySetTTL
func (p *Provider) cachedKey(kid string) (jwk.Key, bool) {
	if t := p.fetchedAt.Load(); t == nil || p.now().Sub(*t) >= keySetTTL {
		return nil, false
	}
	key, ok := p.keySetMap()[kid]
	return key, ok
}

func (p *Provider) keySetMap() map[string]jwk.Key {
	return p.keySet.Load().(map[string]jwk.Key)
}

// usableKeySet returns the cached key set, or nil once the last successful fetch is older than keyMaxStaleAge
func (p *Provider) usableKeySet() map[string]jwk.Key {
	if t := p.fetchedAt.Load(); t == nil || p.now().Sub(*t) >= keyMaxStaleAge {
		return nil
	}
	return p.keySetMap()
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

	if len(tempKeySet) == 0 {
		return descope.ErrPublicKey.WithMessage("No public keys in key set response")
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

	// a cached key is served as is while another caller is fetching
	attempts := p.attempts.Load()
	if key, ok := p.usableKeySet()[kid]; ok {
		if !p.mu.TryLock() {
			return key, nil
		}
	} else {
		p.mu.Lock()
	}
	defer p.mu.Unlock()
	// another caller may have refreshed the key set while we waited for the lock
	if key, ok := p.cachedKey(kid); ok {
		return key, nil
	}

	// unknown key ids wait keyFetchCooldown after a successful fetch, so a failed fetch is retried right away;
	// a cached key past keySetTTL waits keyFetchCooldown after an attempt ends, so it is served while fetches fail;
	// callers that waited for a fetch use its outcome instead of fetching again
	now := p.now()
	var last time.Time
	if t := p.fetchedAt.Load(); t != nil {
		last = *t
	}
	if _, ok := p.keySetMap()[kid]; ok {
		last = p.attemptedAt
	}
	if p.attempts.Load() == attempts && now.Sub(last) >= keyFetchCooldown {
		err := p.requestKeys()
		p.attemptedAt = p.now()
		p.attempts.Add(1)
		if err != nil {
			logger.LogError("Failed to retrieve public keys from API", err)
			if key, ok := p.usableKeySet()[kid]; ok {
				return key, nil
			}
			return nil, err
		}
		p.fetchedAt.Store(&now)
	}

	key, ok := p.usableKeySet()[kid]
	if !ok {
		err := descope.ErrPublicKey.WithMessage("Required public key does not exist in key set")
		logger.LogInfo("Required public key does not exist in key set (key set size [%d])", len(p.keySetMap()))
		return nil, err
	}

	return key, nil
}

func (p *Provider) FetchKeys(_ context.Context, sink jws.KeySink, sig *jws.Signature, _ *jws.Message) error {
	wantedKid := sig.ProtectedHeaders().KeyID()
	v, ok := p.cachedKey(wantedKid)
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
