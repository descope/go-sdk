package auth

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/api"
	"github.com/descope/go-sdk/descope/tests/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type keysServer struct {
	fetches atomic.Int32
	keys    string // JSON array content of the "keys" field
	fail    bool
}

func (s *keysServer) do(_ *http.Request) (*http.Response, error) {
	s.fetches.Add(1)
	if s.fail {
		return &http.Response{StatusCode: http.StatusInternalServerError, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(fmt.Sprintf(`{"keys":[%s]}`, s.keys)))}, nil
}

func newKeysTestProvider(s *keysServer) (*Provider, *time.Time) {
	client := api.NewClient(api.ClientParams{ProjectID: "a", DefaultClient: mocks.NewTestClient(s.do)})
	p := NewProvider(client, &AuthParams{ProjectID: "a"})
	clock := time.Now()
	p.now = func() time.Time { return clock }
	return p, &clock
}

func TestKeySetRefreshedAfterTTL(t *testing.T) {
	s := &keysServer{keys: publicKey}
	p, clock := newKeysTestProvider(s)

	_, err := ValidateJWT(jwtTokenValid, p)
	require.NoError(t, err)
	*clock = clock.Add(keySetTTL - time.Second)
	_, err = ValidateJWT(jwtTokenValid, p)
	require.NoError(t, err)
	require.EqualValues(t, 1, s.fetches.Load())

	// the key is no longer published, so it stays valid until the TTL passes
	s.keys = ""
	*clock = clock.Add(time.Second)
	_, err = ValidateJWT(jwtTokenValid, p)
	require.ErrorIs(t, err, descope.ErrPublicKey)
	require.EqualValues(t, 2, s.fetches.Load())
}

func TestUnknownKeyIDFetchCooldown(t *testing.T) {
	s := &keysServer{keys: publicKey}
	p, clock := newKeysTestProvider(s)

	_, err := p.findKey("unknown")
	require.ErrorIs(t, err, descope.ErrPublicKey)
	require.EqualValues(t, 1, s.fetches.Load())
	*clock = clock.Add(keyFetchCooldown - time.Second)
	_, err = p.findKey("unknown2")
	require.ErrorIs(t, err, descope.ErrPublicKey)
	assert.Contains(t, err.Error(), "does not exist")
	require.EqualValues(t, 1, s.fetches.Load())

	*clock = clock.Add(time.Second)
	_, err = p.findKey("unknown")
	require.ErrorIs(t, err, descope.ErrPublicKey)
	require.EqualValues(t, 2, s.fetches.Load())

	// known keys are still served during the cooldown
	key, err := p.findKey("testkey")
	require.NoError(t, err)
	require.NotNil(t, key)
	require.EqualValues(t, 2, s.fetches.Load())
}

func TestKeySetKeptOnFailedRefresh(t *testing.T) {
	s := &keysServer{keys: publicKey}
	p, clock := newKeysTestProvider(s)
	_, err := ValidateJWT(jwtTokenValid, p)
	require.NoError(t, err)

	s.fail = true
	*clock = clock.Add(keySetTTL)
	_, err = ValidateJWT(jwtTokenValid, p)
	require.NoError(t, err)
	require.EqualValues(t, 2, s.fetches.Load())

	// retries are limited by the cooldown, and the set stays eligible for a refresh
	_, err = ValidateJWT(jwtTokenValid, p)
	require.NoError(t, err)
	require.EqualValues(t, 2, s.fetches.Load())
	*clock = clock.Add(keyFetchCooldown)
	_, err = ValidateJWT(jwtTokenValid, p)
	require.NoError(t, err)
	require.EqualValues(t, 3, s.fetches.Load())

	// a failed fetch does not hold back the next unknown key id
	_, err = p.findKey("unknown")
	require.Error(t, err)
	require.EqualValues(t, 4, s.fetches.Load())
	_, err = p.findKey("unknown")
	require.Error(t, err)
	require.EqualValues(t, 5, s.fetches.Load())

	s.fail = false
	s.keys = ""
	*clock = clock.Add(keyFetchCooldown)
	_, err = ValidateJWT(jwtTokenValid, p)
	require.ErrorIs(t, err, descope.ErrPublicKey)
}

func TestFailedFirstFetchRetriedImmediately(t *testing.T) {
	s := &keysServer{keys: publicKey, fail: true}
	p, _ := newKeysTestProvider(s)
	_, err := ValidateJWT(jwtTokenValid, p)
	require.ErrorIs(t, err, descope.ErrPublicKey)
	require.EqualValues(t, 1, s.fetches.Load())

	s.fail = false
	_, err = ValidateJWT(jwtTokenValid, p)
	require.NoError(t, err)
	require.EqualValues(t, 2, s.fetches.Load())
}

func TestConcurrentUnknownKeyIDFetchOnce(t *testing.T) {
	s := &keysServer{keys: publicKey}
	p, _ := newKeysTestProvider(s)

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := p.findKey("unknown")
			assert.ErrorIs(t, err, descope.ErrPublicKey)
		}()
	}
	wg.Wait()
	require.EqualValues(t, 1, s.fetches.Load())
}
