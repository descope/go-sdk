package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/descope/go-sdk/descope/dpop"
	"github.com/stretchr/testify/require"
)

// The two halves of the SDK must agree: a proof minted by the client package has to pass
// the resource-server validation used by ValidateSessionWithRequest.
func TestClientProofPassesResourceServerValidation(t *testing.T) {
	key, err := dpop.NewKey()
	require.NoError(t, err)

	const accessToken = "access.token.value"
	const requestURL = "https://rs.example.com/api/data?q=1"

	proof, err := key.Proof(http.MethodGet, requestURL, dpop.WithAccessToken(accessToken))
	require.NoError(t, err)

	store := newDPoPJTIStore()
	require.NoError(t, validateDPoPProof(proof, http.MethodGet, requestURL, accessToken, key.Thumbprint(), time.Now, store))

	// The same proof twice is a replay.
	require.Error(t, validateDPoPProof(proof, http.MethodGet, requestURL, accessToken, key.Thumbprint(), time.Now, store))

	// A proof bound to a different access token must not be accepted.
	other, err := key.Proof(http.MethodGet, requestURL, dpop.WithAccessToken("someone.elses.token"))
	require.NoError(t, err)
	require.Error(t, validateDPoPProof(other, http.MethodGet, requestURL, accessToken, key.Thumbprint(), time.Now, store))
}
