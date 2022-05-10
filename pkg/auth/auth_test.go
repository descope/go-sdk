package auth

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuth(t *testing.T) {
	a := Auth{}
	require.NotNil(t, a)
	a.Temp()
}
