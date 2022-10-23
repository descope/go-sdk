package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsStepup(t *testing.T) {
	lo := &LoginOptions{Stepup: true}
	assert.True(t, lo.IsStepup())
	lo = &LoginOptions{Stepup: false}
	assert.False(t, lo.IsStepup())
	lo = nil
	assert.False(t, lo.IsStepup())
}

func TestAuthFactors(t *testing.T) {
	to := &Token{Claims: map[string]interface{}{}}
	assert.False(t, to.IsMFA())
	to = &Token{Claims: map[string]interface{}{"amr": []interface{}{string(AuthFactorEmail)}}}
	assert.False(t, to.IsMFA())
	to = &Token{Claims: map[string]interface{}{"amr": []interface{}{string(AuthFactorEmail), string(AuthFactorWebauthn), string(AuthFactorMFA)}}}
	assert.True(t, to.IsMFA())
}
