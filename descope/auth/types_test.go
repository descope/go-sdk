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
	to := &Token{}
	assert.False(t, to.IsMFA())
	to = &Token{Claims: map[string]interface{}{}}
	assert.False(t, to.IsMFA())
	to = &Token{Claims: map[string]interface{}{"amr": []interface{}{string(AuthFactorEmail)}}}
	assert.False(t, to.IsMFA())
	to = &Token{Claims: map[string]interface{}{"amr": []interface{}{string(AuthFactorEmail), string(AuthFactorWebauthn), string(AuthFactorMFA)}}}
	assert.True(t, to.IsMFA())
}

func TestCustomClaims(t *testing.T) {
	to := &Token{Claims: map[string]interface{}{}}
	assert.Nil(t, to.CustomClaim("a"))
	to = &Token{Claims: map[string]interface{}{"a": "b"}}
	assert.EqualValues(t, "b", to.CustomClaim("a"))
	to = &Token{}
	assert.Nil(t, to.CustomClaim("a"))
}
