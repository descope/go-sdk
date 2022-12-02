package authmocks

import (
	"testing"

	"github.com/descope/go-sdk/descope/auth"
	"github.com/stretchr/testify/assert"
)

func TestManagementMock(t *testing.T) {
	func(auth.Authentication) {
		assert.True(t, true) // we just need to make sure the sdk is implemented
	}(MockAuthentication{})
}
