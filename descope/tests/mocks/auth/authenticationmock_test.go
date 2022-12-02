package authmocks

import (
	"testing"

	"github.com/descope/go-sdk/descope/auth"
)

func TestManagementMock(t *testing.T) {
	func(auth.Authentication) {

	}(MockAuthentication{})
}
