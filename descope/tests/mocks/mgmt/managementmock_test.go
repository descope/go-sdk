package mgmtmocks

import (
	"testing"

	"github.com/descope/go-sdk/descope/mgmt"
	"github.com/stretchr/testify/assert"
)

func TestManagementMock(t *testing.T) {
	func(mgmt.Management) {
		assert.True(t, true) // we just need to make sure the sdk is implemented
	}(MockManagement{})
}
