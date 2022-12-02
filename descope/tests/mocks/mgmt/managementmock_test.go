package mgmtmocks

import (
	"testing"

	"github.com/descope/go-sdk/descope/mgmt"
)

func TestManagementMock(t *testing.T) {
	func(mgmt.Management) {

	}(MockManagement{})
}
