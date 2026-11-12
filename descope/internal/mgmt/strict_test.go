package mgmt

import (
	"context"
	"net/http"
	"testing"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/tests/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Strict is sent only when the caller sets it, so existing calls keep sending the same body. A batch carries it per user.
func TestStrictCustomAttributesIsSentOnlyWhenSet(t *testing.T) {
	ctx := context.Background()
	writes := map[string]func(m *managementService, strict bool) error{
		"tenant create": func(m *managementService, strict bool) error {
			_, err := m.Tenant().Create(ctx, &descope.TenantRequest{Name: "t", Strict: strict})
			return err
		},
		"tenant update": func(m *managementService, strict bool) error {
			return m.Tenant().Update(ctx, "t", &descope.TenantRequest{Name: "t", Strict: strict})
		},
		"tenant patch": func(m *managementService, strict bool) error {
			return m.Tenant().Patch(ctx, &descope.PatchTenantRequest{ID: "t", Strict: strict})
		},
		"user create": func(m *managementService, strict bool) error {
			_, err := m.User().Create(ctx, "u", &descope.UserRequest{Strict: strict})
			return err
		},
		"user create test user": func(m *managementService, strict bool) error {
			_, err := m.User().CreateTestUser(ctx, "u", &descope.UserRequest{Strict: strict})
			return err
		},
		"user invite": func(m *managementService, strict bool) error {
			_, err := m.User().Invite(ctx, "u", &descope.UserRequest{Strict: strict}, nil)
			return err
		},
		"user update": func(m *managementService, strict bool) error {
			_, err := m.User().Update(ctx, "u", &descope.UserRequest{Strict: strict})
			return err
		},
		"user create batch item": func(m *managementService, strict bool) error {
			_, err := m.User().CreateBatch(ctx, []*descope.BatchUser{{LoginID: "u", UserRequest: descope.UserRequest{Strict: strict}}})
			return err
		},
		"user patch": func(m *managementService, strict bool) error {
			_, err := m.User().Patch(ctx, "u", &descope.PatchUserRequest{Strict: strict})
			return err
		},
	}
	for name, write := range writes {
		for _, strict := range []bool{true, false} {
			t.Run(name, func(t *testing.T) {
				var body map[string]any
				m := newTestMgmt(nil, helpers.DoOkWithBody(func(r *http.Request) {
					require.NoError(t, helpers.ReadBody(r, &body))
				}, map[string]any{"id": "t", "user": map[string]any{}}))
				require.NoError(t, write(m, strict))
				if users, isBatch := body["users"].([]any); isBatch {
					body = users[0].(map[string]any)
				}
				value, sent := body["strict"]
				assert.Equal(t, strict, sent)
				if strict {
					assert.Equal(t, true, value)
				}
			})
		}
	}
}
