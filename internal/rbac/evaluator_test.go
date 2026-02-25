package rbac_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/rbac"
)

func TestEvaluator_PermissionGranted(t *testing.T) {
	eval := rbac.NewEvaluator(nil) // nil store for unit tests with in-memory permissions

	identity := &auth.Identity{
		UserID:      "user-123",
		TenantID:    "tenant-456",
		Roles:       []string{"standard_user"},
		Departments: []string{"dept-scouting"},
	}

	// Register role permissions
	eval.RegisterRole("standard_user", []string{
		"agents:read",
		"agents:message",
	})

	decision, err := eval.Authorize(context.Background(), identity, "agents:read", "", "")
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
}

func TestEvaluator_PermissionDenied(t *testing.T) {
	eval := rbac.NewEvaluator(nil)

	identity := &auth.Identity{
		UserID:      "user-123",
		TenantID:    "tenant-456",
		Roles:       []string{"standard_user"},
		Departments: []string{"dept-scouting"},
	}

	eval.RegisterRole("standard_user", []string{
		"agents:read",
		"agents:message",
	})

	decision, err := eval.Authorize(context.Background(), identity, "users:manage", "", "")
	require.NoError(t, err)
	assert.False(t, decision.Allowed)
	assert.NotEmpty(t, decision.Reason)
}

func TestEvaluator_OrgAdminHasAllPermissions(t *testing.T) {
	eval := rbac.NewEvaluator(nil)

	identity := &auth.Identity{
		UserID:   "user-123",
		TenantID: "tenant-456",
		Roles:    []string{"org_admin"},
	}

	eval.RegisterRole("org_admin", []string{"*"}) // wildcard = all permissions

	decision, err := eval.Authorize(context.Background(), identity, "anything:here", "", "")
	require.NoError(t, err)
	assert.True(t, decision.Allowed)
}

func TestEvaluator_MultipleRoles(t *testing.T) {
	eval := rbac.NewEvaluator(nil)

	identity := &auth.Identity{
		UserID:   "user-123",
		TenantID: "tenant-456",
		Roles:    []string{"standard_user", "dept_head"},
	}

	eval.RegisterRole("standard_user", []string{"agents:read", "agents:message"})
	eval.RegisterRole("dept_head", []string{"agents:read", "agents:write", "users:read"})

	// Should have union of permissions
	d1, err := eval.Authorize(context.Background(), identity, "agents:message", "", "")
	require.NoError(t, err)
	assert.True(t, d1.Allowed) // from standard_user

	d2, err := eval.Authorize(context.Background(), identity, "users:read", "", "")
	require.NoError(t, err)
	assert.True(t, d2.Allowed) // from dept_head
}

func TestEvaluator_NoRoles(t *testing.T) {
	eval := rbac.NewEvaluator(nil)

	identity := &auth.Identity{
		UserID:   "user-123",
		TenantID: "tenant-456",
		Roles:    []string{},
	}

	decision, err := eval.Authorize(context.Background(), identity, "agents:read", "", "")
	require.NoError(t, err)
	assert.False(t, decision.Allowed)
}

type mockRoleLoader struct {
	roles []rbac.RoleDef
	err   error
}

func (m *mockRoleLoader) LoadRoles(ctx context.Context) ([]rbac.RoleDef, error) {
	return m.roles, m.err
}

func TestEvaluator_ReloadRoles(t *testing.T) {
	loader := &mockRoleLoader{
		roles: []rbac.RoleDef{
			{Name: "editor", Permissions: []string{"agents:read", "agents:write"}},
			{Name: "viewer", Permissions: []string{"agents:read"}},
		},
	}
	eval := rbac.NewEvaluator(nil, rbac.WithRoleLoader(loader))

	err := eval.ReloadRoles(context.Background())
	require.NoError(t, err)

	identity := &auth.Identity{UserID: "u1", TenantID: "t1", Roles: []string{"editor"}}
	d, err := eval.Authorize(context.Background(), identity, "agents:write", "", "")
	require.NoError(t, err)
	assert.True(t, d.Allowed)

	// viewer should not have agents:write
	identity2 := &auth.Identity{UserID: "u2", TenantID: "t1", Roles: []string{"viewer"}}
	d2, err := eval.Authorize(context.Background(), identity2, "agents:write", "", "")
	require.NoError(t, err)
	assert.False(t, d2.Allowed)
}

func TestEvaluator_ReloadRoles_ReplacesExisting(t *testing.T) {
	loader := &mockRoleLoader{
		roles: []rbac.RoleDef{
			{Name: "editor", Permissions: []string{"agents:read"}},
		},
	}
	eval := rbac.NewEvaluator(nil, rbac.WithRoleLoader(loader))
	require.NoError(t, eval.ReloadRoles(context.Background()))

	// Update loader to give editor more permissions
	loader.roles = []rbac.RoleDef{
		{Name: "editor", Permissions: []string{"agents:read", "agents:write"}},
	}
	require.NoError(t, eval.ReloadRoles(context.Background()))

	identity := &auth.Identity{UserID: "u1", TenantID: "t1", Roles: []string{"editor"}}
	d, err := eval.Authorize(context.Background(), identity, "agents:write", "", "")
	require.NoError(t, err)
	assert.True(t, d.Allowed)
}

func TestEvaluator_ReloadRoles_ErrorPreservesExisting(t *testing.T) {
	loader := &mockRoleLoader{
		roles: []rbac.RoleDef{
			{Name: "editor", Permissions: []string{"agents:read"}},
		},
	}
	eval := rbac.NewEvaluator(nil, rbac.WithRoleLoader(loader))
	require.NoError(t, eval.ReloadRoles(context.Background()))

	// Make loader fail
	loader.err = fmt.Errorf("db connection failed")
	err := eval.ReloadRoles(context.Background())
	require.Error(t, err)

	// Old permissions should still work
	identity := &auth.Identity{UserID: "u1", TenantID: "t1", Roles: []string{"editor"}}
	d, err := eval.Authorize(context.Background(), identity, "agents:read", "", "")
	require.NoError(t, err)
	assert.True(t, d.Allowed)
}
