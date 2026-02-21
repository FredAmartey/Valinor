package rbac_test

import (
	"context"
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
