package tenant_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/platform/database"
	"github.com/valinor-ai/valinor/internal/tenant"
)

func TestRoleStore(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ownerPool, rlsPool, cleanup := setupTestDBWithRLS(t)
	defer cleanup()

	ctx := context.Background()
	tenantStore := tenant.NewStore(ownerPool)
	ten, err := tenantStore.Create(ctx, "Role Org", "role-org")
	require.NoError(t, err)

	roleStore := tenant.NewRoleStore()
	userStore := tenant.NewUserStore()

	t.Run("Create", func(t *testing.T) {
		err := database.WithTenantConnection(ctx, rlsPool, ten.ID, func(ctx context.Context, q database.Querier) error {
			role, createErr := roleStore.Create(ctx, q, "viewer", []string{"agents:read"})
			require.NoError(t, createErr)
			assert.NotEmpty(t, role.ID)
			assert.Equal(t, "viewer", role.Name)
			assert.Equal(t, []string{"agents:read"}, role.Permissions)
			assert.False(t, role.IsSystem)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("Create_EmptyName", func(t *testing.T) {
		err := database.WithTenantConnection(ctx, rlsPool, ten.ID, func(ctx context.Context, q database.Querier) error {
			_, createErr := roleStore.Create(ctx, q, "", []string{"agents:read"})
			assert.ErrorIs(t, createErr, tenant.ErrRoleNameEmpty)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("Create_DuplicateName", func(t *testing.T) {
		ten2, err := tenantStore.Create(ctx, "Dup Role Org", "dup-role-org")
		require.NoError(t, err)

		err = database.WithTenantConnection(ctx, rlsPool, ten2.ID, func(ctx context.Context, q database.Querier) error {
			_, createErr := roleStore.Create(ctx, q, "editor", []string{"agents:write"})
			require.NoError(t, createErr)
			_, createErr = roleStore.Create(ctx, q, "editor", []string{"agents:read"})
			assert.ErrorIs(t, createErr, tenant.ErrRoleDuplicate)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("List", func(t *testing.T) {
		ten3, err := tenantStore.Create(ctx, "List Role Org", "list-role-org")
		require.NoError(t, err)

		err = database.WithTenantConnection(ctx, rlsPool, ten3.ID, func(ctx context.Context, q database.Querier) error {
			_, createErr := roleStore.Create(ctx, q, "admin", []string{"*"})
			require.NoError(t, createErr)
			_, createErr = roleStore.Create(ctx, q, "viewer", []string{"agents:read"})
			require.NoError(t, createErr)

			roles, listErr := roleStore.List(ctx, q)
			require.NoError(t, listErr)
			assert.Len(t, roles, 2)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("AssignAndListForUser", func(t *testing.T) {
		ten4, err := tenantStore.Create(ctx, "Assign Org", "assign-org")
		require.NoError(t, err)

		err = database.WithTenantConnection(ctx, rlsPool, ten4.ID, func(ctx context.Context, q database.Querier) error {
			role, createErr := roleStore.Create(ctx, q, "manager", []string{"agents:write"})
			require.NoError(t, createErr)
			user, createErr := userStore.Create(ctx, q, "mgr@test.com", "Manager")
			require.NoError(t, createErr)

			// Assign role scoped to org
			assignErr := roleStore.AssignToUser(ctx, q, user.ID, role.ID, "org", ten4.ID)
			require.NoError(t, assignErr)

			// List roles for user
			roles, listErr := roleStore.ListForUser(ctx, q, user.ID)
			require.NoError(t, listErr)
			assert.Len(t, roles, 1)
			assert.Equal(t, role.ID, roles[0].RoleID)
			assert.Equal(t, "manager", roles[0].RoleName)
			assert.Equal(t, "org", roles[0].ScopeType)

			return nil
		})
		require.NoError(t, err)
	})

	t.Run("LoadRoles", func(t *testing.T) {
		tenLR, err := tenantStore.Create(ctx, "LoadRoles Org", "loadroles-org")
		require.NoError(t, err)

		// Create roles in tenant context
		err = database.WithTenantConnection(ctx, rlsPool, tenLR.ID, func(ctx context.Context, q database.Querier) error {
			_, createErr := roleStore.Create(ctx, q, "admin", []string{"*"})
			require.NoError(t, createErr)
			_, createErr = roleStore.Create(ctx, q, "viewer", []string{"agents:read"})
			require.NoError(t, createErr)
			return nil
		})
		require.NoError(t, err)

		// LoadRoles uses the owner pool directly (no RLS — cross-tenant)
		roles, loadErr := roleStore.LoadRoles(ctx, ownerPool)
		require.NoError(t, loadErr)
		require.GreaterOrEqual(t, len(roles), 2)

		// Find our roles and verify they carry the correct tenant ID
		found := map[string]bool{}
		for _, r := range roles {
			if r.TenantID == tenLR.ID && (r.Name == "admin" || r.Name == "viewer") {
				found[r.Name] = true
			}
		}
		assert.True(t, found["admin"])
		assert.True(t, found["viewer"])
	})

	t.Run("RemoveFromUser", func(t *testing.T) {
		ten5, err := tenantStore.Create(ctx, "Remove Role Org", "remove-role-org")
		require.NoError(t, err)

		err = database.WithTenantConnection(ctx, rlsPool, ten5.ID, func(ctx context.Context, q database.Querier) error {
			role, createErr := roleStore.Create(ctx, q, "temp", []string{"agents:read"})
			require.NoError(t, createErr)
			user, createErr := userStore.Create(ctx, q, "temp@test.com", "Temp")
			require.NoError(t, createErr)

			assignErr := roleStore.AssignToUser(ctx, q, user.ID, role.ID, "org", ten5.ID)
			require.NoError(t, assignErr)

			removeErr := roleStore.RemoveFromUser(ctx, q, user.ID, role.ID, "org", ten5.ID)
			require.NoError(t, removeErr)

			roles, listErr := roleStore.ListForUser(ctx, q, user.ID)
			require.NoError(t, listErr)
			assert.Len(t, roles, 0)

			return nil
		})
		require.NoError(t, err)
	})
}
