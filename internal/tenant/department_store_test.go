package tenant_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/FredAmartey/heimdall/internal/platform/database"
	"github.com/FredAmartey/heimdall/internal/tenant"
)

func TestDepartmentStore(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ownerPool, rlsPool, cleanup := setupTestDBWithRLS(t)
	defer cleanup()

	ctx := context.Background()
	tenantStore := tenant.NewStore(ownerPool)
	ten, err := tenantStore.Create(ctx, "Test Org", "test-org")
	require.NoError(t, err)

	store := tenant.NewDepartmentStore()

	t.Run("Create", func(t *testing.T) {
		err := database.WithTenantConnection(ctx, rlsPool, ten.ID, func(ctx context.Context, q database.Querier) error {
			dept, createErr := store.Create(ctx, q, "Engineering", nil)
			require.NoError(t, createErr)
			assert.NotEmpty(t, dept.ID)
			assert.Equal(t, ten.ID, dept.TenantID)
			assert.Equal(t, "Engineering", dept.Name)
			assert.Nil(t, dept.ParentID)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("Create_WithParent", func(t *testing.T) {
		err := database.WithTenantConnection(ctx, rlsPool, ten.ID, func(ctx context.Context, q database.Querier) error {
			parent, createErr := store.Create(ctx, q, "Product", nil)
			require.NoError(t, createErr)

			child, createErr := store.Create(ctx, q, "Backend", &parent.ID)
			require.NoError(t, createErr)
			assert.Equal(t, &parent.ID, child.ParentID)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("Create_EmptyName", func(t *testing.T) {
		err := database.WithTenantConnection(ctx, rlsPool, ten.ID, func(ctx context.Context, q database.Querier) error {
			_, createErr := store.Create(ctx, q, "", nil)
			assert.ErrorIs(t, createErr, tenant.ErrDepartmentNameEmpty)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("GetByID", func(t *testing.T) {
		err := database.WithTenantConnection(ctx, rlsPool, ten.ID, func(ctx context.Context, q database.Querier) error {
			created, createErr := store.Create(ctx, q, "Scouting", nil)
			require.NoError(t, createErr)

			got, getErr := store.GetByID(ctx, q, created.ID)
			require.NoError(t, getErr)
			assert.Equal(t, created.ID, got.ID)
			assert.Equal(t, "Scouting", got.Name)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("GetByID_NotFound", func(t *testing.T) {
		err := database.WithTenantConnection(ctx, rlsPool, ten.ID, func(ctx context.Context, q database.Querier) error {
			_, getErr := store.GetByID(ctx, q, "00000000-0000-0000-0000-000000000000")
			assert.ErrorIs(t, getErr, tenant.ErrDepartmentNotFound)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("Update_Name", func(t *testing.T) {
		err := database.WithTenantConnection(ctx, rlsPool, ten.ID, func(ctx context.Context, q database.Querier) error {
			dept, createErr := store.Create(ctx, q, "Old Name", nil)
			require.NoError(t, createErr)

			updated, updateErr := store.Update(ctx, q, dept.ID, "New Name", nil)
			require.NoError(t, updateErr)
			assert.Equal(t, "New Name", updated.Name)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("Update_Parent", func(t *testing.T) {
		err := database.WithTenantConnection(ctx, rlsPool, ten.ID, func(ctx context.Context, q database.Querier) error {
			parent, createErr := store.Create(ctx, q, "Parent Dept", nil)
			require.NoError(t, createErr)
			child, createErr := store.Create(ctx, q, "Child Dept", nil)
			require.NoError(t, createErr)

			updated, updateErr := store.Update(ctx, q, child.ID, "", &parent.ID)
			require.NoError(t, updateErr)
			assert.Equal(t, &parent.ID, updated.ParentID)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("Update_NotFound", func(t *testing.T) {
		err := database.WithTenantConnection(ctx, rlsPool, ten.ID, func(ctx context.Context, q database.Querier) error {
			_, updateErr := store.Update(ctx, q, "00000000-0000-0000-0000-000000000000", "Name", nil)
			assert.ErrorIs(t, updateErr, tenant.ErrDepartmentNotFound)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("Delete", func(t *testing.T) {
		err := database.WithTenantConnection(ctx, rlsPool, ten.ID, func(ctx context.Context, q database.Querier) error {
			dept, createErr := store.Create(ctx, q, "To Delete", nil)
			require.NoError(t, createErr)

			deleteErr := store.Delete(ctx, q, dept.ID)
			require.NoError(t, deleteErr)

			_, getErr := store.GetByID(ctx, q, dept.ID)
			assert.ErrorIs(t, getErr, tenant.ErrDepartmentNotFound)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("Delete_NotFound", func(t *testing.T) {
		err := database.WithTenantConnection(ctx, rlsPool, ten.ID, func(ctx context.Context, q database.Querier) error {
			deleteErr := store.Delete(ctx, q, "00000000-0000-0000-0000-000000000000")
			assert.ErrorIs(t, deleteErr, tenant.ErrDepartmentNotFound)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("List", func(t *testing.T) {
		// Create a fresh tenant to avoid interference from other subtests
		ten2, err := tenantStore.Create(ctx, "List Org", "list-org")
		require.NoError(t, err)

		err = database.WithTenantConnection(ctx, rlsPool, ten2.ID, func(ctx context.Context, q database.Querier) error {
			_, createErr := store.Create(ctx, q, "First Team", nil)
			require.NoError(t, createErr)
			_, createErr = store.Create(ctx, q, "Academy", nil)
			require.NoError(t, createErr)

			departments, listErr := store.List(ctx, q)
			require.NoError(t, listErr)
			assert.Len(t, departments, 2)
			return nil
		})
		require.NoError(t, err)
	})
}
