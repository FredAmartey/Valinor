package tenant_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/platform/database"
	"github.com/valinor-ai/valinor/internal/tenant"
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
