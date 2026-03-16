package tenant_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/FredAmartey/heimdall/internal/platform/database"
	"github.com/FredAmartey/heimdall/internal/tenant"
)

func TestUserStore(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ownerPool, rlsPool, cleanup := setupTestDBWithRLS(t)
	defer cleanup()

	ctx := context.Background()
	tenantStore := tenant.NewStore(ownerPool)
	ten, err := tenantStore.Create(ctx, "User Org", "user-org")
	require.NoError(t, err)

	userStore := tenant.NewUserStore()
	deptStore := tenant.NewDepartmentStore()

	t.Run("Create", func(t *testing.T) {
		err := database.WithTenantConnection(ctx, rlsPool, ten.ID, func(ctx context.Context, q database.Querier) error {
			user, createErr := userStore.Create(ctx, q, "alice@example.com", "Alice")
			require.NoError(t, createErr)
			assert.NotEmpty(t, user.ID)
			assert.Equal(t, ten.ID, user.TenantID)
			assert.Equal(t, "alice@example.com", user.Email)
			assert.Equal(t, "Alice", user.DisplayName)
			assert.Equal(t, "active", user.Status)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("Create_InvalidEmail", func(t *testing.T) {
		err := database.WithTenantConnection(ctx, rlsPool, ten.ID, func(ctx context.Context, q database.Querier) error {
			_, createErr := userStore.Create(ctx, q, "not-an-email", "Bad")
			assert.ErrorIs(t, createErr, tenant.ErrEmailInvalid)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("Create_DuplicateEmail", func(t *testing.T) {
		ten2, err := tenantStore.Create(ctx, "Dup Org", "dup-org")
		require.NoError(t, err)

		err = database.WithTenantConnection(ctx, rlsPool, ten2.ID, func(ctx context.Context, q database.Querier) error {
			_, createErr := userStore.Create(ctx, q, "dup@example.com", "First")
			require.NoError(t, createErr)
			_, createErr = userStore.Create(ctx, q, "dup@example.com", "Second")
			assert.ErrorIs(t, createErr, tenant.ErrEmailDuplicate)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("GetByID", func(t *testing.T) {
		ten3, err := tenantStore.Create(ctx, "Get Org", "get-org")
		require.NoError(t, err)

		err = database.WithTenantConnection(ctx, rlsPool, ten3.ID, func(ctx context.Context, q database.Querier) error {
			created, createErr := userStore.Create(ctx, q, "bob@example.com", "Bob")
			require.NoError(t, createErr)

			got, getErr := userStore.GetByID(ctx, q, created.ID)
			require.NoError(t, getErr)
			assert.Equal(t, "bob@example.com", got.Email)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("List", func(t *testing.T) {
		ten4, err := tenantStore.Create(ctx, "List Org", "list-user-org")
		require.NoError(t, err)

		err = database.WithTenantConnection(ctx, rlsPool, ten4.ID, func(ctx context.Context, q database.Querier) error {
			_, createErr := userStore.Create(ctx, q, "u1@example.com", "User 1")
			require.NoError(t, createErr)
			_, createErr = userStore.Create(ctx, q, "u2@example.com", "User 2")
			require.NoError(t, createErr)

			users, listErr := userStore.List(ctx, q)
			require.NoError(t, listErr)
			assert.Len(t, users, 2)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("Update_DisplayName", func(t *testing.T) {
		err := database.WithTenantConnection(ctx, rlsPool, ten.ID, func(ctx context.Context, q database.Querier) error {
			user, createErr := userStore.Create(ctx, q, "update@example.com", "Original")
			require.NoError(t, createErr)

			updated, updateErr := userStore.Update(ctx, q, user.ID, "Updated Name", "")
			require.NoError(t, updateErr)
			assert.Equal(t, "Updated Name", updated.DisplayName)
			assert.Equal(t, "active", updated.Status)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("Update_Status", func(t *testing.T) {
		err := database.WithTenantConnection(ctx, rlsPool, ten.ID, func(ctx context.Context, q database.Querier) error {
			user, createErr := userStore.Create(ctx, q, "suspend@example.com", "Suspend Me")
			require.NoError(t, createErr)

			updated, updateErr := userStore.Update(ctx, q, user.ID, "", "suspended")
			require.NoError(t, updateErr)
			assert.Equal(t, "suspended", updated.Status)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("Update_NotFound", func(t *testing.T) {
		err := database.WithTenantConnection(ctx, rlsPool, ten.ID, func(ctx context.Context, q database.Querier) error {
			_, updateErr := userStore.Update(ctx, q, "00000000-0000-0000-0000-000000000000", "Name", "")
			assert.ErrorIs(t, updateErr, tenant.ErrUserNotFound)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("SoftDelete", func(t *testing.T) {
		err := database.WithTenantConnection(ctx, rlsPool, ten.ID, func(ctx context.Context, q database.Querier) error {
			user, createErr := userStore.Create(ctx, q, "delete@example.com", "Delete Me")
			require.NoError(t, createErr)

			deleteErr := userStore.SoftDelete(ctx, q, user.ID)
			require.NoError(t, deleteErr)

			got, getErr := userStore.GetByID(ctx, q, user.ID)
			require.NoError(t, getErr)
			assert.Equal(t, "suspended", got.Status)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("DepartmentMembership", func(t *testing.T) {
		ten5, err := tenantStore.Create(ctx, "Dept Membership Org", "dept-member-org")
		require.NoError(t, err)

		err = database.WithTenantConnection(ctx, rlsPool, ten5.ID, func(ctx context.Context, q database.Querier) error {
			user, createErr := userStore.Create(ctx, q, "member@example.com", "Member")
			require.NoError(t, createErr)
			dept, createErr := deptStore.Create(ctx, q, "Engineering", nil)
			require.NoError(t, createErr)

			// Add to department
			addErr := userStore.AddToDepartment(ctx, q, user.ID, dept.ID)
			require.NoError(t, addErr)

			// List departments
			departments, listErr := userStore.ListDepartments(ctx, q, user.ID)
			require.NoError(t, listErr)
			assert.Len(t, departments, 1)
			assert.Equal(t, dept.ID, departments[0].ID)

			// Remove from department
			removeErr := userStore.RemoveFromDepartment(ctx, q, user.ID, dept.ID)
			require.NoError(t, removeErr)

			departments, listErr = userStore.ListDepartments(ctx, q, user.ID)
			require.NoError(t, listErr)
			assert.Len(t, departments, 0)

			return nil
		})
		require.NoError(t, err)
	})
}
