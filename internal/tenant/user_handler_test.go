package tenant_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/platform/database"
	"github.com/valinor-ai/valinor/internal/tenant"
)

func TestUserHandler(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ownerPool, rlsPool, cleanup := setupTestDBWithRLS(t)
	defer cleanup()

	ctx := context.Background()
	tenantStore := tenant.NewStore(ownerPool)
	ten, err := tenantStore.Create(ctx, "User Handler Org", "user-handler-org")
	require.NoError(t, err)

	handler := tenant.NewUserHandler(rlsPool, tenant.NewUserStore(), tenant.NewDepartmentStore())

	t.Run("Create", func(t *testing.T) {
		body := `{"email": "alice@example.com", "display_name": "Alice"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withTenantIdentity(req, ten.ID)
		w := httptest.NewRecorder()

		wrapWithTenantCtx(handler.HandleCreate).ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		var user tenant.User
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &user))
		assert.Equal(t, "alice@example.com", user.Email)
	})

	t.Run("Create_InvalidEmail", func(t *testing.T) {
		body := `{"email": "bad", "display_name": "Bad"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withTenantIdentity(req, ten.ID)
		w := httptest.NewRecorder()

		wrapWithTenantCtx(handler.HandleCreate).ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Get", func(t *testing.T) {
		// Create user first
		var userID string
		err := database.WithTenantConnection(ctx, rlsPool, ten.ID, func(ctx context.Context, q database.Querier) error {
			u, createErr := tenant.NewUserStore().Create(ctx, q, "getme@example.com", "Get Me")
			if createErr != nil {
				return createErr
			}
			userID = u.ID
			return nil
		})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/users/"+userID, nil)
		req.SetPathValue("id", userID)
		req = withTenantIdentity(req, ten.ID)
		w := httptest.NewRecorder()

		wrapWithTenantCtx(handler.HandleGet).ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("List", func(t *testing.T) {
		ten2, err := tenantStore.Create(ctx, "User List Org", "user-list-org")
		require.NoError(t, err)

		err = database.WithTenantConnection(ctx, rlsPool, ten2.ID, func(ctx context.Context, q database.Querier) error {
			_, createErr := tenant.NewUserStore().Create(ctx, q, "u1@test.com", "U1")
			require.NoError(t, createErr)
			_, createErr = tenant.NewUserStore().Create(ctx, q, "u2@test.com", "U2")
			require.NoError(t, createErr)
			return nil
		})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
		req = withTenantIdentity(req, ten2.ID)
		w := httptest.NewRecorder()

		wrapWithTenantCtx(handler.HandleList).ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var users []tenant.User
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &users))
		assert.Len(t, users, 2)
	})

	t.Run("AddToDepartment", func(t *testing.T) {
		ten3, err := tenantStore.Create(ctx, "Dept Member Org", "dept-member-handler-org")
		require.NoError(t, err)

		var userID, deptID string
		err = database.WithTenantConnection(ctx, rlsPool, ten3.ID, func(ctx context.Context, q database.Querier) error {
			u, createErr := tenant.NewUserStore().Create(ctx, q, "member@test.com", "Member")
			require.NoError(t, createErr)
			userID = u.ID
			d, createErr := tenant.NewDepartmentStore().Create(ctx, q, "Eng", nil)
			require.NoError(t, createErr)
			deptID = d.ID
			return nil
		})
		require.NoError(t, err)

		body := `{"department_id": "` + deptID + `"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/users/"+userID+"/departments", strings.NewReader(body))
		req.SetPathValue("id", userID)
		req.Header.Set("Content-Type", "application/json")
		req = withTenantIdentity(req, ten3.ID)
		w := httptest.NewRecorder()

		wrapWithTenantCtx(handler.HandleAddToDepartment).ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("RemoveFromDepartment", func(t *testing.T) {
		ten4, err := tenantStore.Create(ctx, "Remove Dept Org", "remove-dept-org")
		require.NoError(t, err)

		var userID, deptID string
		err = database.WithTenantConnection(ctx, rlsPool, ten4.ID, func(ctx context.Context, q database.Querier) error {
			u, createErr := tenant.NewUserStore().Create(ctx, q, "removeme@test.com", "Remove")
			require.NoError(t, createErr)
			userID = u.ID
			d, createErr := tenant.NewDepartmentStore().Create(ctx, q, "Eng", nil)
			require.NoError(t, createErr)
			deptID = d.ID
			addErr := tenant.NewUserStore().AddToDepartment(ctx, q, userID, deptID)
			require.NoError(t, addErr)
			return nil
		})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/"+userID+"/departments/"+deptID, nil)
		req.SetPathValue("id", userID)
		req.SetPathValue("deptId", deptID)
		req = withTenantIdentity(req, ten4.ID)
		w := httptest.NewRecorder()

		wrapWithTenantCtx(handler.HandleRemoveFromDepartment).ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}
