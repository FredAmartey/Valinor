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

func TestRoleHandler(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ownerPool, rlsPool, cleanup := setupTestDBWithRLS(t)
	defer cleanup()

	ctx := context.Background()
	tenantStore := tenant.NewStore(ownerPool)
	ten, err := tenantStore.Create(ctx, "Role Handler Org", "role-handler-org")
	require.NoError(t, err)

	handler := tenant.NewRoleHandler(rlsPool, tenant.NewRoleStore(), tenant.NewUserStore(), tenant.NewDepartmentStore(), nil)

	t.Run("Create", func(t *testing.T) {
		body := `{"name": "viewer", "permissions": ["agents:read"]}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/roles", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withTenantIdentity(req, ten.ID)
		w := httptest.NewRecorder()

		wrapWithTenantCtx(handler.HandleCreate).ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		var role tenant.Role
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &role))
		assert.Equal(t, "viewer", role.Name)
		assert.Equal(t, []string{"agents:read"}, role.Permissions)
	})

	t.Run("List", func(t *testing.T) {
		ten2, err := tenantStore.Create(ctx, "Role List Org", "role-list-org")
		require.NoError(t, err)

		err = database.WithTenantConnection(ctx, rlsPool, ten2.ID, func(ctx context.Context, q database.Querier) error {
			_, createErr := tenant.NewRoleStore().Create(ctx, q, "admin", []string{"*"})
			require.NoError(t, createErr)
			_, createErr = tenant.NewRoleStore().Create(ctx, q, "reader", []string{"agents:read"})
			require.NoError(t, createErr)
			return nil
		})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/roles", nil)
		req = withTenantIdentity(req, ten2.ID)
		w := httptest.NewRecorder()

		wrapWithTenantCtx(handler.HandleList).ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var roles []tenant.Role
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &roles))
		assert.Len(t, roles, 2)
	})

	t.Run("AssignRole", func(t *testing.T) {
		ten3, err := tenantStore.Create(ctx, "Assign Handler Org", "assign-handler-org")
		require.NoError(t, err)

		var roleID, userID string
		err = database.WithTenantConnection(ctx, rlsPool, ten3.ID, func(ctx context.Context, q database.Querier) error {
			role, createErr := tenant.NewRoleStore().Create(ctx, q, "operator", []string{"agents:write"})
			require.NoError(t, createErr)
			roleID = role.ID
			user, createErr := tenant.NewUserStore().Create(ctx, q, "assign@test.com", "Assign")
			require.NoError(t, createErr)
			userID = user.ID
			return nil
		})
		require.NoError(t, err)

		body := `{"role_id": "` + roleID + `", "scope_type": "org", "scope_id": "` + ten3.ID + `"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/users/"+userID+"/roles", strings.NewReader(body))
		req.SetPathValue("id", userID)
		req.Header.Set("Content-Type", "application/json")
		req = withTenantIdentity(req, ten3.ID)
		w := httptest.NewRecorder()

		wrapWithTenantCtx(handler.HandleAssignRole).ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("IsolationProof_AssignRole_UserFromAnotherTenantDenied", func(t *testing.T) {
		tenantA, err := tenantStore.Create(ctx, "Role Cross User A", "role-cross-user-a")
		require.NoError(t, err)
		tenantB, err := tenantStore.Create(ctx, "Role Cross User B", "role-cross-user-b")
		require.NoError(t, err)

		var roleID string
		err = database.WithTenantConnection(ctx, rlsPool, tenantA.ID, func(ctx context.Context, q database.Querier) error {
			role, createErr := tenant.NewRoleStore().Create(ctx, q, "operator", []string{"agents:write"})
			require.NoError(t, createErr)
			roleID = role.ID
			return nil
		})
		require.NoError(t, err)

		var foreignUserID string
		err = database.WithTenantConnection(ctx, rlsPool, tenantB.ID, func(ctx context.Context, q database.Querier) error {
			user, createErr := tenant.NewUserStore().Create(ctx, q, "cross-user@test.com", "Cross User")
			require.NoError(t, createErr)
			foreignUserID = user.ID
			return nil
		})
		require.NoError(t, err)

		body := `{"role_id": "` + roleID + `", "scope_type": "org", "scope_id": "` + tenantA.ID + `"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/users/"+foreignUserID+"/roles", strings.NewReader(body))
		req.SetPathValue("id", foreignUserID)
		req.Header.Set("Content-Type", "application/json")
		req = withTenantIdentity(req, tenantA.ID)
		w := httptest.NewRecorder()

		wrapWithTenantCtx(handler.HandleAssignRole).ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Contains(t, w.Body.String(), "user not found")
	})

	t.Run("IsolationProof_AssignRole_DepartmentFromAnotherTenantDenied", func(t *testing.T) {
		tenantA, err := tenantStore.Create(ctx, "Role Cross Dept A", "role-cross-dept-a")
		require.NoError(t, err)
		tenantB, err := tenantStore.Create(ctx, "Role Cross Dept B", "role-cross-dept-b")
		require.NoError(t, err)

		var roleID, userID string
		err = database.WithTenantConnection(ctx, rlsPool, tenantA.ID, func(ctx context.Context, q database.Querier) error {
			role, createErr := tenant.NewRoleStore().Create(ctx, q, "operator", []string{"agents:write"})
			require.NoError(t, createErr)
			roleID = role.ID
			user, createErr := tenant.NewUserStore().Create(ctx, q, "cross-dept@test.com", "Cross Dept")
			require.NoError(t, createErr)
			userID = user.ID
			return nil
		})
		require.NoError(t, err)

		var foreignDeptID string
		err = database.WithTenantConnection(ctx, rlsPool, tenantB.ID, func(ctx context.Context, q database.Querier) error {
			dept, createErr := tenant.NewDepartmentStore().Create(ctx, q, "Secret Dept", nil)
			require.NoError(t, createErr)
			foreignDeptID = dept.ID
			return nil
		})
		require.NoError(t, err)

		body := `{"role_id": "` + roleID + `", "scope_type": "department", "scope_id": "` + foreignDeptID + `"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/users/"+userID+"/roles", strings.NewReader(body))
		req.SetPathValue("id", userID)
		req.Header.Set("Content-Type", "application/json")
		req = withTenantIdentity(req, tenantA.ID)
		w := httptest.NewRecorder()

		wrapWithTenantCtx(handler.HandleAssignRole).ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Contains(t, w.Body.String(), "department not found")
	})

	t.Run("RemoveRole", func(t *testing.T) {
		ten4, err := tenantStore.Create(ctx, "Remove Handler Org", "remove-handler-org")
		require.NoError(t, err)

		var roleID, userID string
		err = database.WithTenantConnection(ctx, rlsPool, ten4.ID, func(ctx context.Context, q database.Querier) error {
			role, createErr := tenant.NewRoleStore().Create(ctx, q, "temp", []string{"agents:read"})
			require.NoError(t, createErr)
			roleID = role.ID
			user, createErr := tenant.NewUserStore().Create(ctx, q, "remove@test.com", "Remove")
			require.NoError(t, createErr)
			userID = user.ID
			assignErr := tenant.NewRoleStore().AssignToUser(ctx, q, userID, roleID, "org", ten4.ID)
			require.NoError(t, assignErr)
			return nil
		})
		require.NoError(t, err)

		body := `{"role_id": "` + roleID + `", "scope_type": "org", "scope_id": "` + ten4.ID + `"}`
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/"+userID+"/roles", strings.NewReader(body))
		req.SetPathValue("id", userID)
		req.Header.Set("Content-Type", "application/json")
		req = withTenantIdentity(req, ten4.ID)
		w := httptest.NewRecorder()

		wrapWithTenantCtx(handler.HandleRemoveRole).ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("Update", func(t *testing.T) {
		tenU, err := tenantStore.Create(ctx, "Update Role Org", "update-role-org")
		require.NoError(t, err)

		var roleID string
		err = database.WithTenantConnection(ctx, rlsPool, tenU.ID, func(ctx context.Context, q database.Querier) error {
			role, createErr := tenant.NewRoleStore().Create(ctx, q, "custom_role", []string{"agents:read"})
			require.NoError(t, createErr)
			roleID = role.ID
			return nil
		})
		require.NoError(t, err)

		body := `{"name": "custom_role", "permissions": ["agents:read", "agents:write"]}`
		req := httptest.NewRequest(http.MethodPut, "/api/v1/roles/"+roleID, strings.NewReader(body))
		req.SetPathValue("id", roleID)
		req.Header.Set("Content-Type", "application/json")
		req = withTenantIdentity(req, tenU.ID)
		w := httptest.NewRecorder()

		wrapWithTenantCtx(handler.HandleUpdate).ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var role tenant.Role
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &role))
		assert.Equal(t, []string{"agents:read", "agents:write"}, role.Permissions)
	})

	t.Run("Update_SystemRole_Rejected", func(t *testing.T) {
		tenS, err := tenantStore.Create(ctx, "System Update Org", "system-update-org")
		require.NoError(t, err)

		var systemRoleID string
		err = database.WithTenantConnection(ctx, rlsPool, tenS.ID, func(ctx context.Context, q database.Querier) error {
			_, execErr := q.Exec(ctx,
				`INSERT INTO roles (tenant_id, name, permissions, is_system) VALUES (current_setting('app.current_tenant_id', true)::UUID, 'sys_admin', '["*"]'::jsonb, true) RETURNING id`)
			require.NoError(t, execErr)
			row := q.QueryRow(ctx, `SELECT id FROM roles WHERE name = 'sys_admin' AND tenant_id = current_setting('app.current_tenant_id', true)::UUID`)
			require.NoError(t, row.Scan(&systemRoleID))
			return nil
		})
		require.NoError(t, err)

		body := `{"name": "sys_admin", "permissions": ["agents:read"]}`
		req := httptest.NewRequest(http.MethodPut, "/api/v1/roles/"+systemRoleID, strings.NewReader(body))
		req.SetPathValue("id", systemRoleID)
		req.Header.Set("Content-Type", "application/json")
		req = withTenantIdentity(req, tenS.ID)
		w := httptest.NewRecorder()

		wrapWithTenantCtx(handler.HandleUpdate).ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("Update_WildcardRejected", func(t *testing.T) {
		tenW, err := tenantStore.Create(ctx, "Wildcard Update Org", "wildcard-update-org")
		require.NoError(t, err)

		var roleID string
		err = database.WithTenantConnection(ctx, rlsPool, tenW.ID, func(ctx context.Context, q database.Querier) error {
			role, createErr := tenant.NewRoleStore().Create(ctx, q, "sneaky", []string{"agents:read"})
			require.NoError(t, createErr)
			roleID = role.ID
			return nil
		})
		require.NoError(t, err)

		body := `{"name": "sneaky", "permissions": ["*"]}`
		req := httptest.NewRequest(http.MethodPut, "/api/v1/roles/"+roleID, strings.NewReader(body))
		req.SetPathValue("id", roleID)
		req.Header.Set("Content-Type", "application/json")
		req = withTenantIdentity(req, tenW.ID)
		w := httptest.NewRecorder()

		wrapWithTenantCtx(handler.HandleUpdate).ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Delete", func(t *testing.T) {
		tenD, err := tenantStore.Create(ctx, "Delete Role Org", "delete-role-org")
		require.NoError(t, err)

		var roleID string
		err = database.WithTenantConnection(ctx, rlsPool, tenD.ID, func(ctx context.Context, q database.Querier) error {
			role, createErr := tenant.NewRoleStore().Create(ctx, q, "temp_role", []string{"agents:read"})
			require.NoError(t, createErr)
			roleID = role.ID
			return nil
		})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/roles/"+roleID, nil)
		req.SetPathValue("id", roleID)
		req = withTenantIdentity(req, tenD.ID)
		w := httptest.NewRecorder()

		wrapWithTenantCtx(handler.HandleDelete).ServeHTTP(w, req)

		assert.Equal(t, http.StatusNoContent, w.Code)
	})

	t.Run("Delete_SystemRole_Rejected", func(t *testing.T) {
		tenDS, err := tenantStore.Create(ctx, "System Delete Org", "system-delete-org")
		require.NoError(t, err)

		var systemRoleID string
		err = database.WithTenantConnection(ctx, rlsPool, tenDS.ID, func(ctx context.Context, q database.Querier) error {
			_, execErr := q.Exec(ctx,
				`INSERT INTO roles (tenant_id, name, permissions, is_system) VALUES (current_setting('app.current_tenant_id', true)::UUID, 'sys_locked', '["*"]'::jsonb, true)`)
			require.NoError(t, execErr)
			row := q.QueryRow(ctx, `SELECT id FROM roles WHERE name = 'sys_locked' AND tenant_id = current_setting('app.current_tenant_id', true)::UUID`)
			require.NoError(t, row.Scan(&systemRoleID))
			return nil
		})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/roles/"+systemRoleID, nil)
		req.SetPathValue("id", systemRoleID)
		req = withTenantIdentity(req, tenDS.ID)
		w := httptest.NewRecorder()

		wrapWithTenantCtx(handler.HandleDelete).ServeHTTP(w, req)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("Delete_AssignedRole_Rejected", func(t *testing.T) {
		tenDA, err := tenantStore.Create(ctx, "Delete Assigned Org", "delete-assigned-org")
		require.NoError(t, err)

		var roleID string
		err = database.WithTenantConnection(ctx, rlsPool, tenDA.ID, func(ctx context.Context, q database.Querier) error {
			role, createErr := tenant.NewRoleStore().Create(ctx, q, "in_use", []string{"agents:read"})
			require.NoError(t, createErr)
			roleID = role.ID
			user, createErr := tenant.NewUserStore().Create(ctx, q, "assigned@test.com", "Assigned")
			require.NoError(t, createErr)
			assignErr := tenant.NewRoleStore().AssignToUser(ctx, q, user.ID, roleID, "org", tenDA.ID)
			require.NoError(t, assignErr)
			return nil
		})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/roles/"+roleID, nil)
		req.SetPathValue("id", roleID)
		req = withTenantIdentity(req, tenDA.ID)
		w := httptest.NewRecorder()

		wrapWithTenantCtx(handler.HandleDelete).ServeHTTP(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)
	})

	t.Run("ListUserRoles", func(t *testing.T) {
		ten5, err := tenantStore.Create(ctx, "List Roles Handler Org", "list-roles-handler-org")
		require.NoError(t, err)

		var userID string
		err = database.WithTenantConnection(ctx, rlsPool, ten5.ID, func(ctx context.Context, q database.Querier) error {
			role, createErr := tenant.NewRoleStore().Create(ctx, q, "analyst", []string{"agents:read"})
			require.NoError(t, createErr)
			user, createErr := tenant.NewUserStore().Create(ctx, q, "analyst@test.com", "Analyst")
			require.NoError(t, createErr)
			userID = user.ID
			assignErr := tenant.NewRoleStore().AssignToUser(ctx, q, userID, role.ID, "org", ten5.ID)
			require.NoError(t, assignErr)
			return nil
		})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/users/"+userID+"/roles", nil)
		req.SetPathValue("id", userID)
		req = withTenantIdentity(req, ten5.ID)
		w := httptest.NewRecorder()

		wrapWithTenantCtx(handler.HandleListUserRoles).ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var roles []tenant.UserRole
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &roles))
		assert.Len(t, roles, 1)
		assert.Equal(t, "analyst", roles[0].RoleName)
	})
}
