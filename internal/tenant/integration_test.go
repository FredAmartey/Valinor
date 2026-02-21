package tenant_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/platform/server"
	"github.com/valinor-ai/valinor/internal/rbac"
	"github.com/valinor-ai/valinor/internal/tenant"
)

func TestEndToEnd_TenantOrgSetup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ownerPool, rlsPool, cleanup := setupTestDBWithRLS(t)
	defer cleanup()

	// Create all stores and handlers
	tenantStore := tenant.NewStore(ownerPool)
	deptStore := tenant.NewDepartmentStore()
	userStore := tenant.NewUserStore()
	roleStore := tenant.NewRoleStore()

	tenantHandler := tenant.NewHandler(tenantStore)
	deptHandler := tenant.NewDepartmentHandler(rlsPool, deptStore)
	userHandler := tenant.NewUserHandler(rlsPool, userStore, deptStore)
	roleHandler := tenant.NewRoleHandler(rlsPool, roleStore, userStore)

	// Wire up server with RBAC
	tokenSvc := auth.NewTokenService(testSigningKey, "test", 24, 168) //nolint:gosec // test-only key
	rbacEngine := rbac.NewEvaluator(nil)
	rbacEngine.RegisterRole("org_admin", []string{"*"})

	srv := server.New(":0", server.Dependencies{
		Pool:              ownerPool,
		Auth:              tokenSvc,
		RBAC:              rbacEngine,
		TenantHandler:     tenantHandler,
		DepartmentHandler: deptHandler,
		UserHandler:       userHandler,
		RoleHandler:       roleHandler,
		DevMode:           true,
		DevIdentity: &auth.Identity{
			UserID:          "e2e-admin",
			TenantID:        "will-be-set-per-request",
			Roles:           []string{"org_admin"},
			IsPlatformAdmin: true,
		},
	})

	handler := srv.Handler()

	// Step 1: Create tenant (platform admin)
	body := `{"name": "Chelsea FC", "slug": "chelsea-fc"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer dev")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code, "create tenant: %s", w.Body.String())

	var tenantResp tenant.Tenant
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &tenantResp))
	tenantID := tenantResp.ID

	// For remaining requests, we need a token with the real tenant ID
	devIdentity := &auth.Identity{
		UserID:   "e2e-admin",
		TenantID: tenantID,
		Roles:    []string{"org_admin"},
	}
	accessToken, err := tokenSvc.CreateAccessToken(devIdentity)
	require.NoError(t, err)

	// Step 2: Create departments
	for _, deptName := range []string{"Scouting", "First Team", "Academy"} {
		body = `{"name": "` + deptName + `"}`
		req = httptest.NewRequest(http.MethodPost, "/api/v1/departments", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+accessToken)
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusCreated, w.Code, "create dept %s: %s", deptName, w.Body.String())
	}

	// Step 3: List departments
	req = httptest.NewRequest(http.MethodGet, "/api/v1/departments", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var departments []tenant.Department
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &departments))
	assert.Len(t, departments, 3)

	scoutingDeptID := departments[0].ID // first created

	// Step 4: Create user
	body = `{"email": "scout-a@chelsea.com", "display_name": "Scout A"}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code, "create user: %s", w.Body.String())

	var userResp tenant.User
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &userResp))
	userID := userResp.ID

	// Step 5: Add user to Scouting department
	body = `{"department_id": "` + scoutingDeptID + `"}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/users/"+userID+"/departments", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "add to dept: %s", w.Body.String())

	// Step 6: Create role
	body = `{"name": "scout", "permissions": ["agents:read", "agents:message"]}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/roles", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code, "create role: %s", w.Body.String())

	var roleResp tenant.Role
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &roleResp))
	roleID := roleResp.ID

	// Step 7: Assign role to user (scoped to department)
	body = `{"role_id": "` + roleID + `", "scope_type": "department", "scope_id": "` + scoutingDeptID + `"}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/users/"+userID+"/roles", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "assign role: %s", w.Body.String())

	// Step 8: Verify user's roles
	req = httptest.NewRequest(http.MethodGet, "/api/v1/users/"+userID+"/roles", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var userRoles []tenant.UserRole
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &userRoles))
	assert.Len(t, userRoles, 1)
	assert.Equal(t, "scout", userRoles[0].RoleName)
	assert.Equal(t, "department", userRoles[0].ScopeType)
	assert.Equal(t, scoutingDeptID, userRoles[0].ScopeID)
}
