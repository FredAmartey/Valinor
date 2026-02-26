package orchestrator_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/orchestrator"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
)

func withIdentity(r *http.Request, tenantID string, platformAdmin bool) *http.Request {
	identity := &auth.Identity{
		UserID:          "test-user",
		TenantID:        tenantID,
		IsPlatformAdmin: platformAdmin,
	}
	ctx := auth.WithIdentity(r.Context(), identity)
	ctx = middleware.WithTenantID(ctx, tenantID)
	return r.WithContext(ctx)
}

func TestHandler_Provision(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	driver := orchestrator.NewMockDriver()
	store := orchestrator.NewStore()
	cfg := orchestrator.ManagerConfig{Driver: "mock"}
	mgr := orchestrator.NewManager(pool, driver, store, cfg)
	handler := orchestrator.NewHandler(mgr, nil, nil)
	ctx := context.Background()

	// Create tenant
	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Test', 'test') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	body := bytes.NewBufferString(`{}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents", body)
	req = withIdentity(req, tenantID, false)
	w := httptest.NewRecorder()

	handler.HandleProvision(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp orchestrator.AgentInstance
	err = json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.ID)
	assert.Equal(t, orchestrator.StatusRunning, resp.Status)
}

func TestHandler_Provision_BindsIdentityUserForNonAdmin(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	driver := orchestrator.NewMockDriver()
	store := orchestrator.NewStore()
	cfg := orchestrator.ManagerConfig{Driver: "mock"}
	mgr := orchestrator.NewManager(pool, driver, store, cfg)
	handler := orchestrator.NewHandler(mgr, nil, nil)
	ctx := context.Background()

	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Identity Bound', 'identity-bound') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents", bytes.NewBufferString(`{}`))
	req = withIdentity(req, tenantID, false)
	w := httptest.NewRecorder()

	handler.HandleProvision(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)

	var resp orchestrator.AgentInstance
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	require.NotNil(t, resp.UserID)
	assert.Equal(t, "test-user", *resp.UserID)
}

func TestHandler_Provision_AllowsAdminUserOverride(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	driver := orchestrator.NewMockDriver()
	store := orchestrator.NewStore()
	cfg := orchestrator.ManagerConfig{Driver: "mock"}
	mgr := orchestrator.NewManager(pool, driver, store, cfg)
	handler := orchestrator.NewHandler(mgr, nil, nil)
	ctx := context.Background()

	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Admin Override', 'admin-override') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents", bytes.NewBufferString(`{"user_id":"custom-admin-user"}`))
	req = withIdentity(req, tenantID, true)
	w := httptest.NewRecorder()

	handler.HandleProvision(w, req)
	assert.Equal(t, http.StatusCreated, w.Code)

	var resp orchestrator.AgentInstance
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	require.NotNil(t, resp.UserID)
	assert.Equal(t, "custom-admin-user", *resp.UserID)
}

func TestHandler_Provision_RejectsNonAdminUserSpoofing(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	driver := orchestrator.NewMockDriver()
	store := orchestrator.NewStore()
	cfg := orchestrator.ManagerConfig{Driver: "mock"}
	mgr := orchestrator.NewManager(pool, driver, store, cfg)
	handler := orchestrator.NewHandler(mgr, nil, nil)
	ctx := context.Background()

	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Spoof Reject', 'spoof-reject') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents", bytes.NewBufferString(`{"user_id":"other-user"}`))
	req = withIdentity(req, tenantID, false)
	w := httptest.NewRecorder()

	handler.HandleProvision(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestHandler_GetAgent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	driver := orchestrator.NewMockDriver()
	store := orchestrator.NewStore()
	mgr := orchestrator.NewManager(pool, driver, store, orchestrator.ManagerConfig{Driver: "mock"})
	handler := orchestrator.NewHandler(mgr, nil, nil)
	ctx := context.Background()

	// Create tenant and provision
	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Test', 'test') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	inst, err := mgr.Provision(ctx, tenantID, orchestrator.ProvisionOpts{})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/"+inst.ID, nil)
	req.SetPathValue("id", inst.ID)
	req = withIdentity(req, tenantID, false)
	w := httptest.NewRecorder()

	handler.HandleGetAgent(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestHandler_GetAgent_WrongTenant(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	driver := orchestrator.NewMockDriver()
	store := orchestrator.NewStore()
	mgr := orchestrator.NewManager(pool, driver, store, orchestrator.ManagerConfig{Driver: "mock"})
	handler := orchestrator.NewHandler(mgr, nil, nil)
	ctx := context.Background()

	// Create two tenants
	var tenantA, tenantB string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('A', 'a') RETURNING id",
	).Scan(&tenantA)
	require.NoError(t, err)
	err = pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('B', 'b') RETURNING id",
	).Scan(&tenantB)
	require.NoError(t, err)

	// Provision for tenant A
	inst, err := mgr.Provision(ctx, tenantA, orchestrator.ProvisionOpts{})
	require.NoError(t, err)

	// Tenant B tries to access tenant A's agent
	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents/"+inst.ID, nil)
	req.SetPathValue("id", inst.ID)
	req = withIdentity(req, tenantB, false)
	w := httptest.NewRecorder()

	handler.HandleGetAgent(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandler_Configure(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	driver := orchestrator.NewMockDriver()
	store := orchestrator.NewStore()
	mgr := orchestrator.NewManager(pool, driver, store, orchestrator.ManagerConfig{Driver: "mock"})
	handler := orchestrator.NewHandler(mgr, nil, nil)
	ctx := context.Background()

	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Test', 'test') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	inst, err := mgr.Provision(ctx, tenantID, orchestrator.ProvisionOpts{})
	require.NoError(t, err)

	body := bytes.NewBufferString(`{"config":{"model":"gpt-4"},"tool_allowlist":["search","code"]}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/"+inst.ID+"/configure", body)
	req.SetPathValue("id", inst.ID)
	req = withIdentity(req, tenantID, false)
	w := httptest.NewRecorder()

	handler.HandleConfigure(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp orchestrator.AgentInstance
	err = json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Contains(t, resp.Config, "gpt-4")
	assert.Contains(t, resp.ToolAllowlist, "search")

	var configMap map[string]any
	require.NoError(t, json.Unmarshal([]byte(resp.Config), &configMap))
	assert.Equal(t, "non-main", nestedLookupString(configMap, "agents", "defaults", "sandbox", "mode"))
	assert.Equal(t, true, nestedLookupBool(configMap, "tools", "exec", "workspaceOnly"))
	assert.Equal(t, true, nestedLookupBool(configMap, "tools", "exec", "applyPatch", "workspaceOnly"))
	assert.Equal(t, "loopback", nestedLookupString(configMap, "gateway", "bind"))
}

func TestHandler_Configure_RejectsInsecureRuntimePolicy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	driver := orchestrator.NewMockDriver()
	store := orchestrator.NewStore()
	mgr := orchestrator.NewManager(pool, driver, store, orchestrator.ManagerConfig{Driver: "mock"})
	handler := orchestrator.NewHandler(mgr, nil, nil)
	ctx := context.Background()

	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Policy Reject', 'policy-reject') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	inst, err := mgr.Provision(ctx, tenantID, orchestrator.ProvisionOpts{})
	require.NoError(t, err)

	body := bytes.NewBufferString(`{
		"config":{
			"agents":{"defaults":{"sandbox":{"mode":"off"}}}
		},
		"tool_allowlist":["search"]
	}`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/"+inst.ID+"/configure", body)
	req.SetPathValue("id", inst.ID)
	req = withIdentity(req, tenantID, false)
	w := httptest.NewRecorder()

	handler.HandleConfigure(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "sandbox.mode")
}

func nestedLookupString(root map[string]any, path ...string) string {
	val := nestedLookupAny(root, path...)
	str, _ := val.(string)
	return str
}

func nestedLookupBool(root map[string]any, path ...string) bool {
	val := nestedLookupAny(root, path...)
	boolean, _ := val.(bool)
	return boolean
}

func nestedLookupAny(root map[string]any, path ...string) any {
	current := any(root)
	for _, key := range path {
		m, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		next, ok := m[key]
		if !ok {
			return nil
		}
		current = next
	}
	return current
}

func TestHandler_DestroyAgent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	driver := orchestrator.NewMockDriver()
	store := orchestrator.NewStore()
	mgr := orchestrator.NewManager(pool, driver, store, orchestrator.ManagerConfig{Driver: "mock"})
	handler := orchestrator.NewHandler(mgr, nil, nil)
	ctx := context.Background()

	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Test', 'test') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	inst, err := mgr.Provision(ctx, tenantID, orchestrator.ProvisionOpts{})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/agents/"+inst.ID, nil)
	req.SetPathValue("id", inst.ID)
	req = withIdentity(req, tenantID, false)
	w := httptest.NewRecorder()

	handler.HandleDestroyAgent(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
}
