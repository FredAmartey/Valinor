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
	handler := orchestrator.NewHandler(mgr)
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

func TestHandler_GetAgent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	driver := orchestrator.NewMockDriver()
	store := orchestrator.NewStore()
	mgr := orchestrator.NewManager(pool, driver, store, orchestrator.ManagerConfig{Driver: "mock"})
	handler := orchestrator.NewHandler(mgr)
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
	handler := orchestrator.NewHandler(mgr)
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

func TestHandler_DestroyAgent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	driver := orchestrator.NewMockDriver()
	store := orchestrator.NewStore()
	mgr := orchestrator.NewManager(pool, driver, store, orchestrator.ManagerConfig{Driver: "mock"})
	handler := orchestrator.NewHandler(mgr)
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
