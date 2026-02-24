package orchestrator_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/orchestrator"
)

func TestManager_Provision_ColdStart(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	driver := orchestrator.NewMockDriver()
	store := orchestrator.NewStore()
	cfg := orchestrator.ManagerConfig{Driver: "mock", WarmPoolSize: 0, WorkspaceDataQuotaMB: 512}
	mgr := orchestrator.NewManager(pool, driver, store, cfg)
	ctx := context.Background()

	// Create tenant
	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Test', 'test') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	inst, err := mgr.Provision(ctx, tenantID, orchestrator.ProvisionOpts{})
	require.NoError(t, err)
	assert.NotEmpty(t, inst.ID)
	assert.Equal(t, orchestrator.StatusRunning, inst.Status)
	assert.Equal(t, &tenantID, inst.TenantID)
	assert.Equal(t, 1, driver.RunningCount())
	require.NotNil(t, inst.VMID)
	spec, ok := driver.LastSpec(*inst.VMID)
	require.True(t, ok)
	assert.Equal(t, 512, spec.DataDriveQuotaMB)
}

func TestManager_Provision_FromWarmPool(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	driver := orchestrator.NewMockDriver()
	store := orchestrator.NewStore()
	cfg := orchestrator.ManagerConfig{Driver: "mock", WarmPoolSize: 2}
	mgr := orchestrator.NewManager(pool, driver, store, cfg)
	ctx := context.Background()

	// Create tenant
	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Test', 'test') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	// Pre-create a warm VM in the DB
	warmInst := &orchestrator.AgentInstance{
		Status:        orchestrator.StatusWarm,
		Config:        "{}",
		VMDriver:      "mock",
		ToolAllowlist: "[]",
		VsockCID:      ptrUint32(3),
	}
	err = store.Create(ctx, pool, warmInst)
	require.NoError(t, err)

	// Also start it in the mock driver (warm VMs are running)
	_, err = driver.Start(ctx, orchestrator.VMSpec{VMID: "warm-vm", VsockCID: 3})
	require.NoError(t, err)

	// Provision should claim the warm VM
	inst, err := mgr.Provision(ctx, tenantID, orchestrator.ProvisionOpts{})
	require.NoError(t, err)
	assert.Equal(t, warmInst.ID, inst.ID)
	assert.Equal(t, orchestrator.StatusRunning, inst.Status)
}

func TestManager_Destroy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	driver := orchestrator.NewMockDriver()
	store := orchestrator.NewStore()
	cfg := orchestrator.ManagerConfig{Driver: "mock"}
	mgr := orchestrator.NewManager(pool, driver, store, cfg)
	ctx := context.Background()

	// Create tenant and provision
	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Test', 'test') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	inst, err := mgr.Provision(ctx, tenantID, orchestrator.ProvisionOpts{})
	require.NoError(t, err)

	// Destroy
	err = mgr.Destroy(ctx, inst.ID)
	require.NoError(t, err)

	// Verify destroyed in DB
	got, err := mgr.GetByID(ctx, inst.ID)
	require.NoError(t, err)
	assert.Equal(t, orchestrator.StatusDestroyed, got.Status)

	// Verify VM cleaned up in driver
	assert.Equal(t, 0, driver.RunningCount())
}

func TestManager_Destroy_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	driver := orchestrator.NewMockDriver()
	store := orchestrator.NewStore()
	mgr := orchestrator.NewManager(pool, driver, store, orchestrator.ManagerConfig{Driver: "mock"})

	err := mgr.Destroy(context.Background(), "00000000-0000-0000-0000-000000000000")
	assert.ErrorIs(t, err, orchestrator.ErrVMNotFound)
}

func TestManager_ReconcileOnce(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	driver := orchestrator.NewMockDriver()
	store := orchestrator.NewStore()
	cfg := orchestrator.ManagerConfig{
		Driver:       "mock",
		WarmPoolSize: 2,
	}
	mgr := orchestrator.NewManager(pool, driver, store, cfg)
	ctx := context.Background()

	// Initially no warm VMs
	count, err := store.CountByStatus(ctx, pool, orchestrator.StatusWarm)
	require.NoError(t, err)
	assert.Equal(t, 0, count)

	// Run reconcile once — should create 2 warm VMs
	mgr.ReconcileOnce(ctx)

	count, err = store.CountByStatus(ctx, pool, orchestrator.StatusWarm)
	require.NoError(t, err)
	assert.Equal(t, 2, count)
	assert.Equal(t, 2, driver.RunningCount())
}

func TestManager_HealthCheckOnce_ReplacesUnhealthy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	driver := orchestrator.NewMockDriver()
	store := orchestrator.NewStore()
	cfg := orchestrator.ManagerConfig{
		Driver:                 "mock",
		WarmPoolSize:           0, // don't auto-replenish
		MaxConsecutiveFailures: 2,
	}
	mgr := orchestrator.NewManager(pool, driver, store, cfg)
	ctx := context.Background()

	// Create tenant and provision
	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Test', 'test') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	inst, err := mgr.Provision(ctx, tenantID, orchestrator.ProvisionOpts{})
	require.NoError(t, err)

	// Make VM unhealthy in the mock driver
	driver.SetUnhealthy(*inst.VMID)

	// Health check 1 — failure 1
	mgr.HealthCheckOnce(ctx)
	got, _ := mgr.GetByID(ctx, inst.ID)
	assert.Equal(t, 1, got.ConsecutiveFailures)
	assert.Equal(t, orchestrator.StatusRunning, got.Status)

	// Health check 2 — failure 2, hits threshold, triggers replacement
	mgr.HealthCheckOnce(ctx)
	got, _ = mgr.GetByID(ctx, inst.ID)
	assert.Equal(t, orchestrator.StatusDestroyed, got.Status)
}
