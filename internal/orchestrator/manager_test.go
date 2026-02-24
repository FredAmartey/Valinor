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

func TestManager_Provision_ReusesRunningUserAgent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	driver := orchestrator.NewMockDriver()
	store := orchestrator.NewStore()
	cfg := orchestrator.ManagerConfig{Driver: "mock", WarmPoolSize: 0}
	mgr := orchestrator.NewManager(pool, driver, store, cfg)
	ctx := context.Background()

	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Reuse Tenant', 'reuse-tenant') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	existing := &orchestrator.AgentInstance{
		TenantID:      &tenantID,
		UserID:        ptrString("user-123"),
		Status:        orchestrator.StatusRunning,
		Config:        "{}",
		VMID:          ptrString("existing-vm"),
		VsockCID:      ptrUint32(42),
		VMDriver:      "mock",
		ToolAllowlist: "[]",
	}
	require.NoError(t, store.Create(ctx, pool, existing))

	inst, err := mgr.Provision(ctx, tenantID, orchestrator.ProvisionOpts{
		UserID: ptrString("user-123"),
	})
	require.NoError(t, err)
	assert.Equal(t, existing.ID, inst.ID)
	assert.Equal(t, 0, driver.RunningCount(), "provision should not cold-start when user agent already exists")
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

func TestManager_HealthCheckOnce_ReplacesUnhealthyPreservesUserAffinity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	driver := orchestrator.NewMockDriver()
	store := orchestrator.NewStore()
	cfg := orchestrator.ManagerConfig{
		Driver:                 "mock",
		WarmPoolSize:           0,
		MaxConsecutiveFailures: 1,
	}
	mgr := orchestrator.NewManager(pool, driver, store, cfg)
	ctx := context.Background()

	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Affinity Replace', 'affinity-replace') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	inst, err := mgr.Provision(ctx, tenantID, orchestrator.ProvisionOpts{
		UserID: ptrString("user-42"),
	})
	require.NoError(t, err)
	require.NotNil(t, inst.UserID)
	assert.Equal(t, "user-42", *inst.UserID)

	driver.SetUnhealthy(*inst.VMID)
	mgr.HealthCheckOnce(ctx)

	agents, err := mgr.ListByTenant(ctx, tenantID)
	require.NoError(t, err)

	var replacement *orchestrator.AgentInstance
	for i := range agents {
		if agents[i].Status == orchestrator.StatusRunning {
			replacement = &agents[i]
			break
		}
	}

	require.NotNil(t, replacement)
	assert.NotEqual(t, inst.ID, replacement.ID)
	require.NotNil(t, replacement.UserID)
	assert.Equal(t, "user-42", *replacement.UserID)
}

func TestManager_HealthCheckOnce_DoesNotReplaceWhenDestroyStatusUpdateFails(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	driver := orchestrator.NewMockDriver()
	store := orchestrator.NewStore()
	cfg := orchestrator.ManagerConfig{
		Driver:                 "mock",
		WarmPoolSize:           0,
		MaxConsecutiveFailures: 1,
	}
	mgr := orchestrator.NewManager(pool, driver, store, cfg)
	ctx := context.Background()

	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Destroy Fail Tenant', 'destroy-fail-tenant') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	_, err = pool.Exec(ctx, `
		CREATE OR REPLACE FUNCTION fail_agent_destroyed_status_update()
		RETURNS trigger AS $$
		BEGIN
			IF NEW.status = 'destroyed' THEN
				RAISE EXCEPTION 'blocked destroyed status update';
			END IF;
			RETURN NEW;
		END;
		$$ LANGUAGE plpgsql;
	`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `
		CREATE TRIGGER trg_fail_agent_destroyed_status_update
		BEFORE UPDATE OF status ON agent_instances
		FOR EACH ROW
		EXECUTE FUNCTION fail_agent_destroyed_status_update();
	`)
	require.NoError(t, err)

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP TRIGGER IF EXISTS trg_fail_agent_destroyed_status_update ON agent_instances`)
		_, _ = pool.Exec(context.Background(), `DROP FUNCTION IF EXISTS fail_agent_destroyed_status_update()`)
	})

	inst, err := mgr.Provision(ctx, tenantID, orchestrator.ProvisionOpts{})
	require.NoError(t, err)

	driver.SetUnhealthy(*inst.VMID)
	mgr.HealthCheckOnce(ctx)

	agents, err := mgr.ListByTenant(ctx, tenantID)
	require.NoError(t, err)
	require.Len(t, agents, 1, "replacement should not be provisioned when marking destroyed fails")
	assert.Equal(t, inst.ID, agents[0].ID)
	assert.Equal(t, orchestrator.StatusUnhealthy, agents[0].Status)
}
