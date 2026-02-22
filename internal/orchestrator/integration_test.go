package orchestrator_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/orchestrator"
)

func TestIntegration_FullLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	driver := orchestrator.NewMockDriver()
	store := orchestrator.NewStore()
	cfg := orchestrator.ManagerConfig{
		Driver:                 "mock",
		WarmPoolSize:           2,
		MaxConsecutiveFailures: 2,
	}
	mgr := orchestrator.NewManager(pool, driver, store, cfg)
	ctx := context.Background()

	// 1. Create tenant
	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Chelsea FC', 'chelsea-fc') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	// 2. Replenish warm pool
	mgr.ReconcileOnce(ctx)
	warmCount, err := store.CountByStatus(ctx, pool, orchestrator.StatusWarm)
	require.NoError(t, err)
	assert.Equal(t, 2, warmCount, "warm pool should have 2 VMs")

	// 3. Provision agent from warm pool
	inst, err := mgr.Provision(ctx, tenantID, orchestrator.ProvisionOpts{})
	require.NoError(t, err)
	assert.Equal(t, orchestrator.StatusRunning, inst.Status)
	assert.Equal(t, &tenantID, inst.TenantID)

	// Warm pool should now have 1
	warmCount, err = store.CountByStatus(ctx, pool, orchestrator.StatusWarm)
	require.NoError(t, err)
	assert.Equal(t, 1, warmCount)

	// 4. Health check — should pass
	mgr.HealthCheckOnce(ctx)
	got, err := mgr.GetByID(ctx, inst.ID)
	require.NoError(t, err)
	assert.Equal(t, 0, got.ConsecutiveFailures)
	assert.NotNil(t, got.LastHealthCheck)

	// 5. Make VM unhealthy + trigger replacement
	if inst.VMID != nil {
		driver.SetUnhealthy(*inst.VMID)
	}
	mgr.HealthCheckOnce(ctx) // failure 1
	mgr.HealthCheckOnce(ctx) // failure 2 → replace

	got, err = mgr.GetByID(ctx, inst.ID)
	require.NoError(t, err)
	assert.Equal(t, orchestrator.StatusDestroyed, got.Status, "original should be destroyed")

	// 6. List by tenant — should show the replacement
	agents, err := mgr.ListByTenant(ctx, tenantID)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(agents), 1, "replacement agent should exist")

	var replacement *orchestrator.AgentInstance
	for i := range agents {
		if agents[i].Status == orchestrator.StatusRunning {
			replacement = &agents[i]
			break
		}
	}
	require.NotNil(t, replacement, "should have a running replacement")
	assert.NotEqual(t, inst.ID, replacement.ID, "replacement should be a different instance")

	// 7. Destroy the replacement
	err = mgr.Destroy(ctx, replacement.ID)
	require.NoError(t, err)

	got, err = mgr.GetByID(ctx, replacement.ID)
	require.NoError(t, err)
	assert.Equal(t, orchestrator.StatusDestroyed, got.Status)
}
