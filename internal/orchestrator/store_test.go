package orchestrator_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/valinor-ai/valinor/internal/orchestrator"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

func setupTestDB(t *testing.T) (*database.Pool, func()) {
	t.Helper()
	ctx := context.Background()

	container, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("valinor_test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2),
		),
	)
	require.NoError(t, err)

	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	err = database.RunMigrations(connStr, "file://../../migrations")
	require.NoError(t, err)

	pool, err := database.Connect(ctx, connStr, 5)
	require.NoError(t, err)

	cleanup := func() {
		pool.Close()
		_ = container.Terminate(ctx)
	}

	return pool, cleanup
}

func TestStore_CreateAndGetByID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	store := orchestrator.NewStore()
	ctx := context.Background()

	inst := &orchestrator.AgentInstance{
		Status:        orchestrator.StatusWarm,
		Config:        "{}",
		VMDriver:      "mock",
		ToolAllowlist: "[]",
	}

	err := store.Create(ctx, pool, inst)
	require.NoError(t, err)
	assert.NotEmpty(t, inst.ID)
	assert.Nil(t, inst.TenantID, "warm VM should have nil tenant_id")

	got, err := store.GetByID(ctx, pool, inst.ID)
	require.NoError(t, err)
	assert.Equal(t, inst.ID, got.ID)
	assert.Equal(t, orchestrator.StatusWarm, got.Status)
	assert.Equal(t, "mock", got.VMDriver)
}

func TestStore_ClaimWarm(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	store := orchestrator.NewStore()
	ctx := context.Background()

	// Create a tenant first (warm VM claim needs a valid tenant_id for FK)
	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Test Corp', 'test-corp') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	// Create a warm VM
	inst := &orchestrator.AgentInstance{
		Status:        orchestrator.StatusWarm,
		Config:        "{}",
		VMDriver:      "mock",
		ToolAllowlist: "[]",
		VsockCID:      ptrUint32(3),
	}
	err = store.Create(ctx, pool, inst)
	require.NoError(t, err)

	// Claim it
	claimed, err := store.ClaimWarm(ctx, pool, tenantID, nil, "{}")
	require.NoError(t, err)
	assert.Equal(t, inst.ID, claimed.ID)
	assert.Equal(t, &tenantID, claimed.TenantID)
	assert.Equal(t, orchestrator.StatusProvisioning, claimed.Status)

	// No more warm VMs
	_, err = store.ClaimWarm(ctx, pool, tenantID, nil, "{}")
	assert.ErrorIs(t, err, orchestrator.ErrNoWarmVMs)
}

func TestStore_RecordHealthCheck(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	store := orchestrator.NewStore()
	ctx := context.Background()

	inst := &orchestrator.AgentInstance{
		Status:        orchestrator.StatusRunning,
		Config:        "{}",
		VMDriver:      "mock",
		ToolAllowlist: "[]",
	}
	err := store.Create(ctx, pool, inst)
	require.NoError(t, err)

	// Record unhealthy
	err = store.RecordHealthCheck(ctx, pool, inst.ID, false)
	require.NoError(t, err)

	got, err := store.GetByID(ctx, pool, inst.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, got.ConsecutiveFailures)

	// Record healthy — resets counter
	err = store.RecordHealthCheck(ctx, pool, inst.ID, true)
	require.NoError(t, err)

	got, err = store.GetByID(ctx, pool, inst.ID)
	require.NoError(t, err)
	assert.Equal(t, 0, got.ConsecutiveFailures)
	assert.NotNil(t, got.LastHealthCheck)
}

func TestStore_NextVsockCID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	store := orchestrator.NewStore()
	ctx := context.Background()

	// Empty table — should return 3 (0-2 reserved)
	cid, err := store.NextVsockCID(ctx, pool)
	require.NoError(t, err)
	assert.Equal(t, uint32(3), cid)

	// Create an instance with CID 3
	inst := &orchestrator.AgentInstance{
		Status:        orchestrator.StatusWarm,
		Config:        "{}",
		VMDriver:      "mock",
		ToolAllowlist: "[]",
		VsockCID:      ptrUint32(3),
	}
	err = store.Create(ctx, pool, inst)
	require.NoError(t, err)

	// Next should be 4
	cid, err = store.NextVsockCID(ctx, pool)
	require.NoError(t, err)
	assert.Equal(t, uint32(4), cid)
}

func TestStore_CountByStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	store := orchestrator.NewStore()
	ctx := context.Background()

	count, err := store.CountByStatus(ctx, pool, orchestrator.StatusWarm)
	require.NoError(t, err)
	assert.Equal(t, 0, count)

	inst := &orchestrator.AgentInstance{
		Status:        orchestrator.StatusWarm,
		Config:        "{}",
		VMDriver:      "mock",
		ToolAllowlist: "[]",
	}
	err = store.Create(ctx, pool, inst)
	require.NoError(t, err)

	count, err = store.CountByStatus(ctx, pool, orchestrator.StatusWarm)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func ptrUint32(v uint32) *uint32 {
	return &v
}
