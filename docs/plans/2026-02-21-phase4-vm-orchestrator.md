# Phase 4: VM Orchestrator Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build the orchestrator module that manages VM lifecycles — provisioning, warm pooling, health checking, and destruction — with a pluggable VMDriver interface.

**Architecture:** Manager orchestrates VM lifecycle through a VMDriver abstraction (Mock/Docker/Firecracker). Two background loops maintain a warm pool and check health. Store operates on the owner pool (no RLS) since warm VMs have no tenant assignment.

**Tech Stack:** Go 1.25, pgx/v5, testcontainers-go, errgroup, testify

---

### Task 1: Migration — ALTER agent_instances for orchestrator

**Files:**
- Create: `migrations/000007_orchestrator_columns.up.sql`
- Create: `migrations/000007_orchestrator_columns.down.sql`

**Context:** The `agent_instances` table (migration 000001, line 86) has `tenant_id UUID NOT NULL` — warm VMs need `tenant_id IS NULL`. Column `vsock_cid INTEGER` already exists but needs a `UNIQUE` constraint. Column `last_health_check` already exists.

**Step 1: Write the up migration**

```sql
-- migrations/000007_orchestrator_columns.up.sql

-- Warm-pool VMs have no tenant assigned yet, so tenant_id must be nullable.
ALTER TABLE agent_instances ALTER COLUMN tenant_id DROP NOT NULL;

-- Track which driver started this VM.
ALTER TABLE agent_instances ADD COLUMN vm_driver TEXT NOT NULL DEFAULT 'mock';

-- Health-check failure counter (survives process restart).
ALTER TABLE agent_instances ADD COLUMN consecutive_failures INTEGER NOT NULL DEFAULT 0;

-- Each VM gets a unique vsock CID.
ALTER TABLE agent_instances ADD CONSTRAINT agent_instances_vsock_cid_unique UNIQUE (vsock_cid);

-- Index for warm-pool queries (status='warm', tenant_id IS NULL).
CREATE INDEX idx_agent_instances_status ON agent_instances(status);
```

**Step 2: Write the down migration**

```sql
-- migrations/000007_orchestrator_columns.down.sql

DROP INDEX IF EXISTS idx_agent_instances_status;
ALTER TABLE agent_instances DROP CONSTRAINT IF EXISTS agent_instances_vsock_cid_unique;
ALTER TABLE agent_instances DROP COLUMN IF EXISTS consecutive_failures;
ALTER TABLE agent_instances DROP COLUMN IF EXISTS vm_driver;

-- Restore NOT NULL (delete any warm VMs first to avoid constraint violation).
DELETE FROM agent_instances WHERE tenant_id IS NULL;
ALTER TABLE agent_instances ALTER COLUMN tenant_id SET NOT NULL;
```

**Step 3: Verify migration applies**

Run: `go test ./internal/platform/database/... -run TestConnect -count=1 -v`
Expected: PASS (migrations run as part of other test setups — this verifies no syntax error in migration files)

**Step 4: Commit**

```bash
git add migrations/000007_orchestrator_columns.up.sql migrations/000007_orchestrator_columns.down.sql
git commit -m "feat: add migration for orchestrator columns on agent_instances"
```

---

### Task 2: Orchestrator types, interfaces, and error sentinels

**Files:**
- Create: `internal/orchestrator/orchestrator.go`

**Context:** This is the foundation file for the orchestrator package. Follow the pattern in `internal/tenant/tenant.go` — types, interfaces, error sentinels, constants. The VMDriver interface is the core abstraction.

**Step 1: Write the types file**

```go
// internal/orchestrator/orchestrator.go
package orchestrator

import (
	"context"
	"errors"
	"time"
)

// VM status constants — state machine:
// [warm] → [provisioning] → [running] → [unhealthy] → [destroying] → [destroyed]
const (
	StatusWarm         = "warm"
	StatusProvisioning = "provisioning"
	StatusRunning      = "running"
	StatusUnhealthy    = "unhealthy"
	StatusDestroying   = "destroying"
	StatusDestroyed    = "destroyed"
)

// Error sentinels.
var (
	ErrNoWarmVMs     = errors.New("no warm VMs available")
	ErrVMNotFound    = errors.New("agent instance not found")
	ErrVMNotRunning  = errors.New("VM is not in running state")
	ErrDriverFailure = errors.New("VM driver operation failed")
)

// VMDriver is the pluggable backend for starting/stopping/checking VMs.
// Implementations: FirecrackerDriver (Linux), DockerDriver (integration tests), MockDriver (unit tests).
type VMDriver interface {
	Start(ctx context.Context, spec VMSpec) (VMHandle, error)
	Stop(ctx context.Context, id string) error
	IsHealthy(ctx context.Context, id string) (bool, error)
	Cleanup(ctx context.Context, id string) error
}

// VMSpec describes the configuration for a new VM.
type VMSpec struct {
	VMID       string
	RootDrive  string
	DataDrive  string
	KernelPath string
	KernelArgs string
	VCPUs      int
	MemoryMB   int
	VsockCID   uint32
	UseJailer  bool
	JailerPath string
}

// VMHandle is returned after a VM starts successfully.
type VMHandle struct {
	ID        string
	PID       int
	VsockCID  uint32
	StartedAt time.Time
}

// AgentInstance represents a row in the agent_instances table.
type AgentInstance struct {
	ID                  string     `json:"id"`
	TenantID            *string    `json:"tenant_id,omitempty"`
	DepartmentID        *string    `json:"department_id,omitempty"`
	VMID                *string    `json:"vm_id,omitempty"`
	Status              string     `json:"status"`
	Config              string     `json:"config"`
	VsockCID            *uint32    `json:"vsock_cid,omitempty"`
	VMDriver            string     `json:"vm_driver"`
	ToolAllowlist       string     `json:"tool_allowlist"`
	ConsecutiveFailures int        `json:"consecutive_failures"`
	CreatedAt           time.Time  `json:"created_at"`
	LastHealthCheck     *time.Time `json:"last_health_check,omitempty"`
}

// ProvisionOpts are options passed when provisioning a new agent.
type ProvisionOpts struct {
	DepartmentID *string
	Config       map[string]any
}
```

**Step 2: Verify it compiles**

Run: `go build ./internal/orchestrator/...`
Expected: Success (no output)

**Step 3: Commit**

```bash
git add internal/orchestrator/orchestrator.go
git commit -m "feat: add orchestrator types, VMDriver interface, and error sentinels"
```

---

### Task 3: MockDriver implementation

**Files:**
- Create: `internal/orchestrator/mock_driver.go`
- Create: `internal/orchestrator/mock_driver_test.go`

**Context:** MockDriver is used in all Manager unit tests. It keeps VMs in an in-memory map and supports failure injection for testing unhealthy VM scenarios.

**Step 1: Write the failing test**

```go
// internal/orchestrator/mock_driver_test.go
package orchestrator_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/orchestrator"
)

func TestMockDriver_StartAndHealth(t *testing.T) {
	driver := orchestrator.NewMockDriver()
	ctx := context.Background()

	handle, err := driver.Start(ctx, orchestrator.VMSpec{
		VMID:     "vm-1",
		VsockCID: 3,
	})
	require.NoError(t, err)
	assert.Equal(t, "vm-1", handle.ID)
	assert.Equal(t, uint32(3), handle.VsockCID)

	healthy, err := driver.IsHealthy(ctx, "vm-1")
	require.NoError(t, err)
	assert.True(t, healthy)
}

func TestMockDriver_StopAndCleanup(t *testing.T) {
	driver := orchestrator.NewMockDriver()
	ctx := context.Background()

	_, err := driver.Start(ctx, orchestrator.VMSpec{VMID: "vm-1"})
	require.NoError(t, err)

	err = driver.Stop(ctx, "vm-1")
	require.NoError(t, err)

	healthy, err := driver.IsHealthy(ctx, "vm-1")
	require.NoError(t, err)
	assert.False(t, healthy, "stopped VM should not be healthy")

	err = driver.Cleanup(ctx, "vm-1")
	require.NoError(t, err)

	_, err = driver.IsHealthy(ctx, "vm-1")
	assert.Error(t, err, "cleaned up VM should error")
}

func TestMockDriver_FailureInjection(t *testing.T) {
	driver := orchestrator.NewMockDriver()
	ctx := context.Background()

	_, err := driver.Start(ctx, orchestrator.VMSpec{VMID: "vm-1"})
	require.NoError(t, err)

	driver.SetUnhealthy("vm-1")

	healthy, err := driver.IsHealthy(ctx, "vm-1")
	require.NoError(t, err)
	assert.False(t, healthy)
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/orchestrator/... -run TestMockDriver -v -count=1`
Expected: FAIL — `NewMockDriver` not defined

**Step 3: Write the implementation**

```go
// internal/orchestrator/mock_driver.go
package orchestrator

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type mockVM struct {
	handle  VMHandle
	running bool
	healthy bool
}

// MockDriver is an in-memory VMDriver for unit testing.
type MockDriver struct {
	mu  sync.Mutex
	vms map[string]*mockVM
}

func NewMockDriver() *MockDriver {
	return &MockDriver{
		vms: make(map[string]*mockVM),
	}
}

func (d *MockDriver) Start(_ context.Context, spec VMSpec) (VMHandle, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	handle := VMHandle{
		ID:        spec.VMID,
		PID:       len(d.vms) + 1000, // fake PID
		VsockCID:  spec.VsockCID,
		StartedAt: time.Now(),
	}

	d.vms[spec.VMID] = &mockVM{
		handle:  handle,
		running: true,
		healthy: true,
	}

	return handle, nil
}

func (d *MockDriver) Stop(_ context.Context, id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	vm, ok := d.vms[id]
	if !ok {
		return fmt.Errorf("%w: %s", ErrVMNotFound, id)
	}
	vm.running = false
	vm.healthy = false
	return nil
}

func (d *MockDriver) IsHealthy(_ context.Context, id string) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	vm, ok := d.vms[id]
	if !ok {
		return false, fmt.Errorf("%w: %s", ErrVMNotFound, id)
	}
	return vm.running && vm.healthy, nil
}

func (d *MockDriver) Cleanup(_ context.Context, id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	delete(d.vms, id)
	return nil
}

// SetUnhealthy marks a VM as unhealthy (for testing health check logic).
func (d *MockDriver) SetUnhealthy(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if vm, ok := d.vms[id]; ok {
		vm.healthy = false
	}
}

// SetHealthy marks a VM as healthy again.
func (d *MockDriver) SetHealthy(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if vm, ok := d.vms[id]; ok {
		vm.healthy = true
	}
}

// RunningCount returns how many VMs are running.
func (d *MockDriver) RunningCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()

	count := 0
	for _, vm := range d.vms {
		if vm.running {
			count++
		}
	}
	return count
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/orchestrator/... -run TestMockDriver -v -count=1`
Expected: PASS (3 tests)

**Step 5: Commit**

```bash
git add internal/orchestrator/mock_driver.go internal/orchestrator/mock_driver_test.go
git commit -m "feat: add MockDriver for orchestrator unit testing"
```

---

### Task 4: Orchestrator Store implementation

**Files:**
- Create: `internal/orchestrator/store.go`

**Context:** The Store operates directly on the pool (no RLS) — same pattern as `internal/tenant/store.go`. Warm VMs have `tenant_id IS NULL`. The store uses `database.Querier` as parameter so both pool and individual connections work.

**Step 1: Write the store**

```go
// internal/orchestrator/store.go
package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

// Store handles agent_instances database operations for the orchestrator.
// Operates on the owner pool (no RLS) since warm VMs have no tenant_id.
type Store struct{}

func NewStore() *Store {
	return &Store{}
}

func (s *Store) Create(ctx context.Context, q database.Querier, inst *AgentInstance) error {
	configJSON, err := json.Marshal(inst.Config)
	if err != nil {
		configJSON = []byte("{}")
	}

	return q.QueryRow(ctx,
		`INSERT INTO agent_instances (tenant_id, department_id, vm_id, status, config, vsock_cid, vm_driver, tool_allowlist)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		 RETURNING id, created_at`,
		inst.TenantID, inst.DepartmentID, inst.VMID, inst.Status, configJSON,
		inst.VsockCID, inst.VMDriver, inst.ToolAllowlist,
	).Scan(&inst.ID, &inst.CreatedAt)
}

func (s *Store) GetByID(ctx context.Context, q database.Querier, id string) (*AgentInstance, error) {
	var inst AgentInstance
	err := q.QueryRow(ctx,
		`SELECT id, tenant_id, department_id, vm_id, status, config, vsock_cid,
		        vm_driver, tool_allowlist, consecutive_failures, created_at, last_health_check
		 FROM agent_instances WHERE id = $1`,
		id,
	).Scan(&inst.ID, &inst.TenantID, &inst.DepartmentID, &inst.VMID, &inst.Status,
		&inst.Config, &inst.VsockCID, &inst.VMDriver, &inst.ToolAllowlist,
		&inst.ConsecutiveFailures, &inst.CreatedAt, &inst.LastHealthCheck)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, ErrVMNotFound
		}
		return nil, fmt.Errorf("getting agent instance: %w", err)
	}
	return &inst, nil
}

func (s *Store) UpdateStatus(ctx context.Context, q database.Querier, id, status string) error {
	tag, err := q.Exec(ctx,
		`UPDATE agent_instances SET status = $1 WHERE id = $2`,
		status, id,
	)
	if err != nil {
		return fmt.Errorf("updating status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrVMNotFound
	}
	return nil
}

func (s *Store) ListByStatus(ctx context.Context, q database.Querier, status string) ([]AgentInstance, error) {
	rows, err := q.Query(ctx,
		`SELECT id, tenant_id, department_id, vm_id, status, config, vsock_cid,
		        vm_driver, tool_allowlist, consecutive_failures, created_at, last_health_check
		 FROM agent_instances WHERE status = $1 ORDER BY created_at`,
		status,
	)
	if err != nil {
		return nil, fmt.Errorf("listing by status: %w", err)
	}
	defer rows.Close()

	return scanAgentInstances(rows)
}

func (s *Store) ListByTenant(ctx context.Context, q database.Querier, tenantID string) ([]AgentInstance, error) {
	rows, err := q.Query(ctx,
		`SELECT id, tenant_id, department_id, vm_id, status, config, vsock_cid,
		        vm_driver, tool_allowlist, consecutive_failures, created_at, last_health_check
		 FROM agent_instances WHERE tenant_id = $1 AND status != $2 ORDER BY created_at`,
		tenantID, StatusDestroyed,
	)
	if err != nil {
		return nil, fmt.Errorf("listing by tenant: %w", err)
	}
	defer rows.Close()

	return scanAgentInstances(rows)
}

// ClaimWarm atomically assigns a warm VM to a tenant.
// Uses FOR UPDATE SKIP LOCKED to avoid contention.
func (s *Store) ClaimWarm(ctx context.Context, q database.Querier, tenantID string) (*AgentInstance, error) {
	var inst AgentInstance
	err := q.QueryRow(ctx,
		`UPDATE agent_instances
		 SET tenant_id = $1, status = $2
		 WHERE id = (
		     SELECT id FROM agent_instances
		     WHERE status = $3 AND tenant_id IS NULL
		     ORDER BY created_at LIMIT 1
		     FOR UPDATE SKIP LOCKED
		 )
		 RETURNING id, tenant_id, department_id, vm_id, status, config, vsock_cid,
		           vm_driver, tool_allowlist, consecutive_failures, created_at, last_health_check`,
		tenantID, StatusProvisioning, StatusWarm,
	).Scan(&inst.ID, &inst.TenantID, &inst.DepartmentID, &inst.VMID, &inst.Status,
		&inst.Config, &inst.VsockCID, &inst.VMDriver, &inst.ToolAllowlist,
		&inst.ConsecutiveFailures, &inst.CreatedAt, &inst.LastHealthCheck)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, ErrNoWarmVMs
		}
		return nil, fmt.Errorf("claiming warm VM: %w", err)
	}
	return &inst, nil
}

// RecordHealthCheck updates health state. If healthy, resets failures and updates timestamp.
// If unhealthy, increments consecutive_failures.
func (s *Store) RecordHealthCheck(ctx context.Context, q database.Querier, id string, healthy bool) error {
	var query string
	if healthy {
		query = `UPDATE agent_instances
		         SET last_health_check = now(), consecutive_failures = 0
		         WHERE id = $1`
	} else {
		query = `UPDATE agent_instances
		         SET consecutive_failures = consecutive_failures + 1
		         WHERE id = $1`
	}
	tag, err := q.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("recording health check: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrVMNotFound
	}
	return nil
}

// NextVsockCID returns the next available vsock CID.
// CIDs 0-2 are reserved by the vsock spec.
func (s *Store) NextVsockCID(ctx context.Context, q database.Querier) (uint32, error) {
	var cid uint32
	err := q.QueryRow(ctx,
		`SELECT COALESCE(MAX(vsock_cid), 2) + 1 FROM agent_instances`,
	).Scan(&cid)
	if err != nil {
		return 0, fmt.Errorf("getting next vsock CID: %w", err)
	}
	return cid, nil
}

// CountByStatus returns the count of agent instances with the given status.
func (s *Store) CountByStatus(ctx context.Context, q database.Querier, status string) (int, error) {
	var count int
	err := q.QueryRow(ctx,
		`SELECT COUNT(*) FROM agent_instances WHERE status = $1`,
		status,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("counting by status: %w", err)
	}
	return count, nil
}

// UpdateConfig updates the config and tool_allowlist columns.
func (s *Store) UpdateConfig(ctx context.Context, q database.Querier, id string, config string, toolAllowlist string) error {
	tag, err := q.Exec(ctx,
		`UPDATE agent_instances SET config = $1, tool_allowlist = $2 WHERE id = $3`,
		config, toolAllowlist, id,
	)
	if err != nil {
		return fmt.Errorf("updating config: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrVMNotFound
	}
	return nil
}

func scanAgentInstances(rows pgx.Rows) ([]AgentInstance, error) {
	var instances []AgentInstance
	for rows.Next() {
		var inst AgentInstance
		if err := rows.Scan(&inst.ID, &inst.TenantID, &inst.DepartmentID, &inst.VMID,
			&inst.Status, &inst.Config, &inst.VsockCID, &inst.VMDriver, &inst.ToolAllowlist,
			&inst.ConsecutiveFailures, &inst.CreatedAt, &inst.LastHealthCheck); err != nil {
			return nil, fmt.Errorf("scanning agent instance: %w", err)
		}
		instances = append(instances, inst)
	}
	return instances, rows.Err()
}
```

**Step 2: Verify it compiles**

Run: `go build ./internal/orchestrator/...`
Expected: Success

**Step 3: Commit**

```bash
git add internal/orchestrator/store.go
git commit -m "feat: add orchestrator store for agent_instances"
```

---

### Task 5: Store integration tests

**Files:**
- Create: `internal/orchestrator/store_test.go`

**Context:** Uses the testcontainers pattern from `internal/tenant/store_test.go`. Needs `setupTestDB` helper that starts Postgres, runs migrations, returns pool + cleanup. Store operates on owner pool (no RLS).

**Step 1: Write the tests**

```go
// internal/orchestrator/store_test.go
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
	claimed, err := store.ClaimWarm(ctx, pool, tenantID)
	require.NoError(t, err)
	assert.Equal(t, inst.ID, claimed.ID)
	assert.Equal(t, &tenantID, claimed.TenantID)
	assert.Equal(t, orchestrator.StatusProvisioning, claimed.Status)

	// No more warm VMs
	_, err = store.ClaimWarm(ctx, pool, tenantID)
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
```

**Step 2: Run tests to verify they pass**

Run: `go test ./internal/orchestrator/... -run TestStore -v -count=1`
Expected: PASS (5 tests). If any fail, fix Store queries to match actual column types.

**Step 3: Commit**

```bash
git add internal/orchestrator/store_test.go
git commit -m "test: add orchestrator store integration tests"
```

---

### Task 6: Manager core — Provision and Destroy

**Files:**
- Create: `internal/orchestrator/manager.go`

**Context:** Manager owns the VMDriver + Store + pool. `Provision` claims a warm VM or cold-starts. `Destroy` stops the VM and marks it destroyed. Background loops (Task 7-8) are separate methods.

**Step 1: Write the Manager**

```go
// internal/orchestrator/manager.go
package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/valinor-ai/valinor/internal/platform/database"
	"golang.org/x/sync/errgroup"
)

// ManagerConfig holds orchestrator configuration.
type ManagerConfig struct {
	Driver                 string
	WarmPoolSize           int
	HealthInterval         time.Duration
	ReconcileInterval      time.Duration
	MaxConsecutiveFailures int
}

// Manager orchestrates VM lifecycles.
type Manager struct {
	driver VMDriver
	store  *Store
	pool   *database.Pool
	cfg    ManagerConfig
	mu     sync.Mutex // protects CID allocation
}

func NewManager(pool *database.Pool, driver VMDriver, store *Store, cfg ManagerConfig) *Manager {
	if cfg.WarmPoolSize <= 0 {
		cfg.WarmPoolSize = 2
	}
	if cfg.HealthInterval <= 0 {
		cfg.HealthInterval = 10 * time.Second
	}
	if cfg.ReconcileInterval <= 0 {
		cfg.ReconcileInterval = 30 * time.Second
	}
	if cfg.MaxConsecutiveFailures <= 0 {
		cfg.MaxConsecutiveFailures = 3
	}
	return &Manager{
		driver: driver,
		store:  store,
		pool:   pool,
		cfg:    cfg,
	}
}

// Provision assigns a VM to a tenant. Tries warm pool first, falls back to cold-start.
func (m *Manager) Provision(ctx context.Context, tenantID string, opts ProvisionOpts) (*AgentInstance, error) {
	// Try claiming a warm VM
	inst, err := m.store.ClaimWarm(ctx, m.pool, tenantID)
	if err == nil {
		// Update department if provided
		if opts.DepartmentID != nil {
			inst.DepartmentID = opts.DepartmentID
		}
		if opts.Config != nil {
			configJSON, _ := json.Marshal(opts.Config)
			inst.Config = string(configJSON)
		}
		// Transition to running
		if err := m.store.UpdateStatus(ctx, m.pool, inst.ID, StatusRunning); err != nil {
			return nil, fmt.Errorf("transitioning to running: %w", err)
		}
		inst.Status = StatusRunning
		slog.Info("provisioned agent from warm pool", "id", inst.ID, "tenant", tenantID)
		return inst, nil
	}

	// Cold-start fallback
	slog.Info("no warm VMs available, cold-starting", "tenant", tenantID)
	return m.coldStart(ctx, tenantID, opts)
}

func (m *Manager) coldStart(ctx context.Context, tenantID string, opts ProvisionOpts) (*AgentInstance, error) {
	m.mu.Lock()
	cid, err := m.store.NextVsockCID(ctx, m.pool)
	m.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("allocating vsock CID: %w", err)
	}

	vmID := fmt.Sprintf("vm-%s-%d", tenantID[:8], time.Now().UnixMilli())

	spec := VMSpec{
		VMID:     vmID,
		VsockCID: cid,
	}

	handle, err := m.driver.Start(ctx, spec)
	if err != nil {
		return nil, fmt.Errorf("%w: starting VM: %w", ErrDriverFailure, err)
	}

	configStr := "{}"
	if opts.Config != nil {
		configJSON, _ := json.Marshal(opts.Config)
		configStr = string(configJSON)
	}

	inst := &AgentInstance{
		TenantID:      &tenantID,
		DepartmentID:  opts.DepartmentID,
		VMID:          &vmID,
		Status:        StatusRunning,
		Config:        configStr,
		VsockCID:      &handle.VsockCID,
		VMDriver:      m.cfg.Driver,
		ToolAllowlist: "[]",
	}

	if err := m.store.Create(ctx, m.pool, inst); err != nil {
		// Best-effort cleanup on DB failure
		_ = m.driver.Stop(ctx, vmID)
		_ = m.driver.Cleanup(ctx, vmID)
		return nil, fmt.Errorf("saving agent instance: %w", err)
	}

	slog.Info("cold-started agent", "id", inst.ID, "tenant", tenantID, "vm", vmID)
	return inst, nil
}

// Destroy stops and cleans up a VM, then marks it destroyed.
func (m *Manager) Destroy(ctx context.Context, id string) error {
	inst, err := m.store.GetByID(ctx, m.pool, id)
	if err != nil {
		return err
	}

	if err := m.store.UpdateStatus(ctx, m.pool, id, StatusDestroying); err != nil {
		return fmt.Errorf("marking destroying: %w", err)
	}

	if inst.VMID != nil {
		if stopErr := m.driver.Stop(ctx, *inst.VMID); stopErr != nil {
			slog.Warn("failed to stop VM", "id", id, "vm", *inst.VMID, "error", stopErr)
		}
		if cleanErr := m.driver.Cleanup(ctx, *inst.VMID); cleanErr != nil {
			slog.Warn("failed to cleanup VM", "id", id, "vm", *inst.VMID, "error", cleanErr)
		}
	}

	if err := m.store.UpdateStatus(ctx, m.pool, id, StatusDestroyed); err != nil {
		return fmt.Errorf("marking destroyed: %w", err)
	}

	slog.Info("destroyed agent", "id", id)
	return nil
}

// GetByID returns an agent instance by ID.
func (m *Manager) GetByID(ctx context.Context, id string) (*AgentInstance, error) {
	return m.store.GetByID(ctx, m.pool, id)
}

// ListByTenant returns all non-destroyed agents for a tenant.
func (m *Manager) ListByTenant(ctx context.Context, tenantID string) ([]AgentInstance, error) {
	return m.store.ListByTenant(ctx, m.pool, tenantID)
}

// UpdateConfig updates an agent's config and tool allow-list.
func (m *Manager) UpdateConfig(ctx context.Context, id, config, toolAllowlist string) error {
	return m.store.UpdateConfig(ctx, m.pool, id, config, toolAllowlist)
}

// Run starts the warm pool reconciler and health check loops.
// Blocks until context is cancelled.
func (m *Manager) Run(ctx context.Context) error {
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		m.reconcileLoop(ctx)
		return nil
	})

	g.Go(func() error {
		m.healthCheckLoop(ctx)
		return nil
	})

	return g.Wait()
}

// reconcileLoop maintains the warm pool at the target size.
func (m *Manager) reconcileLoop(ctx context.Context) {
	ticker := time.NewTicker(m.cfg.ReconcileInterval)
	defer ticker.Stop()

	// Run once immediately at startup
	m.reconcileOnce(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.reconcileOnce(ctx)
		}
	}
}

func (m *Manager) reconcileOnce(ctx context.Context) {
	count, err := m.store.CountByStatus(ctx, m.pool, StatusWarm)
	if err != nil {
		slog.Error("warm pool count failed", "error", err)
		return
	}

	deficit := m.cfg.WarmPoolSize - count
	if deficit <= 0 {
		return
	}

	slog.Info("replenishing warm pool", "current", count, "target", m.cfg.WarmPoolSize, "starting", deficit)

	for range deficit {
		if ctx.Err() != nil {
			return
		}

		m.mu.Lock()
		cid, err := m.store.NextVsockCID(ctx, m.pool)
		m.mu.Unlock()
		if err != nil {
			slog.Error("CID allocation failed", "error", err)
			continue
		}

		vmID := fmt.Sprintf("warm-%d-%d", cid, time.Now().UnixMilli())
		spec := VMSpec{
			VMID:     vmID,
			VsockCID: cid,
		}

		handle, err := m.driver.Start(ctx, spec)
		if err != nil {
			slog.Error("warm VM start failed", "error", err)
			continue
		}

		inst := &AgentInstance{
			VMID:          &vmID,
			Status:        StatusWarm,
			Config:        "{}",
			VsockCID:      &handle.VsockCID,
			VMDriver:      m.cfg.Driver,
			ToolAllowlist: "[]",
		}

		if err := m.store.Create(ctx, m.pool, inst); err != nil {
			slog.Error("saving warm VM failed", "error", err)
			_ = m.driver.Stop(ctx, vmID)
			_ = m.driver.Cleanup(ctx, vmID)
			continue
		}

		slog.Info("warm VM started", "id", inst.ID, "cid", cid)
	}
}

// healthCheckLoop checks all running VMs and replaces unhealthy ones.
func (m *Manager) healthCheckLoop(ctx context.Context) {
	ticker := time.NewTicker(m.cfg.HealthInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.healthCheckOnce(ctx)
		}
	}
}

func (m *Manager) healthCheckOnce(ctx context.Context) {
	instances, err := m.store.ListByStatus(ctx, m.pool, StatusRunning)
	if err != nil {
		slog.Error("listing running instances failed", "error", err)
		return
	}

	if len(instances) == 0 {
		return
	}

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(10) // concurrency cap

	for _, inst := range instances {
		inst := inst
		g.Go(func() error {
			if inst.VMID == nil {
				return nil
			}

			healthy, err := m.driver.IsHealthy(ctx, *inst.VMID)
			if err != nil {
				slog.Warn("health check error", "id", inst.ID, "error", err)
				healthy = false
			}

			if err := m.store.RecordHealthCheck(ctx, m.pool, inst.ID, healthy); err != nil {
				slog.Error("recording health check failed", "id", inst.ID, "error", err)
				return nil
			}

			if !healthy {
				// Re-read to get updated consecutive_failures count
				updated, err := m.store.GetByID(ctx, m.pool, inst.ID)
				if err != nil {
					return nil
				}
				if updated.ConsecutiveFailures >= m.cfg.MaxConsecutiveFailures {
					slog.Warn("VM exceeded failure threshold, replacing",
						"id", inst.ID, "failures", updated.ConsecutiveFailures)
					m.replaceUnhealthy(ctx, updated)
				}
			}

			return nil
		})
	}

	_ = g.Wait()
}

func (m *Manager) replaceUnhealthy(ctx context.Context, inst *AgentInstance) {
	// Mark unhealthy
	if err := m.store.UpdateStatus(ctx, m.pool, inst.ID, StatusUnhealthy); err != nil {
		slog.Error("marking unhealthy failed", "id", inst.ID, "error", err)
		return
	}

	// Destroy old VM
	if inst.VMID != nil {
		_ = m.driver.Stop(ctx, *inst.VMID)
		_ = m.driver.Cleanup(ctx, *inst.VMID)
	}
	_ = m.store.UpdateStatus(ctx, m.pool, inst.ID, StatusDestroyed)

	// Provision replacement if this VM had a tenant
	if inst.TenantID != nil {
		replacement, err := m.Provision(ctx, *inst.TenantID, ProvisionOpts{
			DepartmentID: inst.DepartmentID,
		})
		if err != nil {
			slog.Error("replacement provision failed", "original", inst.ID, "error", err)
			return
		}
		slog.Info("replaced unhealthy VM", "original", inst.ID, "replacement", replacement.ID)
	}
}
```

**Step 2: Verify it compiles**

Run: `go build ./internal/orchestrator/...`
Expected: Success

**Step 3: Commit**

```bash
git add internal/orchestrator/manager.go
git commit -m "feat: add orchestrator Manager with Provision, Destroy, warm pool, and health checks"
```

---

### Task 7: Manager unit tests with MockDriver

**Files:**
- Create: `internal/orchestrator/manager_test.go`

**Context:** Tests use MockDriver (no real VMs) with a real Postgres testcontainer (for Store). Tests cover: provision from warm pool, cold-start fallback, destroy, reconcile, health check transitions.

**Step 1: Write the tests**

```go
// internal/orchestrator/manager_test.go
package orchestrator_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/orchestrator"
)

func newTestManager(t *testing.T) (*orchestrator.Manager, *orchestrator.MockDriver, func()) {
	t.Helper()

	pool, cleanup := setupTestDB(t)
	driver := orchestrator.NewMockDriver()
	store := orchestrator.NewStore()
	cfg := orchestrator.ManagerConfig{
		Driver:                 "mock",
		WarmPoolSize:           2,
		HealthInterval:         100 * time.Millisecond,
		ReconcileInterval:      100 * time.Millisecond,
		MaxConsecutiveFailures: 3,
	}

	mgr := orchestrator.NewManager(pool, driver, store, cfg)
	return mgr, driver, cleanup
}

func createTestTenant(t *testing.T, pool interface{ Exec(context.Context, string, ...any) (interface{ RowsAffected() int64 }, error) }) string {
	t.Helper()
	// We need the actual pool for this — use the setupTestDB pool
	return ""
}

func TestManager_Provision_ColdStart(t *testing.T) {
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
```

**Step 2: Run tests**

Run: `go test ./internal/orchestrator/... -run TestManager -v -count=1`
Expected: PASS (4 tests). If compilation fails, fix imports or type mismatches.

**Step 3: Commit**

```bash
git add internal/orchestrator/manager_test.go
git commit -m "test: add Manager unit tests for provision and destroy"
```

---

### Task 8: Reconcile and health check loop tests

**Files:**
- Modify: `internal/orchestrator/manager_test.go` (append tests)

**Context:** These tests verify background loop behavior: warm pool replenishment and unhealthy VM replacement. Use short intervals (100ms) so tests complete quickly.

**Step 1: Add reconcile and health check tests**

Append to `internal/orchestrator/manager_test.go`:

```go
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
```

**Important:** This requires `ReconcileOnce` and `HealthCheckOnce` to be exported on Manager. Update `internal/orchestrator/manager.go`:

Change `reconcileOnce` to `ReconcileOnce` (exported) and `healthCheckOnce` to `HealthCheckOnce` (exported). Update the callers in `reconcileLoop` and `healthCheckLoop` accordingly.

In `manager.go`, rename:
- `func (m *Manager) reconcileOnce(ctx context.Context)` → `func (m *Manager) ReconcileOnce(ctx context.Context)`
- `func (m *Manager) healthCheckOnce(ctx context.Context)` → `func (m *Manager) HealthCheckOnce(ctx context.Context)`

And update their callers:
- In `reconcileLoop`: `m.ReconcileOnce(ctx)`
- In `healthCheckLoop`: `m.HealthCheckOnce(ctx)`

**Step 2: Run tests**

Run: `go test ./internal/orchestrator/... -run "TestManager_Reconcile|TestManager_HealthCheck" -v -count=1`
Expected: PASS (2 tests)

**Step 3: Commit**

```bash
git add internal/orchestrator/manager.go internal/orchestrator/manager_test.go
git commit -m "test: add warm pool reconcile and health check loop tests"
```

---

### Task 9: Configuration additions

**Files:**
- Modify: `internal/platform/config/config.go`

**Context:** Add `OrchestratorConfig` to the Config struct, following the existing pattern. Add defaults in the `Load` function's confmap.

**Step 1: Add the config types and defaults**

In `internal/platform/config/config.go`, add to the `Config` struct:

```go
type Config struct {
	Server       ServerConfig       `koanf:"server"`
	Database     DatabaseConfig     `koanf:"database"`
	Log          LogConfig          `koanf:"log"`
	Auth         AuthConfig         `koanf:"auth"`
	Orchestrator OrchestratorConfig `koanf:"orchestrator"`
}
```

Add the new config types (after `LogConfig`):

```go
type OrchestratorConfig struct {
	Driver                 string            `koanf:"driver"`
	WarmPoolSize           int               `koanf:"warm_pool_size"`
	HealthIntervalSecs     int               `koanf:"health_interval_secs"`
	ReconcileIntervalSecs  int               `koanf:"reconcile_interval_secs"`
	MaxConsecutiveFailures int               `koanf:"max_consecutive_failures"`
	Firecracker            FirecrackerConfig `koanf:"firecracker"`
	Docker                 DockerConfig      `koanf:"docker"`
}

type FirecrackerConfig struct {
	KernelPath string `koanf:"kernel_path"`
	RootDrive  string `koanf:"root_drive"`
	JailerPath string `koanf:"jailer_path"`
}

type DockerConfig struct {
	Image string `koanf:"image"`
}
```

Add defaults in the `Load` function's confmap:

```go
"orchestrator.driver":                   "mock",
"orchestrator.warm_pool_size":           2,
"orchestrator.health_interval_secs":     10,
"orchestrator.reconcile_interval_secs":  30,
"orchestrator.max_consecutive_failures": 3,
"orchestrator.docker.image":             "valinor-agent:latest",
```

**Step 2: Verify it compiles**

Run: `go build ./internal/platform/config/...`
Expected: Success

**Step 3: Commit**

```bash
git add internal/platform/config/config.go
git commit -m "feat: add orchestrator configuration to config"
```

---

### Task 10: HTTP Handler

**Files:**
- Create: `internal/orchestrator/handler.go`

**Context:** Follow the pattern in `internal/tenant/handler.go`. Handler holds Manager + pool. Routes: POST /agents, GET /agents/:id, DELETE /agents/:id, POST /agents/:id/configure. Gets tenant ID from `middleware.GetTenantID` (via auth identity context).

**Step 1: Write the handler**

```go
// internal/orchestrator/handler.go
package orchestrator

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
)

// Handler handles HTTP requests for agent lifecycle.
type Handler struct {
	manager *Manager
}

// NewHandler creates a new orchestrator Handler.
func NewHandler(manager *Manager) *Handler {
	return &Handler{manager: manager}
}

// HandleProvision creates a new agent for the caller's tenant.
// POST /api/v1/agents
func (h *Handler) HandleProvision(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 10<<10)

	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant context required"})
		return
	}

	var req struct {
		DepartmentID *string        `json:"department_id,omitempty"`
		Config       map[string]any `json:"config,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err.Error() != "EOF" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	inst, err := h.manager.Provision(r.Context(), tenantID, ProvisionOpts{
		DepartmentID: req.DepartmentID,
		Config:       req.Config,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "provisioning failed"})
		return
	}

	writeJSON(w, http.StatusCreated, inst)
}

// HandleGetAgent returns agent details.
// GET /api/v1/agents/{id}
func (h *Handler) HandleGetAgent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id is required"})
		return
	}

	inst, err := h.manager.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrVMNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "lookup failed"})
		return
	}

	// Verify tenant ownership (or platform admin)
	identity := auth.GetIdentity(r.Context())
	if identity != nil && !identity.IsPlatformAdmin {
		tenantID := middleware.GetTenantID(r.Context())
		if inst.TenantID == nil || *inst.TenantID != tenantID {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
			return
		}
	}

	writeJSON(w, http.StatusOK, inst)
}

// HandleListAgents returns all agents for the caller's tenant.
// GET /api/v1/agents
func (h *Handler) HandleListAgents(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant context required"})
		return
	}

	agents, err := h.manager.ListByTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list agents"})
		return
	}

	if agents == nil {
		agents = []AgentInstance{}
	}

	writeJSON(w, http.StatusOK, map[string]any{"agents": agents})
}

// HandleDestroyAgent destroys an agent and its VM.
// DELETE /api/v1/agents/{id}
func (h *Handler) HandleDestroyAgent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id is required"})
		return
	}

	// Verify tenant ownership
	inst, err := h.manager.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrVMNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "lookup failed"})
		return
	}

	identity := auth.GetIdentity(r.Context())
	if identity != nil && !identity.IsPlatformAdmin {
		tenantID := middleware.GetTenantID(r.Context())
		if inst.TenantID == nil || *inst.TenantID != tenantID {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
			return
		}
	}

	if err := h.manager.Destroy(r.Context(), id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "destroy failed"})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// HandleConfigure updates an agent's config and tool allow-list.
// POST /api/v1/agents/{id}/configure
func (h *Handler) HandleConfigure(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 10<<10)

	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id is required"})
		return
	}

	// Verify tenant ownership
	inst, err := h.manager.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrVMNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "lookup failed"})
		return
	}

	identity := auth.GetIdentity(r.Context())
	if identity != nil && !identity.IsPlatformAdmin {
		tenantID := middleware.GetTenantID(r.Context())
		if inst.TenantID == nil || *inst.TenantID != tenantID {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
			return
		}
	}

	var req struct {
		Config        map[string]any `json:"config"`
		ToolAllowlist []string       `json:"tool_allowlist"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	configJSON, _ := json.Marshal(req.Config)
	allowlistJSON, _ := json.Marshal(req.ToolAllowlist)

	if err := h.manager.UpdateConfig(r.Context(), id, string(configJSON), string(allowlistJSON)); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "update failed"})
		return
	}

	// Return updated instance
	updated, err := h.manager.GetByID(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "lookup failed"})
		return
	}

	writeJSON(w, http.StatusOK, updated)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
```

**Step 2: Verify it compiles**

Run: `go build ./internal/orchestrator/...`
Expected: Success

**Step 3: Commit**

```bash
git add internal/orchestrator/handler.go
git commit -m "feat: add orchestrator HTTP handler for agent lifecycle"
```

---

### Task 11: Handler tests

**Files:**
- Create: `internal/orchestrator/handler_test.go`

**Context:** Follow `internal/tenant/handler_test.go` pattern. Use httptest + real DB (testcontainers). Set up auth identity in context for tenant scoping.

**Step 1: Write the handler tests**

```go
// internal/orchestrator/handler_test.go
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
```

**Important:** This test uses `auth.WithIdentity` and `middleware.WithTenantID` — helper functions that may or may not exist. Check if they exist. If not, use the raw `context.WithValue` approach from the existing test files.

If `auth.WithIdentity` doesn't exist, add it to `internal/auth/middleware.go`:

```go
// WithIdentity adds an Identity to the context (for testing).
func WithIdentity(ctx context.Context, identity *Identity) context.Context {
	return context.WithValue(ctx, identityContextKey{}, identity)
}
```

If `middleware.WithTenantID` doesn't exist, add it to `internal/platform/middleware/tenant.go`:

```go
// WithTenantID adds a tenant ID to the context (for testing).
func WithTenantID(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantContextKey{}, tenantID)
}
```

**Step 2: Run handler tests**

Run: `go test ./internal/orchestrator/... -run TestHandler -v -count=1`
Expected: PASS (4 tests)

**Step 3: Commit**

```bash
git add internal/orchestrator/handler_test.go internal/auth/middleware.go internal/platform/middleware/tenant.go
git commit -m "test: add orchestrator handler tests with tenant isolation"
```

---

### Task 12: Server wiring — Dependencies + routes

**Files:**
- Modify: `internal/platform/server/server.go`

**Context:** Add `AgentHandler *orchestrator.Handler` to Dependencies. Replace the inline `handleListAgents` stub (lines 81-86 and 256-300) with routes that delegate to the orchestrator handler. Add import for `orchestrator` package.

**Step 1: Update Dependencies struct**

In `internal/platform/server/server.go`, add to imports:

```go
"github.com/valinor-ai/valinor/internal/orchestrator"
```

Add to Dependencies struct:

```go
AgentHandler *orchestrator.Handler
```

**Step 2: Replace the agents route block**

Replace the existing agents route (lines 81-86):

```go
protectedMux.Handle("GET /api/v1/agents",
    rbac.RequirePermission(deps.RBAC, "agents:read")(
        http.HandlerFunc(s.handleListAgents),
    ),
)
```

With the full agent routes block:

```go
if deps.AgentHandler != nil {
    protectedMux.Handle("POST /api/v1/agents",
        rbac.RequirePermission(deps.RBAC, "agents:write")(
            http.HandlerFunc(deps.AgentHandler.HandleProvision),
        ),
    )
    protectedMux.Handle("GET /api/v1/agents",
        rbac.RequirePermission(deps.RBAC, "agents:read")(
            http.HandlerFunc(deps.AgentHandler.HandleListAgents),
        ),
    )
    protectedMux.Handle("GET /api/v1/agents/{id}",
        rbac.RequirePermission(deps.RBAC, "agents:read")(
            http.HandlerFunc(deps.AgentHandler.HandleGetAgent),
        ),
    )
    protectedMux.Handle("DELETE /api/v1/agents/{id}",
        rbac.RequirePermission(deps.RBAC, "agents:write")(
            http.HandlerFunc(deps.AgentHandler.HandleDestroyAgent),
        ),
    )
    protectedMux.Handle("POST /api/v1/agents/{id}/configure",
        rbac.RequirePermission(deps.RBAC, "agents:write")(
            http.HandlerFunc(deps.AgentHandler.HandleConfigure),
        ),
    )
}
```

**Step 3: Delete the inline handleListAgents method**

Remove the entire `handleListAgents` method (lines 256-300 of the current file). It's replaced by `AgentHandler.HandleListAgents`.

**Step 4: Verify it compiles**

Run: `go build ./cmd/valinor/...`
Expected: May fail if main.go doesn't wire AgentHandler yet — that's Task 13. For now:

Run: `go build ./internal/platform/server/...`
Expected: Success

**Step 5: Commit**

```bash
git add internal/platform/server/server.go
git commit -m "feat: wire orchestrator handler routes into server"
```

---

### Task 13: Main.go wiring

**Files:**
- Modify: `cmd/valinor/main.go`

**Context:** Wire the orchestrator Manager + Handler in the composition root. Start background loops with `go manager.Run(ctx)`. Import the orchestrator package. Build the ManagerConfig from the config.

**Step 1: Add orchestrator wiring**

In `cmd/valinor/main.go`, add to imports:

```go
"time"
"github.com/valinor-ai/valinor/internal/orchestrator"
```

After the RBAC section (after line 132), before the dev mode identity section, add:

```go
// Orchestrator
var agentHandler *orchestrator.Handler
if pool != nil {
    orchStore := orchestrator.NewStore()
    orchDriver := orchestrator.NewMockDriver() // TODO: select driver from config
    orchCfg := orchestrator.ManagerConfig{
        Driver:                 cfg.Orchestrator.Driver,
        WarmPoolSize:           cfg.Orchestrator.WarmPoolSize,
        HealthInterval:         time.Duration(cfg.Orchestrator.HealthIntervalSecs) * time.Second,
        ReconcileInterval:      time.Duration(cfg.Orchestrator.ReconcileIntervalSecs) * time.Second,
        MaxConsecutiveFailures: cfg.Orchestrator.MaxConsecutiveFailures,
    }
    orchManager := orchestrator.NewManager(pool, orchDriver, orchStore, orchCfg)
    agentHandler = orchestrator.NewHandler(orchManager)

    // Start background loops (warm pool + health checks)
    go func() {
        if err := orchManager.Run(ctx); err != nil {
            slog.Error("orchestrator background loops stopped", "error", err)
        }
    }()
    slog.Info("orchestrator started", "driver", cfg.Orchestrator.Driver, "warm_pool", cfg.Orchestrator.WarmPoolSize)
}
```

Add `AgentHandler` to the Dependencies struct:

```go
srv := server.New(addr, server.Dependencies{
    Pool:              pool,
    Auth:              tokenSvc,
    AuthHandler:       authHandler,
    RBAC:              rbacEngine,
    TenantHandler:     tenantHandler,
    DepartmentHandler: deptHandler,
    UserHandler:       userHandler,
    RoleHandler:       roleHandler,
    AgentHandler:      agentHandler,
    DevMode:           cfg.Auth.DevMode,
    DevIdentity:       devIdentity,
    Logger:            logger,
})
```

**Step 2: Verify the full binary compiles**

Run: `go build ./cmd/valinor/...`
Expected: Success

**Step 3: Run all existing tests to check nothing is broken**

Run: `go test ./... -short -count=1`
Expected: PASS (all unit tests pass; integration tests skipped with -short)

**Step 4: Commit**

```bash
git add cmd/valinor/main.go
git commit -m "feat: wire orchestrator into main.go composition root"
```

---

### Task 14: End-to-end integration test

**Files:**
- Create: `internal/orchestrator/integration_test.go`

**Context:** Full lifecycle test: create tenant → provision agent → verify running → destroy → verify destroyed. Uses testcontainers + MockDriver. This is the smoke test for the entire orchestrator flow.

**Step 1: Write the integration test**

```go
// internal/orchestrator/integration_test.go
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
```

**Step 2: Run the integration test**

Run: `go test ./internal/orchestrator/... -run TestIntegration -v -count=1`
Expected: PASS

**Step 3: Run ALL orchestrator tests**

Run: `go test ./internal/orchestrator/... -v -count=1`
Expected: PASS (all tests)

**Step 4: Run the full test suite**

Run: `go test ./... -count=1`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/orchestrator/integration_test.go
git commit -m "test: add orchestrator end-to-end integration test"
```

---

### Task 15: FirecrackerDriver stub (Linux build tag)

**Files:**
- Create: `internal/orchestrator/firecracker_driver.go`

**Context:** A build-tagged stub that compiles only on Linux. For now, returns `ErrDriverFailure` — actual Firecracker SDK integration happens when we have a Linux CI environment. The important thing is the build tag prevents compilation failures on macOS.

**Step 1: Write the stub**

```go
//go:build linux

// internal/orchestrator/firecracker_driver.go
package orchestrator

import (
	"context"
	"fmt"
)

// FirecrackerDriver manages Firecracker MicroVMs.
// Requires Linux with KVM support.
type FirecrackerDriver struct {
	kernelPath string
	rootDrive  string
	jailerPath string
}

// NewFirecrackerDriver creates a new FirecrackerDriver.
func NewFirecrackerDriver(kernelPath, rootDrive, jailerPath string) *FirecrackerDriver {
	return &FirecrackerDriver{
		kernelPath: kernelPath,
		rootDrive:  rootDrive,
		jailerPath: jailerPath,
	}
}

func (d *FirecrackerDriver) Start(_ context.Context, spec VMSpec) (VMHandle, error) {
	// TODO: implement with firecracker-go-sdk when Linux CI is available
	return VMHandle{}, fmt.Errorf("%w: firecracker driver not yet implemented", ErrDriverFailure)
}

func (d *FirecrackerDriver) Stop(_ context.Context, id string) error {
	return fmt.Errorf("%w: firecracker driver not yet implemented", ErrDriverFailure)
}

func (d *FirecrackerDriver) IsHealthy(_ context.Context, id string) (bool, error) {
	return false, fmt.Errorf("%w: firecracker driver not yet implemented", ErrDriverFailure)
}

func (d *FirecrackerDriver) Cleanup(_ context.Context, id string) error {
	return fmt.Errorf("%w: firecracker driver not yet implemented", ErrDriverFailure)
}
```

**Step 2: Verify it doesn't break macOS build**

Run: `go build ./internal/orchestrator/...`
Expected: Success (file is excluded on macOS by build tag)

**Step 3: Commit**

```bash
git add internal/orchestrator/firecracker_driver.go
git commit -m "feat: add FirecrackerDriver stub with Linux build tag"
```

---

## Summary

| Task | Description | Files |
|------|-------------|-------|
| 1 | Migration: ALTER agent_instances | `migrations/000007_*` |
| 2 | Types, interfaces, error sentinels | `internal/orchestrator/orchestrator.go` |
| 3 | MockDriver + tests | `internal/orchestrator/mock_driver.go`, `mock_driver_test.go` |
| 4 | Store implementation | `internal/orchestrator/store.go` |
| 5 | Store integration tests | `internal/orchestrator/store_test.go` |
| 6 | Manager core (Provision, Destroy, Run) | `internal/orchestrator/manager.go` |
| 7 | Manager unit tests | `internal/orchestrator/manager_test.go` |
| 8 | Reconcile + health check loop tests | `internal/orchestrator/manager_test.go` (append) |
| 9 | Configuration additions | `internal/platform/config/config.go` |
| 10 | HTTP Handler | `internal/orchestrator/handler.go` |
| 11 | Handler tests | `internal/orchestrator/handler_test.go` |
| 12 | Server wiring (Dependencies, routes) | `internal/platform/server/server.go` |
| 13 | Main.go wiring | `cmd/valinor/main.go` |
| 14 | End-to-end integration test | `internal/orchestrator/integration_test.go` |
| 15 | FirecrackerDriver stub (Linux) | `internal/orchestrator/firecracker_driver.go` |
