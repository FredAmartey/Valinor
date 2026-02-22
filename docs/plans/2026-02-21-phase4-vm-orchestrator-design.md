# Phase 4: VM Orchestrator — Design

**Date:** 2026-02-21
**Status:** Approved
**Phase:** 4 of 9 (MVP Build)

## Goal

Build the orchestrator module that manages Firecracker MicroVM lifecycles — provisioning, warm pooling, health checking, and destruction — with a driver abstraction that supports local development on macOS.

## Architecture Overview

```
Manager (orchestration logic)
  ├── VMDriver (interface — pluggable backend)
  │     ├── FirecrackerDriver  (production, Linux only, //go:build linux)
  │     ├── DockerDriver       (integration tests, testcontainers)
  │     └── MockDriver         (unit tests)
  ├── Store (agent_instances table, owner pool)
  └── Two background goroutines:
        ├── Warm Pool Reconciler (every 30s)
        └── Health Check Loop (every 10s)
```

**State machine:**
```
[warm] →claim→ [provisioning] →config inject→ [running] →health fail (3x)→ [unhealthy] →replace→ [destroying] → [destroyed]
```

Manager owns all state transitions. VMDriver only knows how to start/stop/check a VM — it has no awareness of tenant assignment or warm pool logic.

## VMDriver Interface

```go
type VMDriver interface {
    Start(ctx context.Context, spec VMSpec) (VMHandle, error)
    Stop(ctx context.Context, id string) error
    IsHealthy(ctx context.Context, id string) (bool, error)
    Cleanup(ctx context.Context, id string) error
}

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

type VMHandle struct {
    ID        string
    PID       int
    VsockCID  uint32
    StartedAt time.Time
}
```

### FirecrackerDriver (Linux only)

- Uses `firecracker-go-sdk` v1.0.0 (`github.com/firecracker-microvm/firecracker-go-sdk`)
- Build-tagged `//go:build linux` — won't compile on macOS
- `Start`: creates Firecracker machine with jailer config, boots VM, returns handle
- `IsHealthy`: checks `/proc/{pid}` exists and vsock responds to ping
- `Cleanup`: kills process, removes jailer chroot directory

### DockerDriver (integration tests)

- Uses `testcontainers-go` to run a lightweight container simulating a VM
- Container image: configurable (default `valinor-agent:latest`)
- `Start`: runs container with exposed port (simulates vsock)
- `IsHealthy`: container inspect → running state
- `Cleanup`: stops and removes container

### MockDriver (unit tests)

- In-memory map of VM states
- Configurable failure injection (e.g., `FailStartAfter(n)`, `FailHealthAfter(n)`)
- Deterministic — no goroutines, no I/O

## Warm Pool + Health Check Loops

### Warm Pool Reconciler (every 30s)

- Queries store: `CountByStatus(ctx, q, "warm")`
- If count < target (default: **2**), starts new VMs via `VMDriver.Start()` to fill the gap
- Each warm VM gets a pre-allocated vsock CID but no tenant assignment (`tenant_id IS NULL`)
- On `ClaimVM(tenantID)`: picks oldest warm VM via `ClaimWarm` (SELECT ... FOR UPDATE SKIP LOCKED), sets `tenant_id` + status `provisioning`, injects tenant config, transitions to `running`
- If no warm VMs available: falls back to cold-start (boot + configure synchronously)

### Health Check Loop (every 10s)

- Queries store: `ListByStatus(ctx, q, "running")`
- Calls `VMDriver.IsHealthy()` for each, batched with `errgroup` (concurrency limit: 10)
- Healthy: `RecordHealthCheck(ctx, q, id, true)` — updates `last_health_check`, resets `consecutive_failures` to 0
- Unhealthy: `RecordHealthCheck(ctx, q, id, false)` — increments `consecutive_failures`
- If `consecutive_failures >= 3`: transitions to `unhealthy`, spawns replacement from warm pool, then destroys old VM via `VMDriver.Cleanup()`

### Graceful Shutdown

Both loops respect `context.Context` cancellation. On shutdown, running VMs are left intact (not destroyed) — they'll be reconciled on next startup.

## Store + Database

Reuses existing `agent_instances` table. New columns via migration:

```sql
ALTER TABLE agent_instances
  ADD COLUMN vm_driver TEXT NOT NULL DEFAULT 'mock',
  ADD COLUMN vsock_cid INTEGER UNIQUE,
  ADD COLUMN consecutive_failures INTEGER NOT NULL DEFAULT 0;
```

Note: `last_health_check`, `vm_id`, `status`, `config`, `tenant_id`, `department_id` already exist.

### Store Interface

```go
type Store interface {
    Create(ctx context.Context, q database.Querier, inst *AgentInstance) error
    UpdateStatus(ctx context.Context, q database.Querier, id string, status string) error
    GetByID(ctx context.Context, q database.Querier, id string) (*AgentInstance, error)
    ListByStatus(ctx context.Context, q database.Querier, status string) ([]AgentInstance, error)
    ClaimWarm(ctx context.Context, q database.Querier, tenantID string) (*AgentInstance, error)
    RecordHealthCheck(ctx context.Context, q database.Querier, id string, healthy bool) error
    NextVsockCID(ctx context.Context, q database.Querier) (uint32, error)
    CountByStatus(ctx context.Context, q database.Querier, status string) (int, error)
}
```

### CID Allocation

`NextVsockCID`: `SELECT COALESCE(MAX(vsock_cid), 2) + 1 FROM agent_instances` — CIDs start at 3 (0-2 reserved by vsock spec). UNIQUE constraint prevents races; collisions retry.

### ClaimWarm

```sql
UPDATE agent_instances
SET tenant_id = $1, status = 'provisioning'
WHERE id = (
    SELECT id FROM agent_instances
    WHERE status = 'warm' AND tenant_id IS NULL
    ORDER BY created_at LIMIT 1
    FOR UPDATE SKIP LOCKED
)
RETURNING *
```

### RLS Note

Warm VMs have no `tenant_id`, so the orchestrator store operates on the **owner pool** (bypasses RLS). VM lifecycle is a platform-level operation.

## HTTP Handlers

Four endpoints:

| Method | Path | Permission | Description |
|--------|------|-----------|-------------|
| POST | `/api/v1/agents` | `agents:write` | Provision agent (claim warm or cold-start) |
| GET | `/api/v1/agents/:id` | `agents:read` | Get agent status/health |
| DELETE | `/api/v1/agents/:id` | `agents:write` | Destroy agent + VM |
| POST | `/api/v1/agents/:id/configure` | `agents:write` | Update config/tool allow-list |

### Handler

```go
type Handler struct {
    manager *Manager
    pool    *database.Pool
}
```

### Provision Flow (POST /agents)

1. Extract tenant ID from auth identity (JWT claims)
2. Validate request body (optional `department_id`, `config` JSONB)
3. `manager.Provision(ctx, tenantID, opts)` → claims warm VM or cold-starts
4. Returns 201 with agent instance JSON

### Get Status (GET /agents/:id)

1. Load agent instance from store
2. Tenant check: caller's tenant must match agent's tenant (or platform admin)
3. Returns 200

### Destroy (DELETE /agents/:id)

1. Same tenant check
2. `manager.Destroy(ctx, id)` → stops VM, cleans up, marks `destroyed`
3. Returns 204

### Configure (POST /agents/:id/configure)

1. Same tenant check
2. Updates `config` and `tool_allowlist` columns
3. If VM is running, pushes config via vsock (Phase 5 — for now just stores it)
4. Returns 200

## Configuration

```yaml
orchestrator:
  driver: "mock"              # "firecracker", "docker", "mock"
  warm_pool_size: 2
  health_interval: "10s"
  reconcile_interval: "30s"
  max_consecutive_failures: 3
  firecracker:
    kernel_path: "/var/lib/valinor/vmlinux"
    root_drive: "/var/lib/valinor/rootfs.ext4"
    jailer_path: "/usr/bin/jailer"
  docker:
    image: "valinor-agent:latest"
```

## Error Handling

```go
var (
    ErrNoWarmVMs     = errors.New("no warm VMs available")
    ErrVMNotFound    = errors.New("agent instance not found")
    ErrVMNotRunning  = errors.New("VM is not in running state")
    ErrDriverFailure = errors.New("VM driver operation failed")
)
```

`ErrNoWarmVMs` triggers cold-start fallback inside Manager — not surfaced to API. Others map to HTTP 404, 409, 502.

## Testing Strategy

- **Unit tests**: MockDriver, test Manager logic (claim, health transitions, reconcile) without real VMs
- **Integration tests**: DockerDriver with testcontainers, verify full lifecycle
- **CI**: Both run. Firecracker tests only in Linux environments (future)

## Tech Debt Notes

- **Max idle TTL for warm VMs**: Not implemented. Warm VMs sit indefinitely. Add recycling when we observe stale state issues.
- Warm pool target of 2 is conservative — increase when tenant count grows.

## Decisions Log

| Decision | Choice | Reasoning |
|----------|--------|-----------|
| Local testing | Mock + Docker driver | Firecracker is Linux-only, macOS dev needs alternatives |
| Warm pool strategy | Running VMs | Simpler than snapshot-based, sufficient for MVP scale |
| Jailer | Included from day one | Security-critical, harder to retrofit |
| Warm pool default | 2 | Conservative for early stage, configurable |
| Health failure tracking | DB column | Survives process restarts, unlike in-memory map |
| Store pool | Owner (no RLS) | Warm VMs have no tenant_id, lifecycle is platform-level |
