# Hierarchical Memory Volume Mounts Design

**Date:** 2026-03-03
**Status:** Approved

## Goal

Wire all four memory layers (personal, department, tenant, shared) as Docker bind mounts so OpenClaw agents can read/write hierarchical knowledge via the filesystem.

## Context

The DockerDriver currently mounts only the personal layer. The OpenClaw guest config (`configs/openclaw-guest.json`) already declares `memory.qmd.paths` for all four layers. The `knowledge_bases` and `knowledge_base_grants` tables exist but have no query layer.

## Architecture

### VMSpec Expansion

Add `UserID`, `DepartmentID`, and `KnowledgeBaseIDs` to VMSpec:

```go
type VMSpec struct {
    // ... existing fields ...
    UserID           string
    DepartmentID     string
    KnowledgeBaseIDs []string // granted KB IDs for /memory/shared mounts
}
```

Manager populates these from `ProvisionOpts` and the new `KnowledgeBaseStore`.

### KnowledgeBaseStore

New file `internal/orchestrator/kb_store.go`. Thin query layer over `knowledge_bases` + `knowledge_base_grants`.

```go
type KnowledgeBaseGrant struct {
    KBID string
    Name string
}

type KnowledgeBaseStore struct {
    pool *pgxpool.Pool
}

func (s *KnowledgeBaseStore) GrantsForUser(
    ctx context.Context, tenantID, userID, departmentID string,
) ([]KnowledgeBaseGrant, error)
```

Single query: join `knowledge_bases` and `knowledge_base_grants` where `kb.tenant_id = tenantID` and grant matches user directly (`grant_type='user', target=userID`), department (`grant_type='department', target=departmentID`), or user's roles (join `user_roles` for `grant_type='role'`).

### Filesystem Layout

```
{MemoryBasePath}/
  {vmID}/personal/           → /memory/personal     (rw)
  departments/{deptID}/      → /memory/department    (ro)
  tenants/{tenantID}/        → /memory/tenant        (ro)
  kbs/{kbID}/                → /memory/shared/{name} (ro, one per grant)
```

- Personal: per-VM, read-write (existing behavior)
- Department: shared across all agents in that department, read-only
- Tenant: shared across all agents in that tenant, read-only
- Shared: one sub-mount per granted knowledge base, read-only

All paths get the same traversal guard as personal (filepath.Clean + HasPrefix check).

### Mount Logic in DockerDriver.Start()

Expand the existing mount block. Department and tenant mounts are conditional on non-empty IDs. Shared mounts iterate `KnowledgeBaseIDs`. All non-personal mounts use `ReadOnly: true`.

### Manager Wiring

In `coldStart()`:
1. Query `KnowledgeBaseStore.GrantsForUser(tenantID, userID, deptID)`
2. Set `spec.UserID`, `spec.DepartmentID`, `spec.KnowledgeBaseIDs`

In warm pool claim: same — after claiming, resolve grants and pass to driver. Since warm VMs are already started without mounts, this means warm pool VMs need mounts added post-start (or we accept that warm pool VMs don't get shared mounts until restart). For now: warm pool VMs skip shared mounts (they have no tenant context at start time). Cold-start path gets all four layers.

## Testing

- `TestKBStore_GrantsForUser` — integration test against DB, verifies user/dept/role grant resolution
- `TestDockerDriver_MemoryMounts` — unit test with mock, verifies all 4 mount types in container config
- Existing E2E test unaffected (uses `--skip-openclaw-spawn`, no MemoryBasePath)

## Decisions

| Decision | Choice | Reasoning |
|----------|--------|-----------|
| Pass identity via VMSpec vs driver queries DB | VMSpec fields | Explicit, no new driver-DB coupling, consistent with TenantID pattern |
| KB grant resolution location | Manager (via KBStore) | DB access belongs in stores per project rules |
| Warm pool shared mounts | Skip (cold-start only) | Warm VMs have no tenant context at creation; adding mounts post-start adds complexity for marginal benefit |
| Shared mount naming | `/memory/shared/{kbName}` | Human-readable, OpenClaw indexes by directory name |
