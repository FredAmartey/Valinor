# OpenClaw Integration — Follow-Up Items

Deferred items from internal and external code reviews on PR #70.

## Resolved

### 1. Filter network list in `ensureTenantNetwork`
**File:** `internal/orchestrator/docker_driver.go:226`
**Resolution:** Added `filters.Arg("label", dockerContainerLabel)` to both NetworkList calls.

### 2. Tenant network cleanup on last container removal
**File:** `internal/orchestrator/docker_driver.go` (Cleanup + cleanupTenantNetwork)
**Resolution:** Cleanup now inspects the container for its tenant label, then removes the tenant network if no other valinor containers belong to that tenant.

### 3. OpenClaw guest config missing `memory.qmd.paths`
**File:** `configs/openclaw-guest.json`
**Resolution:** Added `memory.qmd.paths` with entries for personal, department, tenant, and shared layers (correct key per OpenClaw docs — `memory.qmd.paths`, not `memory.paths`).

## Dropped (not real problems)

### 4. Sanitize `tenantID` in Docker network names
**Reason:** TenantID comes from the JWT, sourced from `users.tenant_id` in the database. Never user-supplied input.

### 5. Sanitize `spec.VMID` in container names
**Reason:** VMID is system-generated (`vm-{prefix}-{timestamp}` or `warm-{cid}-{timestamp}`). Never user-supplied input.
