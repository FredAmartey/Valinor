# OpenClaw Integration — Follow-Up Items

Deferred items from internal and external code reviews on PR #70.

## From Reviews

### 1. Filter network list in `ensureTenantNetwork`
**File:** `internal/orchestrator/docker_driver.go:225`
**Severity:** Minor (performance)
`NetworkList` fetches all Docker networks. Should use a label filter to scope to valinor-managed networks only.

### 2. Tenant network cleanup on last container removal
**File:** `internal/orchestrator/docker_driver.go` (Cleanup method)
**Severity:** Medium (resource leak)
When the last container for a tenant is removed, the per-tenant bridge network is orphaned. Add cleanup logic to remove the network when no containers reference it.

### 3. OpenClaw guest config missing `memory.paths`
**File:** `configs/openclaw-guest.json`
**Severity:** Medium (functionality)
The hardened config restricts execution but doesn't configure memory mount paths for OpenClaw to discover. Add `memory.paths` section mapping `/memory/personal`, `/memory/department`, etc.

### 4. Sanitize `tenantID` in Docker network names
**File:** `internal/orchestrator/docker_driver.go:223`
**Severity:** Medium (security hardening)
`tenantID` is used directly in `fmt.Sprintf("valinor-net-%s", tenantID)`. Should validate/sanitize to prevent unexpected characters in Docker network names.

### 5. Sanitize `spec.VMID` in container names
**File:** `internal/orchestrator/docker_driver.go:67`
**Severity:** Medium (security hardening)
`spec.VMID` is used directly in `fmt.Sprintf("valinor-%s", spec.VMID)`. Should validate against a strict pattern (e.g., `^[a-zA-Z0-9-]+$`) to prevent container name injection.
