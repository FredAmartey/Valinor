# Phase 3 P1: RLS Integration Tests + Tenant Provisioning API

## Context

Phase 3 P0 is complete (HMAC state tokens, refresh token rotation). The next blocker before multi-replica production deployment is:

1. **RLS policies exist but are never activated** — `database.WithTenantConnection()` exists but no handler calls it. Tenant isolation is purely application-level (RBAC + FK constraints). No tests verify the DB-level isolation.
2. **No tenant provisioning API** — tenants can only be created via raw SQL. There's no programmatic way to onboard a customer.
3. **No platform-level auth** — all identities are tenant-scoped. There's no way for an operator to manage tenants across the platform.

## Design

### 1. Platform Admin Auth

**Schema:** Add `is_platform_admin BOOLEAN NOT NULL DEFAULT false` to the `users` table (migration 000005).

**Identity:** Add `IsPlatformAdmin bool` to `Identity` struct. Carried in JWT claims as `"pa"` (omitempty — false omitted, existing tokens unaffected).

**Auth flow:** Platform admin logs in on the base domain (no subdomain). `HandleCallback` is modified: if TenantResolver returns `ErrTenantNotFound` and the user is a platform admin (looked up by OIDC subject), skip tenant resolution. `TenantID` is empty in the token.

**Middleware:** New `RequirePlatformAdmin()` middleware checks `identity.IsPlatformAdmin`. Returns 403 if false.

**Bootstrap:** Seed SQL script (`scripts/seed_platform_admin.sql`) inserts the first platform admin. Operators run this manually after initial deployment.

> **Revisit note:** `is_platform_admin` is intentionally minimal. Once we discover what platform-level operations exist beyond tenant CRUD, we may need to graduate this to a `platform_role TEXT` column or a dedicated `platform_roles` table. Track this in future planning.

### 2. Tenant Provisioning API

**Package:** `internal/tenant` — separate from auth per module boundary rules.

**Store methods:**
- `Create(ctx, querier, name, slug) (*Tenant, error)` — INSERT with slug uniqueness enforced by DB constraint
- `GetByID(ctx, querier, id) (*Tenant, error)` — SELECT by UUID
- `List(ctx, querier) ([]Tenant, error)` — SELECT all (platform admin only)

**Slug validation (application-level):**
- Lowercase alphanumeric + hyphens only
- 3-63 characters (DNS label rules)
- Cannot start/end with hyphen
- Reserved words: `api`, `app`, `www`, `admin`, `platform`, `auth`, `static`, `assets`

**Endpoints:**

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST /api/v1/tenants` | `RequirePlatformAdmin` | Create tenant |
| `GET /api/v1/tenants/{id}` | `RequirePlatformAdmin` | Get tenant by ID |
| `GET /api/v1/tenants` | `RequirePlatformAdmin` | List all tenants |

All platform-admin-only. These endpoints do NOT use `WithTenantConnection` because they operate across tenants. The `tenants` table has no RLS policy (it's the root entity).

**Request/response:**
```
POST /api/v1/tenants
{"name": "Chelsea FC", "slug": "chelsea-fc"}
-> 201 {"id": "...", "name": "Chelsea FC", "slug": "chelsea-fc", "status": "active", "created_at": "..."}

GET /api/v1/tenants/{id}
-> 200 {"id": "...", "name": "Chelsea FC", "slug": "chelsea-fc", "status": "active", ...}

GET /api/v1/tenants
-> 200 [{"id": "...", "name": "Chelsea FC", ...}, ...]
```

### 3. RLS Integration Tests

**File:** `internal/platform/database/rls_test.go`

**Setup:** Two tenants (A and B) with data seeded into every RLS-protected table via superuser connection.

**Test cases:**

| Test | Proves |
|------|--------|
| `TestRLS_TenantIsolation_Users` | Tenant A query sees only Tenant A users |
| `TestRLS_TenantIsolation_Departments` | Same for departments |
| `TestRLS_TenantIsolation_Roles` | Same for roles |
| `TestRLS_TenantIsolation_AgentInstances` | Same for agent_instances |
| `TestRLS_TenantIsolation_Connectors` | Same for connectors |
| `TestRLS_TenantIsolation_RefreshTokenFamilies` | Same for refresh_token_families |
| `TestRLS_CrossTenantWrite_Blocked` | INSERT as Tenant A with Tenant B's tenant_id fails |
| `TestRLS_NoTenantSet_ReturnsEmpty` | Query without `app.current_tenant_id` returns 0 rows |

Each test uses `database.WithTenantConnection()` to activate RLS and verify isolation.

**RLS gap fix:** `audit_events` currently has no RLS policy. Add `tenant_id UUID` column (nullable, for platform-level events) and a tenant_isolation policy via migration. Alternatively, if audit events should be platform-visible, document as intentionally unscoped.

### 4. WithTenantConnection Handler Pattern

**Reference implementation:** Wire `WithTenantConnection` into the existing `handleListAgents` stub in `server.go`. This establishes the pattern for all future tenant-scoped handlers.

**Pattern:**
```go
func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
    tenantID := middleware.GetTenantID(r.Context())
    var agents []AgentInstance
    err := database.WithTenantConnection(r.Context(), s.pool, tenantID, func(ctx context.Context, q database.Querier) error {
        rows, err := q.Query(ctx, "SELECT ... FROM agent_instances")
        // ...scan...
        return err
    })
    // ...write response...
}
```

**Scope:** Only wire `handleListAgents` in this P1. Existing auth stores use explicit `tenant_id` WHERE clauses and don't need retrofitting — RLS is defense-in-depth, not the primary access control. Future handlers adopt the pattern.

## Files Summary

| File | Action |
|------|--------|
| `migrations/000005_platform_admin.up.sql` | CREATE |
| `migrations/000005_platform_admin.down.sql` | CREATE |
| `scripts/seed_platform_admin.sql` | CREATE |
| `internal/auth/auth.go` | MODIFY (Identity + IsPlatformAdmin) |
| `internal/auth/token.go` | MODIFY (JWT claims) |
| `internal/auth/handler.go` | MODIFY (tenantless callback path) |
| `internal/auth/middleware.go` | MODIFY (RequirePlatformAdmin) |
| `internal/auth/store.go` | MODIFY (lookup by OIDC subject for platform admin) |
| `internal/tenant/tenant.go` | CREATE |
| `internal/tenant/store.go` | CREATE |
| `internal/tenant/handler.go` | CREATE |
| `internal/tenant/store_test.go` | CREATE |
| `internal/tenant/handler_test.go` | CREATE |
| `internal/platform/database/rls_test.go` | CREATE |
| `internal/platform/server/server.go` | MODIFY (register tenant routes, wire handleListAgents) |
