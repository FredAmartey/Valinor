# Tenant Detail Stats — Design

## Goal

Replace the placeholder `--` values on the tenant detail page with live counts of users, departments, agents, and connectors for the selected tenant.

## Approach

Enrich the existing `GET /api/v1/tenants/{id}` response with a `stats` object. No new endpoints.

## Backend

Add a `TenantStats` struct:

```go
type TenantStats struct {
    Users       int `json:"users"`
    Departments int `json:"departments"`
    Agents      int `json:"agents"`
    Connectors  int `json:"connectors"`
}
```

Add `GetStats(ctx, tenantID) (*TenantStats, error)` to the tenant store. Single query using sub-selects:

```sql
SELECT
  (SELECT COUNT(*) FROM users WHERE tenant_id = $1) AS users,
  (SELECT COUNT(*) FROM departments WHERE tenant_id = $1) AS departments,
  (SELECT COUNT(*) FROM agent_instances WHERE tenant_id = $1) AS agents,
  (SELECT COUNT(*) FROM connectors WHERE tenant_id = $1) AS connectors
```

This runs as platform admin (no RLS session variable needed) since the route is gated by `RequirePlatformAdmin`.

Modify `HandleGet` to call `GetStats` after fetching the tenant, and include stats in the response.

Response shape:

```json
{
  "id": "...",
  "name": "Gondolin FC",
  "slug": "gondolin-fc",
  "status": "active",
  "settings": {},
  "created_at": "...",
  "updated_at": "...",
  "stats": {
    "users": 5,
    "departments": 3,
    "agents": 2,
    "connectors": 1
  }
}
```

## Frontend

Extend `Tenant` type with optional stats:

```typescript
export interface TenantStats {
  users: number
  departments: number
  agents: number
  connectors: number
}

export interface Tenant {
  // ... existing fields
  stats?: TenantStats
}
```

Replace `--` placeholders in `tenant-detail.tsx` with `tenant.stats?.users ?? "--"` etc.

## Access Control

Platform admin only — no change needed. The route already requires `RequirePlatformAdmin`.

## Testing

Store-level test for `GetStats` returning correct counts (requires testcontainers).
