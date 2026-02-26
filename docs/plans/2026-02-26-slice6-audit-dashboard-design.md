# Phase 9, Slice 6: Audit Dashboard — Design Document

## Goal

Deliver a full audit log experience: backend API filters + CRUD event emission (Slice 6a), then a dashboard UI for browsing, filtering, and inspecting audit events (Slice 6b).

## Delivery Structure

Two sub-slices, each a separate PR:

- **Slice 6a** — Backend: API filters, CRUD event constants, emit audit events from existing handlers
- **Slice 6b** — Dashboard: audit log page, filter bar, expandable rows, query hooks, nav fix

---

## Slice 6a: Backend — Audit Filters + CRUD Events

### API Changes

Extend `GET /api/v1/audit/events` with new query parameters:

| Param | Type | Example | Notes |
|-------|------|---------|-------|
| `action` | string | `user.created` | Exact match |
| `resource_type` | string | `agent` | Exact match |
| `user_id` | UUID | `a1b2...` | Filter by actor |
| `source` | string | `api` | Exact match |
| `before` | RFC3339 | `2026-02-26T00:00:00Z` | Upper bound on created_at |
| `limit` | int | `50` | Existing, unchanged (default 50, max 200) |
| `after` | RFC3339 | `2026-02-25T00:00:00Z` | Existing, unchanged |

All filters are optional, composable (AND logic), applied in SQL with parameterized queries.

### New Audit Action Constants

```go
// CRUD actions
ActionUserCreated              = "user.created"
ActionUserUpdated              = "user.updated"
ActionUserSuspended            = "user.suspended"
ActionUserReactivated          = "user.reactivated"

ActionAgentProvisioned         = "agent.provisioned"
ActionAgentUpdated             = "agent.updated"
ActionAgentDestroyed           = "agent.destroyed"

ActionTenantCreated            = "tenant.created"
ActionTenantUpdated            = "tenant.updated"
ActionTenantSuspended          = "tenant.suspended"

ActionDepartmentCreated        = "department.created"
ActionDepartmentUpdated        = "department.updated"
ActionDepartmentDeleted        = "department.deleted"

ActionRoleCreated              = "role.created"
ActionRoleUpdated              = "role.updated"
ActionRoleDeleted              = "role.deleted"

ActionUserRoleAssigned         = "user_role.assigned"
ActionUserRoleRevoked          = "user_role.revoked"
```

### Event Emission Points

Add `audit.Log()` calls to existing HTTP handlers:

| Handler | Actions | Files |
|---------|---------|-------|
| Tenant CRUD | tenant.created, tenant.updated, tenant.suspended | `internal/tenant/handler.go` |
| User CRUD | user.created, user.updated, user.suspended, user.reactivated | `internal/tenant/handler.go` |
| Department CRUD | department.created, department.updated, department.deleted | `internal/tenant/handler.go` |
| Agent lifecycle | agent.provisioned, agent.updated, agent.destroyed | `internal/orchestrator/handler.go` |
| Role CRUD | role.created, role.updated, role.deleted | `internal/rbac/handler.go` |
| User role assignment | user_role.assigned, user_role.revoked | `internal/rbac/handler.go` or `internal/tenant/handler.go` |

Each event captures:
- `TenantID` from request context
- `UserID` from JWT claims
- `Action` constant
- `ResourceType` (e.g. "user", "agent")
- `ResourceID` of the created/modified resource
- `Metadata` with relevant details (e.g. `{"email": "...", "display_name": "..."}` for user creation)
- `Source` = "api"

### Store Changes

Replace current raw limit/after query with a `ListEventsParams` struct:

```go
type ListEventsParams struct {
    TenantID     uuid.UUID
    Action       *string
    ResourceType *string
    UserID       *uuid.UUID
    Source       *string
    After        *time.Time
    Before       *time.Time
    Limit        int
}
```

Dynamic WHERE clause builder using parameterized queries. No string concatenation.

### Acceptance Criteria (Slice 6a)

1. `GET /api/v1/audit/events?action=user.created` returns only user.created events
2. `GET /api/v1/audit/events?resource_type=agent&source=api` composes filters correctly
3. `GET /api/v1/audit/events?after=...&before=...` returns events within date range
4. Creating a user via API produces a `user.created` audit event
5. Provisioning an agent produces an `agent.provisioned` audit event
6. Creating/updating/deleting a role produces corresponding audit events
7. All new SQL uses parameterized queries
8. `go test ./internal/audit/...` passes
9. `go test ./...` passes (no regressions)

---

## Slice 6b: Dashboard — Audit Log UI

### Page & Route

- Route: `/audit`
- Server component: `app/(dashboard)/audit/page.tsx` — title, description, wraps `<AuditTable />`
- Client component: `components/audit/audit-table.tsx` — filters, table, expandable rows

### Filter Bar

Horizontal bar above the table:

| Filter | Type | Values |
|--------|------|--------|
| Action | Dropdown | Grouped by category: Channel, User, Agent, Tenant, Department, Role |
| Resource type | Dropdown | user, agent, tenant, department, role, connector |
| Source | Dropdown | api, whatsapp, telegram, slack, system |
| Date range | Two date inputs | Maps to `after` / `before` API params |
| Clear all | Button | Visible when any filter is active |

All filters hit the backend API directly. Changing a filter updates the TanStack Query key, triggering a refetch.

### Table Layout

| Column | Width | Content |
|--------|-------|---------|
| Time | `140px` | `formatTimeAgo()`, full timestamp on hover via title attribute |
| Action | `1fr` | Human-readable label (e.g. "User Created") with colored category dot |
| Resource | `1fr` | Resource type + truncated resource_id |
| Actor | `1fr` | Truncated user_id, or "System" if null |
| Source | `100px` | Pill/badge: API, WhatsApp, Telegram, Slack, System |

Sort: `created_at DESC` (fixed, from API).

### Expandable Row Detail

Click a row to expand inline below it:

- Full event ID (copyable)
- Full resource ID (copyable)
- Full actor ID (copyable)
- Correlation ID (from metadata, if present)
- Metadata as key-value pairs (not raw JSON)
- Full timestamp in long format (`formatDate(created_at, "long")`)

### Pagination

Cursor-based using timestamps:
- "Older" button: passes `before` = `created_at` of last visible event
- "Newer" button: passes `after` = `created_at` of first visible event
- No page numbers (append-only data)

### States

| State | Behavior |
|-------|----------|
| Loading | 6 skeleton rows matching table column widths |
| Empty (no filters) | "No events have been recorded yet" |
| Empty (with filters) | "No events match your filters" with "Clear filters" link |
| Error | Rose banner inline with retry button |

### Query Hook

New file: `dashboard/src/lib/queries/audit.ts`

```typescript
auditKeys = {
  all: ["auditEvents"] as const,
  list: (filters: AuditFilters) => [...auditKeys.all, "list", filters] as const,
}
```

- `fetchAuditEvents(accessToken, params)` — calls `GET /api/v1/audit/events`
- `useAuditEventsQuery(filters)` — enabled when session exists, staleTime 30s
- Filter params included in query key for automatic refetch on change

### Type Updates

Add to `dashboard/src/lib/types.ts`:

```typescript
export interface AuditListResponse {
  events: AuditEvent[]
  count: number
}

export interface AuditFilters {
  action?: string
  resource_type?: string
  user_id?: string
  source?: string
  after?: string
  before?: string
  limit?: number
}
```

Fix: remove `correlation_id` from `AuditEvent` interface (not in API response; it's inside `metadata`).

### Nav Permission Fix

Replace the current `canReadConnectors` gate on "Audit Log" nav item with a proper `canReadAudit` check using the `audit:read` permission (already defined in backend RBAC roles).

### Action Label Mapping

Utility in `components/audit/audit-labels.ts`:

```typescript
const ACTION_LABELS: Record<string, { label: string; category: string; color: string }> = {
  "user.created": { label: "User Created", category: "User", color: "emerald" },
  "channel.action_denied_rbac": { label: "Action Denied (RBAC)", category: "Channel", color: "rose" },
  // ...
}
```

Categories: Channel, User, Agent, Tenant, Department, Role — each with a dot color.

### Acceptance Criteria (Slice 6b)

1. `/audit` page renders with filter bar and table
2. Selecting an action filter fetches filtered results from API
3. Date range filter constrains visible events
4. Clicking a row expands to show metadata details inline
5. "Older" / "Newer" pagination navigates through events
6. Loading state shows skeleton rows
7. Empty state adjusts message based on active filters
8. Error state shows retry banner
9. Nav item gated by `audit:read` permission (not `connectors:read`)
10. `npm run build` succeeds with zero TypeScript errors
11. Vitest component tests pass for AuditTable and filter interactions

---

## Risks & Rollback

| Risk | Mitigation |
|------|------------|
| Audit event emission adds latency to CRUD handlers | Audit logger is async (buffered channel), fire-and-forget. No handler blocking. |
| Filter query builder SQL injection | All filters use parameterized queries, validated types (UUID, RFC3339, string enum). |
| Large event volume in production | Limit stays at max 200, cursor pagination prevents unbounded queries. Partitioned table. |
| Breaking existing audit API consumers | All new params are optional. Existing behavior unchanged with no params. |

### Rollback

- Slice 6a: Revert Go PR. Audit events stop being emitted for CRUD; existing channel events unaffected.
- Slice 6b: Revert dashboard PR. `/audit` route disappears; rest of dashboard unaffected.
