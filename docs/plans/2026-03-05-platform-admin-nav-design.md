# Platform Admin Tenant Navigation — Design

## Problem

Platform admins only see Overview and Tenants in the sidebar. They can view tenant stats on the detail page but cannot drill into tenant-scoped resources (Users, Departments, RBAC, Agents, Channels, Connectors, Audit Log). In emergencies, they have no way to take action inside a tenant.

## Design Decisions

- **Read-only drill-down by default** — platform admin views tenant resources without write access
- **Nested routes** (`/tenants/[id]/users`) — keeps the "outsider looking in" context clear
- **Path-based backend routes** — most secure; no query param/header tenant override that could be abused
- **Emergency impersonation** — separate mode with full write access, short-lived JWT, audit trail
- **Reuse existing components** — pass `tenantId` + `readOnly` props rather than duplicating

## Navigation & URL Structure

Platform admin default sidebar: Overview, Tenants.

Inside tenant drill-down, sidebar changes to:
- Tenant name + "← Back to Tenants" at top
- Sub-nav: Users, Departments, RBAC, Agents, Channels, Connectors, Audit Log

Routes:
```
/tenants/[id]           → tenant overview (existing detail page, stats link to sub-pages)
/tenants/[id]/users
/tenants/[id]/departments
/tenants/[id]/agents
/tenants/[id]/channels
/tenants/[id]/connectors
/tenants/[id]/rbac
/tenants/[id]/audit
```

## Frontend — Component Reuse & Read-Only Mode

Existing table components get two new optional props:

```typescript
tenantId?: string   // override session tenant for cross-tenant queries
readOnly?: boolean  // hides create/edit/delete actions
```

- `/tenants/[id]/users` page extracts tenant ID from route, passes `tenantId={id} readOnly` to `<UserTable>`
- Query hooks get optional `tenantId` override — when provided, API calls go to `/api/v1/tenants/{id}/users`
- `readOnly` hides "Create" buttons, edit links, delete actions
- Subtle banner at top of each page: "Viewing [Tenant Name] — Read only"

### Layout & Context

- New layout at `app/(dashboard)/tenants/[id]/layout.tsx` wraps drill-down pages
- Fetches tenant name, renders tenant-scoped sidebar
- `TenantContext` provider so child pages access tenant ID/name without prop drilling

## Backend — Path-Based Tenant Routes

New read-only routes, platform admin only:

```
GET /api/v1/tenants/{id}/users
GET /api/v1/tenants/{id}/departments
GET /api/v1/tenants/{id}/agents
GET /api/v1/tenants/{id}/channels
GET /api/v1/tenants/{id}/connectors
GET /api/v1/tenants/{id}/rbac/roles
GET /api/v1/tenants/{id}/audit/events
```

- `PlatformAdminOnly` middleware — checks `identity.IsPlatformAdmin`, rejects with 403
- Thin handler wrapper: extracts `{id}` from path, validates tenant exists, sets tenant context via `database.WithTenantConnection`, delegates to existing handler query logic
- Only GET methods — no POST/PUT/DELETE
- RLS enforced at DB level via `app.current_tenant_id`
- No new tables or migrations

## Emergency Tenant Impersonation

For emergencies (locked-out org_admin, rogue agent, broken RBAC):

### UX Flow
1. Tenant detail page shows "Enter Tenant" button with warning icon
2. Confirmation dialog: "You are about to enter [Tenant Name] with full admin privileges. All actions will be logged in the audit trail."
3. On confirm, backend issues short-lived JWT scoped to that tenant
4. Redirect to normal `/users`, `/agents` routes (standard tenant sidebar)
5. Persistent red banner: "Impersonating [Tenant Name] — Emergency access • [Exit]"
6. "Exit" drops impersonation JWT, returns to `/tenants`

### Backend
- `POST /api/v1/tenants/{id}/impersonate` — platform admin only
- Returns JWT with:
  - `tenantId`: target tenant
  - `isPlatformAdmin: true` (retained)
  - `roles: ["org_admin"]` (full permissions)
  - 30-minute TTL
- All actions audit-logged with `source: "platform_admin_impersonation"` and `impersonator_id` in metadata

## Scope Summary

| Mode | URL pattern | Access | Sidebar |
|------|------------|--------|---------|
| Platform admin default | `/`, `/tenants` | Overview + tenant list | Overview, Tenants |
| Tenant drill-down (read-only) | `/tenants/[id]/users`, etc. | View any tenant's resources | Tenant sub-nav + "← Back" |
| Emergency impersonation | `/users`, `/agents`, etc. | Full write, 30min TTL | Normal tenant sidebar + red banner |

## Out of Scope

- Two-person approval for impersonation (follow-up for enterprise)
- Editing tenant settings from drill-down (use existing detail page)
- Dedicated impersonation audit viewer (use existing audit page)
