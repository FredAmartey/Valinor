# Phase 9 Slice 5 — RBAC Configuration

## Goal

Give org_admins a dedicated RBAC page to view system roles, create/edit/delete custom roles with a permission checkbox matrix, and manage role assignments. Custom roles are enforced at runtime by switching the evaluator from hardcoded in-memory roles to DB-backed roles.

## Scope

### In scope

- DB-backed evaluator: load roles from `roles` table at startup, reload on mutation
- New API endpoints: `PUT /api/v1/roles/{id}`, `DELETE /api/v1/roles/{id}`
- System role protection: reject update/delete on `is_system=true` roles
- Wildcard `*` rejection for non-system roles
- Delete-with-assignments guard (409 if role is assigned to users)
- Dashboard `/rbac` page with role list + permission matrix detail
- Checkbox matrix: resources as rows, actions as columns
- System roles shown read-only with banner
- Custom role CRUD: create dialog, inline edit via matrix, delete dialog
- Permission gating: page requires `users:manage`

### Out of scope

- Resource-level policy editor (existing `resource_policies` table — future slice)
- Department-scoped permission restrictions in the matrix
- Role inheritance / hierarchy
- Bulk role assignment from the RBAC page (use user detail page)

## Backend Changes

### DB-Backed Evaluator

New interface in `internal/rbac/`:

```go
type RoleLoader interface {
    LoadRoles(ctx context.Context) ([]RoleDef, error)
}

type RoleDef struct {
    Name        string
    Permissions []string
}
```

`Evaluator` gains:
- `loader RoleLoader` field, set via constructor
- `ReloadRoles(ctx context.Context) error` — queries DB, rebuilds `map[string][]string` under write lock
- Called at startup in `main.go` (replacing 4 `RegisterRole` calls)
- Called after create/update/delete in role handlers

The `RoleLoader` implementation queries `SELECT name, permissions FROM roles` across all tenants (role names are global — the evaluator is not tenant-scoped).

### New API Endpoints

| Method | Endpoint | Permission | Behavior |
|--------|----------|------------|----------|
| `PUT` | `/api/v1/roles/{id}` | `users:manage` | Update name + permissions. Reject if `is_system=true` (403). Reject `*` in permissions for non-system roles (400). Reload evaluator on success. |
| `DELETE` | `/api/v1/roles/{id}` | `users:manage` | Delete role. Reject if `is_system=true` (403). Reject if role has user assignments (409). Reload evaluator on success. |

### System Role Protection

- `is_system=true` roles cannot be updated or deleted via API
- Wildcard `*` permission cannot be granted to non-system roles
- System roles are defined by the seed SQL (`scripts/seed_dev_roles.sql`)

## Frontend Changes

### Route

`/rbac` — already linked in sidebar. Page component at `dashboard/src/app/(dashboard)/rbac/page.tsx`.

### Page Layout

Two-panel: role list (left) + role detail (right).

### Role List

Table with columns: Name, Permission Count, Type (system badge), Users Assigned. "Create Role" button visible only for org_admin. Click row to select and show detail.

### Role Detail — Permission Matrix

Checkbox grid:

| Resource | read | write | message | manage |
|----------|------|-------|---------|--------|
| Agents | ✓ | ✓ | ✓ | |
| Users | ✓ | ✓ | | ✓ |
| Departments | ✓ | ✓ | | |
| Connectors | ✓ | ✓ | | |
| Channels: Links | ✓ | ✓ | | |
| Channels: Messages | | ✓ | | |
| Channels: Outbox | ✓ | ✓ | | |
| Channels: Providers | ✓ | ✓ | | |

- Empty cells (e.g., Users:message) are not rendered — only valid permission combinations appear
- System roles: all checkboxes disabled, "System role — read only" banner
- Custom roles: checkboxes enabled, dirty state tracked, Save button appears on change

### Components

- `RoleList` — `useRolesQuery()`, table with system badge
- `RoleDetail` — selected role metadata + `PermissionMatrix`
- `PermissionMatrix` — checkbox grid, `permissions[]` + `readonly` prop
- `CreateRoleDialog` — name input + empty matrix, `POST /api/v1/roles`
- `DeleteRoleDialog` — confirmation, `DELETE /api/v1/roles/{id}`

### New Query Hooks

Add to `dashboard/src/lib/queries/roles.ts`:

- `useUpdateRoleMutation()` — `PUT /api/v1/roles/{id}`, invalidates `roleKeys.list()`
- `useDeleteRoleMutation()` — `DELETE /api/v1/roles/{id}`, invalidates `roleKeys.list()`

### State Management

TanStack Query for server state. Local `useState` for dirty permission edits in the matrix. Save triggers PUT then invalidates query cache.

## Data Flow

1. Admin edits matrix checkbox → local dirty state updated
2. Save → `PUT /api/v1/roles/{id}` with `{name, permissions[]}`
3. Backend updates DB → calls `evaluator.ReloadRoles(ctx)`
4. Evaluator rebuilds in-memory map under write lock
5. Next `Authorize` call uses new permissions immediately
6. Response returns → frontend invalidates `roleKeys.list()`

## Edge Cases

- **JWT staleness:** Evaluator looks up permissions by role *name* from its current in-memory map, not from the JWT payload. So permission changes take effect immediately for enforcement, even if the user's JWT is stale. UI-side gating (`useCan`) still uses JWT roles — acceptable lag until re-login.
- **Delete assigned role:** 409 with message "role is assigned to N users — remove assignments first." No cascade.
- **Rename collision:** `UNIQUE(tenant_id, name)` → 409.
- **Concurrent edits:** Last write wins. Matrix is small, merge not worth the complexity.
- **Empty permissions:** Valid — effectively a no-access role. UI allows it with a visual hint.
- **Wildcard injection:** Handler rejects `*` in permissions array for non-system roles (400).

## Testing

### Backend
- Evaluator: `ReloadRoles` loads from DB, replaces in-memory map, concurrent reads safe
- Handlers: create/update/delete happy path, system role rejection, assigned-role deletion guard, wildcard rejection
- Integration: create custom role → assign to user → authorize succeeds for granted permission

### Frontend
- Matrix renders correct cells for known permission set
- System role: all checkboxes disabled, banner shown
- Custom role: checkboxes toggle, dirty state tracked, save calls PUT
- Create dialog: validates name, submits, appears in list
- Delete dialog: confirms, submits, removed from list
- Permission gating: page hidden from non-org_admin users

## Risks

- **Evaluator reload under load:** Write lock during reload blocks concurrent `Authorize` calls briefly. Acceptable — role mutations are rare admin operations, reload is a fast in-memory map swap.
- **Role name divergence:** If the seed SQL role names ever differ from what's in the DB, the evaluator uses DB as source of truth. Seed script is authoritative for fresh installs.
- **Multi-instance deployment:** If multiple Go instances run, a role mutation on one instance won't propagate to others. Future: add a notification mechanism (pg_notify or polling). For now, single-instance is the deployment model.

## Rollback

- Backend: revert evaluator to hardcoded `RegisterRole` calls. Custom roles in DB become inert (display-only, as before).
- Frontend: remove `/rbac` page. Sidebar link becomes dead (same as current state).
