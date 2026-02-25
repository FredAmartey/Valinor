# Phase 9 Slice 2: User & Department Management — Design Document

## Goal

Add User Management and Department Management views to the admin dashboard, enabling tenant admins to manage their organization's users, department hierarchy, department memberships, and role assignments.

## Scope

### In scope

- User list page with search/filter
- User detail page with department memberships (add/remove) and role assignments (assign/remove)
- Create user form
- Department list page with hierarchy visualization (indented rows)
- Department detail page with member list (add/remove)
- Create department form with optional parent
- TanStack Query hooks for users, departments, and roles
- New TypeScript types (Role, UserRole, CreateUserRequest, CreateDepartmentRequest)
- Skeleton loading states, error boundaries, empty states per section
- Vitest tests for query hooks, forms, and hierarchy rendering

### Out of scope

- Role CRUD (create/edit/delete roles) — deferred to RBAC Configuration slice
- User edit/update (no endpoint exists yet)
- Department edit/rename (no endpoint exists yet)
- User suspension/activation (no endpoint exists yet)
- Bulk operations

## No Go API Changes

All required endpoints already exist:

| Endpoint | Method | Permission |
|----------|--------|------------|
| `/api/v1/users` | GET, POST | `users:read`, `users:write` |
| `/api/v1/users/{id}` | GET | `users:read` |
| `/api/v1/users/{id}/departments` | POST | `users:write` |
| `/api/v1/users/{id}/departments/{deptId}` | DELETE | `users:write` |
| `/api/v1/users/{id}/roles` | GET, POST, DELETE | `users:read`, `users:manage` |
| `/api/v1/departments` | GET, POST | `departments:read`, `departments:write` |
| `/api/v1/departments/{id}` | GET | `departments:read` |
| `/api/v1/roles` | GET | `users:read` |

---

## User Management Views

### User List (`/users`)

- Filterable table: display name, email, status, department memberships (as pills), created date
- Search input with debounced filtering on name or email
- Status pills: emerald (active), amber (suspended)
- Department memberships shown as small badges per row — click navigates to department detail
- "Create user" button top-right
- Row click navigates to user detail
- Server-side initial fetch, client-side TanStack Query for interactive filtering

### User Detail (`/users/[id]`)

- Header: display name (or email fallback), email, status badge, created date
- **Departments section**: list of memberships with remove button per item. "Add to department" dropdown at bottom selecting from tenant departments
- **Roles section**: list of role assignments showing role name, scope type (org/department), scope name. Remove button per item. "Assign role" inline form: select role, scope type dropdown (org/department), scope selector (tenant name for org, department dropdown for department scope)
- Inline editing with TanStack Query mutations for immediate cache invalidation
- Parallel fetch of user, user roles, and departments list via `Promise.all()` in server component

### Create User (`/users/new`)

- Form: email (required, validated client-side), display name (optional)
- On success: redirect to user detail page
- Label above input, error inline, same patterns as Slice 1

---

## Department Management Views

### Department List (`/departments`)

- Table: name (indented by hierarchy depth), parent department name (or "—"), member count, created date
- Hierarchy visualization: flat table with left-padding based on depth (`pl-[calc(depth*1.5rem)]`) and subtle `border-l` connector
- Search input filtering by name
- "Create department" button top-right
- Row click navigates to department detail

### Department Detail (`/departments/[id]`)

- Header: department name, parent department link (or "Top-level"), created date
- **Members section**: user list showing display name, email, status. Remove button per member. "Add member" dropdown selecting from tenant users not already in this department

### Create Department (`/departments/new`)

- Form: name (required), parent department (optional dropdown from existing departments)
- On success: redirect to department detail

---

## Data Layer

### New Query Hooks

**`lib/queries/users.ts`**: `userKeys` factory, `useUsersQuery`, `useUserQuery`, `useCreateUserMutation`, `useAddUserToDepartmentMutation`, `useRemoveUserFromDepartmentMutation`

**`lib/queries/departments.ts`**: `departmentKeys` factory, `useDepartmentsQuery`, `useDepartmentQuery`, `useCreateDepartmentMutation`

**`lib/queries/roles.ts`**: `roleKeys` factory, `useRolesQuery`, `useUserRolesQuery`, `useAssignRoleMutation`, `useRemoveRoleMutation`

### New Types (additions to `lib/types.ts`)

```typescript
interface Role {
  id: string
  tenant_id: string
  name: string
  permissions: string[]
  is_system: boolean
  created_at: string
}

interface UserRole {
  user_id: string
  role_id: string
  role_name: string
  scope_type: "org" | "department"
  scope_id: string
}

interface CreateUserRequest {
  email: string
  display_name?: string
}

interface CreateDepartmentRequest {
  name: string
  parent_id?: string
}
```

---

## Design System

Follows all rules established in Slice 1 design doc:
- Zinc/Slate neutrals, Emerald accent, muted Rose for alerts
- Geist + Geist Mono fonts
- Cards only where elevation communicates hierarchy
- Skeleton loaders matching layout dimensions
- Empty states with CTAs
- `active:scale-[0.98]` on buttons
- `min-h-[100dvh]`, `max-w-[1400px] mx-auto`

---

## Testing

| Layer | What |
|-------|------|
| Query hook functions (Vitest) | Verify correct endpoints called with correct params |
| Create user form (Vitest + RTL) | Email validation, submit behavior |
| Department hierarchy (Vitest + RTL) | Indentation logic, parent-child rendering |
| Role assignment form (Vitest + RTL) | Scope type toggle, dropdown population |

---

## Acceptance Criteria

1. Tenant admin can list, view, and create users
2. Tenant admin can view user's departments and add/remove memberships
3. Tenant admin can view user's roles and assign/remove role assignments
4. Tenant admin can list, view, and create departments with hierarchy
5. Department detail shows member list with add/remove
6. All views have skeleton loading states and empty states
7. `npm run build` succeeds with zero TypeScript errors
8. `npx vitest run` passes

---

## Risks & Rollback

| Risk | Mitigation |
|------|------------|
| Department hierarchy depth causes layout issues | Cap indentation at 4 levels visually |
| Role assignment form complexity | Scope type toggle simplifies to two states: org-wide or department-specific |

Rollback: Remove the new route files. No Go changes to revert.
