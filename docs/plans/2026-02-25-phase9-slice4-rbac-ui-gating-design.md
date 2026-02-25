# Phase 9 Slice 4 — RBAC UI Gating Design

**Date:** 2026-02-25

## Goal

Gate dashboard UI elements (nav links, Create buttons, Configure/Destroy buttons) based on the
authenticated user's roles, so the interface reflects what each user is actually allowed to do.

## Scope

**In scope:**
- Propagate `roles: string[]` from JWT into the NextAuth session
- `PermissionProvider` React context + `useCan()` hook
- Hide sidebar nav links (Users, Departments, RBAC) for users without `users:read`
- Hide "Create Agent" button and `/agents/new` page for users without `agents:write`
- Show "Configure" and "Destroy" buttons as disabled-with-tooltip for users without `agents:write`

**Out of scope:**
- Backend permission changes (already enforced in Go)
- Per-department scoping (dept_head can only manage their own dept) — future slice
- Role management UI (already in scope for a separate slice)
- Any changes to the platform admin nav (Tenants link already gated by `isPlatformAdmin`)

## Data Flow

1. User logs in → Go backend issues JWT with `roles: ["standard_user"]` claim
2. NextAuth `jwt()` callback decodes the access token payload (base64) and extracts `roles: string[]`
3. NextAuth `session()` callback copies `roles` and `isPlatformAdmin` onto the session object
4. Dashboard layout server component calls `auth()` and renders `<PermissionProvider>` around the page tree
5. Client components call `useCan("agents:write")` → boolean, no extra API calls, no prop drilling

## Architecture

### Approach

React Context `PermissionProvider` (Approach B). Chosen over a standalone utility function approach
because it centralises permission reads into one context, avoiding scattered `useSession()` calls
across components and making it easy to test by wrapping components in a mock provider.

### Permission Map

Mirrors the Go backend's in-memory role→permission map:

| Role | Permissions |
|---|---|
| `org_admin` | `["*"]` |
| `dept_head` | agents r/w, users r/w, departments r/w, connectors r/w, channels r/w |
| `standard_user` | `["agents:read", "agents:message"]` |
| `read_only` | `["agents:read"]` |

### `can(permission)` Resolution

1. `isPlatformAdmin === true` → `true` (full bypass)
2. Any role grants `"*"` → `true`
3. Any role's grants include the exact permission string → `true`
4. Otherwise → `false`

Users may hold multiple roles; the check is a union (any qualifying role is sufficient).

### Files

- `dashboard/src/lib/permissions.ts` — permission map, `resolvePermissions()` pure function
- `dashboard/src/components/providers/permission-provider.tsx` — React context + `useCan()` hook
- `dashboard/src/app/(dashboard)/layout.tsx` — mount `PermissionProvider` with session data
- `dashboard/src/lib/auth.ts` (NextAuth config) — extract `roles` from JWT in callbacks
- `dashboard/src/lib/types.ts` — extend `Session` type with `roles: string[]`

## UX Rules

| Element | Behaviour |
|---|---|
| Sidebar: Users, Departments, RBAC links | **Hidden** if user lacks `users:read` |
| "Create Agent" button | **Hidden** if user lacks `agents:write` |
| `/agents/new` page | Redirect to `/agents` if user lacks `agents:write` |
| "Configure" button (agent detail) | **Disabled + tooltip** if user lacks `agents:write` |
| "Destroy" button (agent detail) | **Disabled + tooltip** if user lacks `agents:write` |
| Agent list, chat/message interface | No change — available to all roles with `agents:read` |

Tooltip text: "You don't have permission to do this."

## Acceptance Criteria

- Logged in as `glorfindel` (standard_user): Users/Departments/RBAC nav links absent, Create Agent button absent, Configure/Destroy buttons visible but disabled with tooltip
- Logged in as `ecthelion` (dept_head): Users/Departments links present, Create Agent button present, Configure/Destroy buttons active
- Logged in as `turgon` (org_admin + isPlatformAdmin): all controls active, Tenants nav link present (unchanged)
- Logged in as `maeglin` (read_only): same as standard_user for nav; no agent:message access either
- Backend still enforces permissions independently — UI gating is UX polish, not a security boundary

## Risks

- NextAuth JWT decode: access token is a standard JWT (base64url). If the Go backend ever switches to
  opaque tokens, this breaks. Mitigation: keep the decode in one place (`auth.ts` callbacks only).
- Role changes mid-session: roles are baked into the JWT at login. If an admin changes a user's role,
  the UI won't update until the user's token refreshes (default NextAuth session lifetime). Acceptable
  for now — backend enforcement is immediate regardless.

## Rollback

Delete `permission-provider.tsx`, revert `layout.tsx`, revert `auth.ts` callbacks, revert `types.ts`.
No database migrations. No backend changes.
