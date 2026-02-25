# Phase 9 Slice 4: RBAC UI Gating Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Surface the user's roles from the backend JWT into the NextAuth session and use them to hide/disable UI controls the user lacks permission to use, preventing confusing 403 errors.

**Architecture:** Decode the `roles` claim from the backend access token (JWT payload is public base64) during NextAuth sign-in and store it in the session. Mirror the backend's in-memory role→permission map as a client-side pure function. Use a `usePermission()` hook in client components and `hasPermission()` directly in server components to conditionally render action buttons, nav items, and gate "new" pages.

**Tech Stack:** Next.js 15 (App Router), NextAuth v5, React, TypeScript, Vitest + React Testing Library

---

## Background

The backend already enforces RBAC on every endpoint. The four roles and their permissions (mirroring `cmd/valinor/main.go`):

| Role | Permissions |
|---|---|
| `org_admin` | `*` (wildcard — everything) |
| `dept_head` | `agents:read/write/message`, `users:read/write`, `departments:read`, `connectors:read/write`, `channels:*` |
| `standard_user` | `agents:read`, `agents:message`, `channels:messages:write` |
| `read_only` | `agents:read` |

The backend JWT access token already contains a `roles: ["org_admin"]` claim (field name `"roles"` in the JSON payload). We just need to extract it into the NextAuth session.

---

## What Gets Gated

| UI Element | Required Permission | Hidden for |
|---|---|---|
| Sidebar: Users, Departments | `users:read` | `standard_user`, `read_only` |
| Sidebar: RBAC, Channels, Connectors, Audit | `connectors:read` | `standard_user`, `read_only` |
| "Provision agent" button / `/agents/new` page | `agents:write` | `standard_user`, `read_only` |
| Agent detail: Configure + Destroy buttons | `agents:write` | `standard_user`, `read_only` |
| "Create user" button / `/users/new` page | `users:write` | `read_only` (dept_head can create users) |
| "Create department" button / `/departments/new` page | `departments:write` | `dept_head`, `standard_user`, `read_only` |

---

## Task 1: Add `roles` to NextAuth session

**Files:**
- Modify: `dashboard/src/lib/auth.ts`

The access token is a signed JWT: `header.payload.signature`. The payload is base64url-encoded JSON we can decode without the signing secret (we trust it — we just received it from our own backend). The JWT claims use field name `"roles"` (see `internal/auth/token.go`).

**Step 1: Read the file**

```
Read: dashboard/src/lib/auth.ts
```

**Step 2: Add `roles` to the JWT and Session type declarations**

In the `declare module "next-auth"` block, update `Session.user` and `User`:
```typescript
interface Session {
  accessToken: string
  user: {
    id: string
    email: string
    name: string
    tenantId: string | null
    isPlatformAdmin: boolean
    roles: string[]          // ← add this
  }
}

interface User {
  id: string
  email: string
  name: string
  tenantId: string | null
  isPlatformAdmin: boolean
  accessToken: string
  refreshToken: string
  expiresIn: number
  roles: string[]            // ← add this
}
```

In the `declare module "@auth/core/jwt"` block, update `JWT`:
```typescript
interface JWT {
  accessToken: string
  refreshToken: string
  expiresAt: number
  userId: string
  tenantId: string | null
  isPlatformAdmin: boolean
  roles: string[]            // ← add this
}
```

**Step 3: Add a decode helper and extract roles in `authorize()`**

Add this helper function before `authConfig` (it runs server-side so `Buffer` is available):

```typescript
function decodeJwtRoles(token: string): string[] {
  try {
    const payload = token.split(".")[1]
    const json = Buffer.from(payload, "base64url").toString("utf8")
    const claims = JSON.parse(json) as { roles?: string[] }
    return Array.isArray(claims.roles) ? claims.roles : []
  } catch {
    return []
  }
}
```

In the `authorize()` function, after `const data = await res.json()`, add:
```typescript
const roles = decodeJwtRoles(data.access_token)
```

And include it in the returned user object:
```typescript
return {
  // ... existing fields ...
  roles,
}
```

**Step 4: Persist `roles` through the `jwt` callback**

In the `jwt` callback, in the `if (user)` block that handles initial sign-in, add:
```typescript
token.roles = user.roles ?? []
```

**Step 5: Surface `roles` in the `session` callback**

In the `session` callback, add:
```typescript
session.user.roles = token.roles
```

**Step 6: Build to verify no TypeScript errors**

```bash
cd dashboard && npm run build 2>&1 | tail -5
```

Expected: Clean build, no TypeScript errors.

**Step 7: Commit**

```bash
git add dashboard/src/lib/auth.ts
git commit -m "feat(auth): surface roles from JWT in NextAuth session"
```

---

## Task 2: Create permissions utility

**Files:**
- Create: `dashboard/src/lib/permissions.ts`
- Create: `dashboard/src/lib/permissions.test.ts`

This is a pure utility — no React, no dependencies. It mirrors the role→permission map from `cmd/valinor/main.go`. The `usePermission` hook is also defined here.

**Step 1: Write the failing test first**

Create `dashboard/src/lib/permissions.test.ts`:

```typescript
import { describe, it, expect } from "vitest"
import { hasPermission } from "./permissions"

describe("hasPermission", () => {
  it("allows org_admin wildcard for any permission", () => {
    expect(hasPermission(["org_admin"], "agents:write")).toBe(true)
    expect(hasPermission(["org_admin"], "departments:write")).toBe(true)
    expect(hasPermission(["org_admin"], "anything:read")).toBe(true)
  })

  it("allows dept_head agents:write", () => {
    expect(hasPermission(["dept_head"], "agents:write")).toBe(true)
  })

  it("denies dept_head departments:write", () => {
    expect(hasPermission(["dept_head"], "departments:write")).toBe(false)
  })

  it("allows standard_user agents:read", () => {
    expect(hasPermission(["standard_user"], "agents:read")).toBe(true)
  })

  it("denies standard_user agents:write", () => {
    expect(hasPermission(["standard_user"], "agents:write")).toBe(false)
  })

  it("denies read_only agents:write", () => {
    expect(hasPermission(["read_only"], "agents:write")).toBe(false)
  })

  it("returns false for empty roles", () => {
    expect(hasPermission([], "agents:read")).toBe(false)
  })

  it("returns false for unknown role", () => {
    expect(hasPermission(["ghost"], "agents:read")).toBe(false)
  })

  it("allows when any role in array grants the permission", () => {
    expect(hasPermission(["read_only", "dept_head"], "agents:write")).toBe(true)
  })
})
```

**Step 2: Run test to verify it fails**

```bash
cd dashboard && npx vitest run src/lib/permissions.test.ts 2>&1 | tail -10
```

Expected: FAIL — `permissions` module not found.

**Step 3: Implement `permissions.ts`**

Create `dashboard/src/lib/permissions.ts`:

```typescript
import { useSession } from "next-auth/react"

// Mirrors cmd/valinor/main.go rbacEngine.RegisterRole() calls.
// Keep in sync with the backend whenever roles change.
const ROLE_PERMISSIONS: Record<string, string[]> = {
  org_admin: ["*"],
  dept_head: [
    "agents:read", "agents:write", "agents:message",
    "users:read", "users:write",
    "departments:read",
    "connectors:read", "connectors:write",
    "channels:links:read", "channels:links:write",
    "channels:messages:write",
    "channels:outbox:read", "channels:outbox:write",
    "channels:providers:read", "channels:providers:write",
  ],
  standard_user: [
    "agents:read", "agents:message",
    "channels:messages:write",
  ],
  read_only: [
    "agents:read",
  ],
}

/**
 * Pure permission check. Use this in server components or anywhere
 * you already have the roles array.
 */
export function hasPermission(roles: string[], permission: string): boolean {
  for (const role of roles) {
    const perms = ROLE_PERMISSIONS[role]
    if (!perms) continue
    if (perms.includes("*") || perms.includes(permission)) return true
  }
  return false
}

/**
 * React hook. Use this in client components.
 * Returns false while session is loading (safe default: deny).
 */
export function usePermission(permission: string): boolean {
  const { data: session } = useSession()
  const roles = session?.user?.roles ?? []
  return hasPermission(roles, permission)
}
```

**Step 4: Run test to verify it passes**

```bash
cd dashboard && npx vitest run src/lib/permissions.test.ts 2>&1 | tail -10
```

Expected: PASS, 9 tests.

**Step 5: Commit**

```bash
git add dashboard/src/lib/permissions.ts dashboard/src/lib/permissions.test.ts
git commit -m "feat(rbac): add permissions utility with hasPermission and usePermission"
```

---

## Task 3: Gate sidebar navigation items

**Files:**
- Modify: `dashboard/src/components/nav/sidebar.tsx`
- Modify: `dashboard/src/components/nav/mobile-sidebar.tsx` (same nav items — must be kept in sync)

**Step 1: Read both files**

```
Read: dashboard/src/components/nav/sidebar.tsx
Read: dashboard/src/components/nav/mobile-sidebar.tsx
```

**Step 2: Update sidebar to filter nav items by permission**

The sidebar currently builds `navItems` based on `isPlatformAdmin`. Add a permission filter to the tenant nav items.

In `sidebar.tsx`, import `usePermission`:
```typescript
import { usePermission } from "@/lib/permissions"
```

Replace the static `tenantAdminNav` array with a hook-filtered version. After the `isPlatformAdmin` check, add:

```typescript
const canReadUsers = usePermission("users:read")
const canReadDepts = usePermission("departments:read")
const canReadConnectors = usePermission("connectors:read")
```

Filter the tenant nav items:
```typescript
const tenantNavItems = allTenantNavItems.filter((item) => {
  if (item.href === "/users" || item.href === "/users/new") return canReadUsers
  if (item.href === "/departments") return canReadDepts
  if (item.href === "/rbac" || item.href === "/connectors" || item.href === "/channels" || item.href === "/audit") return canReadConnectors
  return true // Overview and Agents visible to everyone with a session
})

const navItems = isPlatformAdmin ? platformAdminNav : tenantNavItems
```

Apply the same pattern to `mobile-sidebar.tsx`.

**Step 3: Run the full test suite to confirm nothing broke**

```bash
cd dashboard && npx vitest run 2>&1 | tail -10
```

Expected: All tests pass.

**Step 4: Commit**

```bash
git add dashboard/src/components/nav/sidebar.tsx dashboard/src/components/nav/mobile-sidebar.tsx
git commit -m "feat(rbac): hide nav items user lacks permission to access"
```

---

## Task 4: Gate "Create" buttons on list pages

**Files:**
- Modify: `dashboard/src/app/(dashboard)/agents/page.tsx`
- Modify: `dashboard/src/app/(dashboard)/users/page.tsx`
- Modify: `dashboard/src/app/(dashboard)/departments/page.tsx`

These are **server components**. Use `auth()` + `hasPermission()` directly — no hooks needed.

**Step 1: Read all three files**

```
Read: dashboard/src/app/(dashboard)/agents/page.tsx
Read: dashboard/src/app/(dashboard)/users/page.tsx
Read: dashboard/src/app/(dashboard)/departments/page.tsx
```

**Step 2: Update agents page**

At the top of `AgentsPage`, get the session and check permission:

```typescript
import { auth } from "@/lib/auth"
import { hasPermission } from "@/lib/permissions"

export default async function AgentsPage() {
  const session = await auth()
  const canProvision = hasPermission(session?.user?.roles ?? [], "agents:write")

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>...</div>
        {canProvision && (
          <Link href="/agents/new" className="...">
            <Plus size={16} />
            Provision agent
          </Link>
        )}
      </div>
      <AgentGrid />
    </div>
  )
}
```

**Step 3: Update users page**

Same pattern, check `users:write`:
```typescript
const canCreateUser = hasPermission(session?.user?.roles ?? [], "users:write")
// conditionally render "Create user" link
```

**Step 4: Update departments page**

Same pattern, check `departments:write`:
```typescript
const canCreateDept = hasPermission(session?.user?.roles ?? [], "departments:write")
// conditionally render "Create department" link
```

Note: only `org_admin` (wildcard) has `departments:write`, so this button disappears for `dept_head` too.

**Step 5: Build to verify**

```bash
cd dashboard && npm run build 2>&1 | tail -5
```

Expected: Clean build.

**Step 6: Commit**

```bash
git add dashboard/src/app/(dashboard)/agents/page.tsx \
        dashboard/src/app/(dashboard)/users/page.tsx \
        dashboard/src/app/(dashboard)/departments/page.tsx
git commit -m "feat(rbac): hide create buttons for users without write permission"
```

---

## Task 5: Gate the "new" pages (forbidden gate)

**Files:**
- Modify: `dashboard/src/app/(dashboard)/agents/new/page.tsx`
- Modify: `dashboard/src/app/(dashboard)/users/new/page.tsx`
- Modify: `dashboard/src/app/(dashboard)/departments/new/page.tsx`

Direct URL access to `/agents/new` by a `standard_user` should show a clear "forbidden" message rather than an error after submit. These are server components — use `auth()` + `hasPermission()`.

**Step 1: Read the three "new" page files**

```
Read: dashboard/src/app/(dashboard)/agents/new/page.tsx
Read: dashboard/src/app/(dashboard)/users/new/page.tsx
Read: dashboard/src/app/(dashboard)/departments/new/page.tsx
```

**Step 2: Add a shared `ForbiddenMessage` inline component**

We don't need a separate file — just a small inline element. The pattern for each page:

```typescript
import { auth } from "@/lib/auth"
import { hasPermission } from "@/lib/permissions"

export default async function AgentsNewPage() {
  const session = await auth()
  if (!hasPermission(session?.user?.roles ?? [], "agents:write")) {
    return (
      <div className="rounded-xl border border-rose-200 bg-rose-50 p-6 max-w-lg">
        <h2 className="text-sm font-semibold text-rose-800">Permission denied</h2>
        <p className="mt-1 text-sm text-rose-700">
          You need the <span className="font-mono">agents:write</span> permission to provision agents.
        </p>
      </div>
    )
  }

  return (
    // ... existing page content ...
  )
}
```

Apply the same pattern:
- `/agents/new` → requires `agents:write`
- `/users/new` → requires `users:write`
- `/departments/new` → requires `departments:write`

**Step 3: Build to verify**

```bash
cd dashboard && npm run build 2>&1 | tail -5
```

Expected: Clean build.

**Step 4: Commit**

```bash
git add dashboard/src/app/(dashboard)/agents/new/page.tsx \
        dashboard/src/app/(dashboard)/users/new/page.tsx \
        dashboard/src/app/(dashboard)/departments/new/page.tsx
git commit -m "feat(rbac): show forbidden message on write pages for unauthorized users"
```

---

## Task 6: Gate Configure and Destroy on agent detail

**Files:**
- Modify: `dashboard/src/components/agents/agent-detail.tsx`

This is a client component. Use `usePermission()`.

**Step 1: Read the file**

```
Read: dashboard/src/components/agents/agent-detail.tsx
```

**Step 2: Import and use `usePermission`**

```typescript
import { usePermission } from "@/lib/permissions"

export function AgentDetail({ id }: { id: string }) {
  // ... existing hooks ...
  const canWrite = usePermission("agents:write")

  // ...
  // In the header buttons section, wrap both Configure and Destroy:
  {canWrite && (
    <button onClick={() => setEditing(!editing)} ...>
      <Gear size={14} />
      Configure
    </button>
  )}
  {canWrite && (
    !confirmDestroy ? (
      <button onClick={() => setConfirmDestroy(true)} ...>
        <Trash size={14} />
        Destroy
      </button>
    ) : (
      // confirm destroy buttons...
    )
  )}
```

**Step 3: Run tests**

```bash
cd dashboard && npx vitest run 2>&1 | tail -10
```

Expected: All tests pass.

**Step 4: Build**

```bash
cd dashboard && npm run build 2>&1 | tail -5
```

Expected: Clean build.

**Step 5: Commit**

```bash
git add dashboard/src/components/agents/agent-detail.tsx
git commit -m "feat(rbac): hide configure and destroy actions for users without agents:write"
```

---

## Task 7: Final verification

**Step 1: Run full test suite**

```bash
cd dashboard && npx vitest run 2>&1 | tail -20
```

Expected: All tests pass (including new permissions tests).

**Step 2: Full build**

```bash
cd dashboard && npm run build 2>&1 | tail -10
```

Expected: Clean build, no TypeScript errors, no lint warnings.

**Step 3: Manual smoke test — sign in as each role and verify**

```bash
# standard_user (glorfindel): should see Agents nav, no write buttons
curl -s http://localhost:8080/auth/dev/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"glorfindel@gondolin.fc"}' | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["user"]["display_name"], "roles:", json.loads(__import__("base64").b64decode(d["access_token"].split(".")[1]+"=="))["roles"])'

# org_admin (turgon): should see all nav items and all write buttons
curl -s http://localhost:8080/auth/dev/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"turgon@gondolin.fc"}' | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d["user"]["display_name"], "roles:", json.loads(__import__("base64").b64decode(d["access_token"].split(".")[1]+"=="))["roles"])'
```

Expected: Glorfindel has `["standard_user"]`, Turgon has `["org_admin"]`.

**Step 4: Use finishing-a-development-branch skill**

After all tasks complete and verified:
- REQUIRED SUB-SKILL: Use superpowers:finishing-a-development-branch
