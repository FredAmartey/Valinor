# Phase 9 Slice 4: RBAC UI Gating — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Surface the user's roles from the backend JWT into the NextAuth session and gate UI controls (nav links, Create buttons, Configure/Destroy buttons) so the interface matches what each user is allowed to do.

**Architecture:** Decode `roles` from the backend access token (JWT payload is public base64) during NextAuth sign-in and store it in the session. Provide a `PermissionProvider` React context that the dashboard layout mounts server-side, exposing a `useCan()` hook to all client components. Server components call `auth()` + `hasPermission()` directly. Platform admin (`isPlatformAdmin=true`) is a full bypass — no role check needed.

**Tech Stack:** Next.js 15 (App Router), NextAuth v5, React context, TypeScript, Vitest

---

## Background

The backend enforces RBAC on every endpoint. The four roles (mirroring `cmd/valinor/main.go`):

| Role | Permissions |
|---|---|
| `org_admin` | `*` (wildcard — everything) |
| `dept_head` | agents r/w/message, users r/w, departments:read, connectors r/w, channels r/w |
| `standard_user` | `agents:read`, `agents:message`, `channels:messages:write` |
| `read_only` | `agents:read` |

Dev user role assignments (from `scripts/seed_dev_roles.sql`):
- `turgon@gondolin.fc` → `org_admin` + `isPlatformAdmin=true`
- `ecthelion@gondolin.fc` → `dept_head`
- `glorfindel@gondolin.fc` → `standard_user`
- `maeglin@gondolin.fc` → `read_only`

---

## UX Rules

| Element | Behaviour if lacking permission |
|---|---|
| Sidebar: Users, Departments links | **Hidden** (requires `users:read`) |
| Sidebar: RBAC, Channels, Connectors, Audit links | **Hidden** (requires `connectors:read`) |
| "Provision agent" button / `/agents/new` page | **Hidden** / forbidden message (requires `agents:write`) |
| "Create user" button / `/users/new` page | **Hidden** / forbidden message (requires `users:write`) |
| "Create department" button / `/departments/new` page | **Hidden** / forbidden message (requires `departments:write`) |
| "Configure" button (agent detail) | **Disabled + tooltip** (requires `agents:write`) |
| "Destroy" button (agent detail) | **Disabled + tooltip** (requires `agents:write`) |

---

## Task 1: Add `roles` to NextAuth session

**Files:**
- Modify: `dashboard/src/lib/auth.ts`

The access token is a signed JWT: `header.payload.signature`. The payload is base64url-encoded JSON. The Go backend puts `"roles": ["org_admin"]` in the claims (see `internal/auth/token.go`).

**Step 1: Add `roles` to the type declarations**

In the `declare module "next-auth"` block, add `roles: string[]` to both `Session.user` and `User`:

```typescript
declare module "next-auth" {
  interface Session {
    accessToken: string
    user: {
      id: string
      email: string
      name: string
      tenantId: string | null
      isPlatformAdmin: boolean
      roles: string[]        // ← add
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
    roles: string[]          // ← add
  }
}
```

In the `declare module "@auth/core/jwt"` block, add `roles: string[]` to `JWT`:

```typescript
declare module "@auth/core/jwt" {
  interface JWT {
    accessToken: string
    refreshToken: string
    expiresAt: number
    userId: string
    tenantId: string | null
    isPlatformAdmin: boolean
    roles: string[]          // ← add
  }
}
```

**Step 2: Add a decode helper above `authConfig`**

Insert this function between the `declare module` blocks and `const VALINOR_API_URL`:

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

**Step 3: Extract roles in `authorize()`**

In the `authorize()` function, after `const data = await res.json()`, add:

```typescript
const roles = decodeJwtRoles(data.access_token)
```

Then add `roles` to the returned object:

```typescript
return {
  id: data.user.id,
  email: data.user.email,
  name: data.user.display_name ?? data.user.email,
  tenantId: data.user.tenant_id ?? null,
  isPlatformAdmin: data.user.is_platform_admin ?? false,
  accessToken: data.access_token,
  refreshToken: data.refresh_token,
  expiresIn: data.expires_in ?? 86400,
  roles,
}
```

**Step 4: Persist `roles` through the `jwt` callback**

In the `jwt` callback, inside the `if (user)` block (initial sign-in), add:

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
cd dashboard && npm run build 2>&1 | tail -10
```

Expected: Clean build, no TypeScript errors.

**Step 7: Commit**

```bash
git add dashboard/src/lib/auth.ts
git commit -m "feat(auth): surface roles from JWT in NextAuth session"
```

---

## Task 2: Create the permissions module (TDD)

**Files:**
- Create: `dashboard/src/lib/permissions.ts`
- Create: `dashboard/src/lib/permissions.test.ts`

`hasPermission()` is a pure function — no React, no dependencies. Tests run with Vitest.

**Step 1: Write the failing test**

Create `dashboard/src/lib/permissions.test.ts`:

```typescript
import { describe, it, expect } from "vitest"
import { hasPermission } from "./permissions"

describe("hasPermission", () => {
  it("allows org_admin wildcard for any permission", () => {
    expect(hasPermission(false, ["org_admin"], "agents:write")).toBe(true)
    expect(hasPermission(false, ["org_admin"], "departments:write")).toBe(true)
  })

  it("platform admin bypasses all checks", () => {
    expect(hasPermission(true, [], "anything:write")).toBe(true)
    expect(hasPermission(true, ["read_only"], "agents:write")).toBe(true)
  })

  it("allows dept_head agents:write", () => {
    expect(hasPermission(false, ["dept_head"], "agents:write")).toBe(true)
  })

  it("denies dept_head departments:write", () => {
    expect(hasPermission(false, ["dept_head"], "departments:write")).toBe(false)
  })

  it("allows standard_user agents:read", () => {
    expect(hasPermission(false, ["standard_user"], "agents:read")).toBe(true)
  })

  it("denies standard_user agents:write", () => {
    expect(hasPermission(false, ["standard_user"], "agents:write")).toBe(false)
  })

  it("denies read_only agents:write", () => {
    expect(hasPermission(false, ["read_only"], "agents:write")).toBe(false)
  })

  it("returns false for empty roles", () => {
    expect(hasPermission(false, [], "agents:read")).toBe(false)
  })

  it("returns false for unknown role", () => {
    expect(hasPermission(false, ["ghost"], "agents:read")).toBe(false)
  })

  it("union: allows when any role grants the permission", () => {
    expect(hasPermission(false, ["read_only", "dept_head"], "agents:write")).toBe(true)
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
// Mirrors cmd/valinor/main.go rbacEngine.RegisterRole() calls.
// Keep in sync with the backend when roles change.
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
 * Pure permission check. Safe to call in server components,
 * tests, and anywhere you already have the roles array.
 *
 * @param isPlatformAdmin - full bypass when true
 * @param roles - array of role names from the session
 * @param permission - exact permission string, e.g. "agents:write"
 */
export function hasPermission(
  isPlatformAdmin: boolean,
  roles: string[],
  permission: string,
): boolean {
  if (isPlatformAdmin) return true
  for (const role of roles) {
    const perms = ROLE_PERMISSIONS[role]
    if (!perms) continue
    if (perms.includes("*") || perms.includes(permission)) return true
  }
  return false
}
```

**Step 4: Run test to verify it passes**

```bash
cd dashboard && npx vitest run src/lib/permissions.test.ts 2>&1 | tail -10
```

Expected: PASS, 10 tests.

**Step 5: Commit**

```bash
git add dashboard/src/lib/permissions.ts dashboard/src/lib/permissions.test.ts
git commit -m "feat(rbac): add hasPermission utility with platform admin bypass"
```

---

## Task 3: Create `PermissionProvider` context + `useCan()` hook

**Files:**
- Create: `dashboard/src/components/providers/permission-provider.tsx`

This is a client component that wraps the dashboard and exposes `useCan()`. The dashboard layout (server component) passes `roles` and `isPlatformAdmin` as props.

**Step 1: Create the directory**

```bash
mkdir -p dashboard/src/components/providers
```

**Step 2: Create `permission-provider.tsx`**

```typescript
"use client"

import { createContext, useContext } from "react"
import { hasPermission } from "@/lib/permissions"

interface PermissionContextValue {
  can: (permission: string) => boolean
}

const PermissionContext = createContext<PermissionContextValue>({
  can: () => false,
})

interface PermissionProviderProps {
  isPlatformAdmin: boolean
  roles: string[]
  children: React.ReactNode
}

export function PermissionProvider({
  isPlatformAdmin,
  roles,
  children,
}: PermissionProviderProps) {
  function can(permission: string): boolean {
    return hasPermission(isPlatformAdmin, roles, permission)
  }

  return (
    <PermissionContext.Provider value={{ can }}>
      {children}
    </PermissionContext.Provider>
  )
}

/**
 * Use in any client component inside the dashboard layout.
 * Returns false while session data is unavailable (safe deny default).
 */
export function useCan(permission: string): boolean {
  const { can } = useContext(PermissionContext)
  return can(permission)
}
```

**Step 3: Commit**

```bash
git add dashboard/src/components/providers/permission-provider.tsx
git commit -m "feat(rbac): add PermissionProvider context and useCan hook"
```

---

## Task 4: Mount `PermissionProvider` in the dashboard layout

**Files:**
- Modify: `dashboard/src/app/(dashboard)/layout.tsx`

The layout is a server component. Make it async, call `auth()`, and wrap children in `PermissionProvider`.

**Step 1: Read the current layout**

The current content of `dashboard/src/app/(dashboard)/layout.tsx`:

```typescript
import { Sidebar } from "@/components/nav/sidebar"
import { TopBar } from "@/components/nav/top-bar"
import { MobileSidebar } from "@/components/nav/mobile-sidebar"

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-[100dvh]">
      ...
    </div>
  )
}
```

**Step 2: Update the layout**

Replace the entire file with:

```typescript
import { auth } from "@/lib/auth"
import { Sidebar } from "@/components/nav/sidebar"
import { TopBar } from "@/components/nav/top-bar"
import { MobileSidebar } from "@/components/nav/mobile-sidebar"
import { PermissionProvider } from "@/components/providers/permission-provider"

export default async function DashboardLayout({ children }: { children: React.ReactNode }) {
  const session = await auth()
  const roles = session?.user?.roles ?? []
  const isPlatformAdmin = session?.user?.isPlatformAdmin ?? false

  return (
    <PermissionProvider roles={roles} isPlatformAdmin={isPlatformAdmin}>
      <div className="flex min-h-[100dvh]">
        <div className="hidden lg:block">
          <Sidebar />
        </div>
        <div className="flex flex-1 flex-col">
          <header className="flex h-14 items-center gap-3 border-b border-zinc-200 bg-white px-4 lg:px-6">
            <MobileSidebar />
            <TopBar />
          </header>
          <main className="flex-1 px-4 py-6 lg:px-8">
            <div className="mx-auto max-w-[1400px]">{children}</div>
          </main>
        </div>
      </div>
    </PermissionProvider>
  )
}
```

**Step 3: Build to verify**

```bash
cd dashboard && npm run build 2>&1 | tail -10
```

Expected: Clean build.

**Step 4: Commit**

```bash
git add dashboard/src/app/(dashboard)/layout.tsx
git commit -m "feat(rbac): mount PermissionProvider in dashboard layout"
```

---

## Task 5: Gate sidebar nav items

**Files:**
- Modify: `dashboard/src/components/nav/sidebar.tsx`

The sidebar is already a client component. Replace `useSession()` with `useCan()`.

**Step 1: Read the current sidebar**

Current `tenantAdminNav` is a static array of 8 items. The sidebar currently checks `session?.user?.isPlatformAdmin` to choose which nav to show.

**Step 2: Update `sidebar.tsx`**

Replace the entire file with:

```typescript
"use client"

import { useCan } from "@/components/providers/permission-provider"
import { useSession } from "next-auth/react"
import { SidebarItem } from "./sidebar-item"
import {
  ChartBar,
  Buildings,
  Users,
  TreeStructure,
  Robot,
  ShieldCheck,
  ChatCircle,
  Plugs,
  ClockCounterClockwise,
} from "@phosphor-icons/react"

const platformAdminNav = [
  { href: "/", icon: <ChartBar size={20} />, label: "Overview" },
  { href: "/tenants", icon: <Buildings size={20} />, label: "Tenants" },
]

export function Sidebar() {
  const { data: session } = useSession()
  const isPlatformAdmin = session?.user?.isPlatformAdmin ?? false

  const canReadUsers = useCan("users:read")
  const canReadConnectors = useCan("connectors:read")

  const tenantAdminNav = [
    { href: "/", icon: <ChartBar size={20} />, label: "Overview" },
    ...(canReadUsers ? [{ href: "/users", icon: <Users size={20} />, label: "Users" }] : []),
    ...(canReadUsers ? [{ href: "/departments", icon: <TreeStructure size={20} />, label: "Departments" }] : []),
    { href: "/agents", icon: <Robot size={20} />, label: "Agents" },
    ...(canReadConnectors ? [{ href: "/rbac", icon: <ShieldCheck size={20} />, label: "RBAC" }] : []),
    ...(canReadConnectors ? [{ href: "/channels", icon: <ChatCircle size={20} />, label: "Channels" }] : []),
    ...(canReadConnectors ? [{ href: "/connectors", icon: <Plugs size={20} />, label: "Connectors" }] : []),
    ...(canReadConnectors ? [{ href: "/audit", icon: <ClockCounterClockwise size={20} />, label: "Audit Log" }] : []),
  ]

  const navItems = isPlatformAdmin ? platformAdminNav : tenantAdminNav

  return (
    <aside className="flex h-full w-60 flex-col border-r border-zinc-200 bg-white">
      <div className="flex h-14 items-center border-b border-zinc-200 px-4">
        <span className="text-lg font-semibold tracking-tight text-zinc-900">Valinor</span>
      </div>
      <nav className="flex flex-1 flex-col gap-1 p-3">
        {navItems.map((item) => (
          <SidebarItem key={item.href} {...item} />
        ))}
      </nav>
    </aside>
  )
}
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
git add dashboard/src/components/nav/sidebar.tsx
git commit -m "feat(rbac): hide nav items user lacks permission to access"
```

---

## Task 6: Gate "Create" buttons on list pages

**Files:**
- Modify: `dashboard/src/app/(dashboard)/agents/page.tsx`
- Modify: `dashboard/src/app/(dashboard)/users/page.tsx`
- Modify: `dashboard/src/app/(dashboard)/departments/page.tsx`

These are **server components**. Use `auth()` + `hasPermission()` directly.

**Step 1: Update `agents/page.tsx`**

```typescript
import Link from "next/link"
import { auth } from "@/lib/auth"
import { hasPermission } from "@/lib/permissions"
import { AgentGrid } from "@/components/agents/agent-grid"
import { Plus } from "@phosphor-icons/react/dist/ssr"

export default async function AgentsPage() {
  const session = await auth()
  const canProvision = hasPermission(
    session?.user?.isPlatformAdmin ?? false,
    session?.user?.roles ?? [],
    "agents:write",
  )

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">Agents</h1>
          <p className="mt-1 text-sm text-zinc-500">Manage AI agent instances.</p>
        </div>
        {canProvision && (
          <Link
            href="/agents/new"
            className="flex items-center gap-2 rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-zinc-800 active:scale-[0.98]"
          >
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

**Step 2: Update `users/page.tsx`**

```typescript
import Link from "next/link"
import { auth } from "@/lib/auth"
import { hasPermission } from "@/lib/permissions"
import { UserTable } from "@/components/users/user-table"
import { Plus } from "@phosphor-icons/react/dist/ssr"

export default async function UsersPage() {
  const session = await auth()
  const canCreate = hasPermission(
    session?.user?.isPlatformAdmin ?? false,
    session?.user?.roles ?? [],
    "users:write",
  )

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">Users</h1>
          <p className="mt-1 text-sm text-zinc-500">Manage users in your organization.</p>
        </div>
        {canCreate && (
          <Link
            href="/users/new"
            className="flex items-center gap-2 rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-zinc-800 active:scale-[0.98]"
          >
            <Plus size={16} />
            Create user
          </Link>
        )}
      </div>
      <UserTable />
    </div>
  )
}
```

**Step 3: Update `departments/page.tsx`**

```typescript
import Link from "next/link"
import { auth } from "@/lib/auth"
import { hasPermission } from "@/lib/permissions"
import { DepartmentTable } from "@/components/departments/department-table"
import { Plus } from "@phosphor-icons/react/dist/ssr"

export default async function DepartmentsPage() {
  const session = await auth()
  const canCreate = hasPermission(
    session?.user?.isPlatformAdmin ?? false,
    session?.user?.roles ?? [],
    "departments:write",
  )

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">Departments</h1>
          <p className="mt-1 text-sm text-zinc-500">Organize your team into departments.</p>
        </div>
        {canCreate && (
          <Link
            href="/departments/new"
            className="flex items-center gap-2 rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-zinc-800 active:scale-[0.98]"
          >
            <Plus size={16} />
            Create department
          </Link>
        )}
      </div>
      <DepartmentTable />
    </div>
  )
}
```

Note: `departments:write` is only granted to `org_admin` (wildcard). `dept_head` has `departments:read` but not `departments:write`. So `dept_head` won't see "Create department" — this is intentional.

**Step 4: Build to verify**

```bash
cd dashboard && npm run build 2>&1 | tail -5
```

Expected: Clean build.

**Step 5: Commit**

```bash
git add dashboard/src/app/(dashboard)/agents/page.tsx \
        dashboard/src/app/(dashboard)/users/page.tsx \
        dashboard/src/app/(dashboard)/departments/page.tsx
git commit -m "feat(rbac): hide create buttons for users without write permission"
```

---

## Task 7: Gate the "new" pages (forbidden gate)

**Files:**
- Modify: `dashboard/src/app/(dashboard)/agents/new/page.tsx`
- Modify: `dashboard/src/app/(dashboard)/users/new/page.tsx`
- Modify: `dashboard/src/app/(dashboard)/departments/new/page.tsx`

Direct URL access to `/agents/new` by `standard_user` should show a clear forbidden message rather than a confusing 403 after submit.

**Step 1: Update `agents/new/page.tsx`**

```typescript
import { auth } from "@/lib/auth"
import { hasPermission } from "@/lib/permissions"
import { ProvisionAgentForm } from "@/components/agents/provision-agent-form"

export default async function NewAgentPage() {
  const session = await auth()
  if (!hasPermission(session?.user?.isPlatformAdmin ?? false, session?.user?.roles ?? [], "agents:write")) {
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
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">Provision Agent</h1>
        <p className="mt-1 text-sm text-zinc-500">Start a new AI agent instance.</p>
      </div>
      <ProvisionAgentForm />
    </div>
  )
}
```

**Step 2: Update `users/new/page.tsx`**

Read the file first, then add the same guard at the top:

```typescript
const session = await auth()
if (!hasPermission(session?.user?.isPlatformAdmin ?? false, session?.user?.roles ?? [], "users:write")) {
  return (
    <div className="rounded-xl border border-rose-200 bg-rose-50 p-6 max-w-lg">
      <h2 className="text-sm font-semibold text-rose-800">Permission denied</h2>
      <p className="mt-1 text-sm text-rose-700">
        You need the <span className="font-mono">users:write</span> permission to create users.
      </p>
    </div>
  )
}
```

**Step 3: Update `departments/new/page.tsx`**

Read the file first, then add the same guard at the top with `departments:write`.

**Step 4: Build to verify**

```bash
cd dashboard && npm run build 2>&1 | tail -5
```

Expected: Clean build.

**Step 5: Commit**

```bash
git add dashboard/src/app/(dashboard)/agents/new/page.tsx \
        dashboard/src/app/(dashboard)/users/new/page.tsx \
        dashboard/src/app/(dashboard)/departments/new/page.tsx
git commit -m "feat(rbac): show forbidden message on write pages for unauthorized users"
```

---

## Task 8: Gate Configure and Destroy on agent detail

**Files:**
- Modify: `dashboard/src/components/agents/agent-detail.tsx`

This is a client component. Use `useCan()`. Per the UX spec: both Configure and Destroy show **disabled + native tooltip** when `!canWrite` (not hidden — users should know the action exists but is locked).

**Step 1: Add `useCan` import and check**

At the top of `agent-detail.tsx`, add:

```typescript
import { useCan } from "@/components/providers/permission-provider"
```

Inside the `AgentDetail` function, after existing hooks, add:

```typescript
const canWrite = useCan("agents:write")
```

**Step 2: Replace the header buttons section**

Find the `<div className="flex gap-2">` block containing Configure and Destroy buttons (lines 74–107 of the current file). Replace it with:

```typescript
<div className="flex gap-2">
  <span
    title={!canWrite ? "You don't have permission to do this." : undefined}
    className={!canWrite ? "cursor-not-allowed" : undefined}
  >
    <button
      onClick={() => setEditing(!editing)}
      disabled={!canWrite}
      className="flex items-center gap-1.5 rounded-lg border border-zinc-200 px-3 py-1.5 text-sm font-medium text-zinc-700 hover:bg-zinc-50 transition-colors active:scale-[0.98] disabled:opacity-40 disabled:cursor-not-allowed disabled:pointer-events-none"
    >
      <Gear size={14} />
      Configure
    </button>
  </span>
  {!confirmDestroy ? (
    <span
      title={!canWrite ? "You don't have permission to do this." : undefined}
      className={!canWrite ? "cursor-not-allowed" : undefined}
    >
      <button
        onClick={() => setConfirmDestroy(true)}
        disabled={!canWrite}
        className="flex items-center gap-1.5 rounded-lg border border-rose-200 px-3 py-1.5 text-sm font-medium text-rose-600 hover:bg-rose-50 transition-colors active:scale-[0.98] disabled:opacity-40 disabled:cursor-not-allowed disabled:pointer-events-none"
      >
        <Trash size={14} />
        Destroy
      </button>
    </span>
  ) : (
    <div className="flex items-center gap-2">
      <button
        onClick={handleDestroy}
        disabled={destroyMutation.isPending}
        className="rounded-lg bg-rose-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-rose-700 active:scale-[0.98] disabled:opacity-50"
      >
        {destroyMutation.isPending ? "Destroying..." : "Confirm destroy"}
      </button>
      <button
        onClick={() => setConfirmDestroy(false)}
        className="text-sm text-zinc-500 hover:text-zinc-700"
      >
        Cancel
      </button>
    </div>
  )}
</div>
```

Note: The `<span title="...">` wrapper is needed because `disabled` buttons do not fire mouse events in all browsers, so a native `title` tooltip won't show on hover. The wrapper span catches the hover and shows the tooltip.

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
git commit -m "feat(rbac): disable configure and destroy for users without agents:write"
```

---

## Task 9: Final verification

**Step 1: Run full test suite**

```bash
cd dashboard && npx vitest run 2>&1 | tail -20
```

Expected: All tests pass, including the 10 `hasPermission` tests.

**Step 2: Full build**

```bash
cd dashboard && npm run build 2>&1 | tail -10
```

Expected: Clean build, no TypeScript errors.

**Step 3: Manual smoke test — verify JWT roles via curl**

```bash
# standard_user (glorfindel)
curl -s http://localhost:8080/auth/dev/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"glorfindel@gondolin.fc"}' \
  | python3 -c 'import sys,json,base64; d=json.load(sys.stdin); p=d["access_token"].split(".")[1]; p+="=="*(4-len(p)%4%4); print(d["user"]["display_name"], "roles:", json.loads(base64.urlsafe_b64decode(p))["roles"])'

# org_admin (turgon)
curl -s http://localhost:8080/auth/dev/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"turgon@gondolin.fc"}' \
  | python3 -c 'import sys,json,base64; d=json.load(sys.stdin); p=d["access_token"].split(".")[1]; p+="=="*(4-len(p)%4%4); print(d["user"]["display_name"], "roles:", json.loads(base64.urlsafe_b64decode(p))["roles"])'
```

Expected: Glorfindel has `["standard_user"]`, Turgon has `["org_admin"]`.

**Step 4: Acceptance criteria checklist**

Sign in as each dev user and verify:

- `glorfindel` (standard_user): No Users/Departments/RBAC/Channels/Connectors/Audit nav links. No "Provision agent" button. Configure + Destroy buttons visible but greyed out with tooltip on hover.
- `ecthelion` (dept_head): Users + Departments nav visible. Agents nav visible with "Provision agent" button. No "Create department" button. Configure + Destroy active.
- `turgon` (org_admin + isPlatformAdmin): All controls active. Sees Tenants nav (platform admin view).
- `maeglin` (read_only): Same nav as standard_user. Configure + Destroy disabled.

**Step 5: Use finishing-a-development-branch skill**

REQUIRED SUB-SKILL: Use superpowers:finishing-a-development-branch
