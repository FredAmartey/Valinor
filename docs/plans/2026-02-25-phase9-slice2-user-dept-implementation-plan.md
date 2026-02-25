# Phase 9 Slice 2: User & Department Management — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add User Management and Department Management views to the Valinor admin dashboard with inline role assignment.

**Architecture:** Extends the existing Next.js 15 dashboard (`dashboard/`) with new route groups, components, and TanStack Query hooks. Server Components for initial data, `"use client"` leaves for interactive sections. All data from the existing Go API — no backend changes.

**Tech Stack:** Next.js 15 (App Router), TypeScript, Tailwind CSS v4, shadcn/ui, TanStack Query v5, @phosphor-icons/react, Vitest + RTL

**Skills to follow during implementation:**
- `design-taste-frontend` — UI engineering rules (DESIGN_VARIANCE: 8, MOTION_INTENSITY: 6, VISUAL_DENSITY: 4)
- `vercel-react-best-practices` — React/Next.js performance rules

**Design doc:** `docs/plans/2026-02-25-phase9-slice2-user-dept-design.md`

**Reference patterns:** All patterns established in Slice 1 (`dashboard/src/`) — see `components/tenants/`, `lib/queries/tenants.ts`, `app/(dashboard)/tenants/` for the exact conventions to follow.

---

## Task 1: Add New Types

**Files:**
- Modify: `dashboard/src/lib/types.ts`

**Step 1: Add Role, UserRole, and request types**

Append to `dashboard/src/lib/types.ts`:

```typescript
// Role types — matches Go internal/tenant/role_handler.go responses
export interface Role {
  id: string
  tenant_id: string
  name: string
  permissions: string[]
  is_system: boolean
  created_at: string
}

export interface UserRole {
  user_id: string
  role_id: string
  role_name: string
  scope_type: "org" | "department"
  scope_id: string
}

export interface CreateUserRequest {
  email: string
  display_name?: string
}

export interface CreateDepartmentRequest {
  name: string
  parent_id?: string
}

export interface AssignRoleRequest {
  role_id: string
  scope_type: "org" | "department"
  scope_id: string
}
```

**Step 2: Verify types compile**

```bash
cd dashboard && npx tsc --noEmit
```

Expected: No errors.

**Step 3: Commit**

```bash
git add src/lib/types.ts
git commit -m "feat(dashboard): add Role, UserRole, and request types for Slice 2"
```

---

## Task 2: User Query Hooks

**Files:**
- Create: `dashboard/src/lib/queries/users.ts`
- Create: `dashboard/src/lib/queries/users.test.ts`

**Step 1: Write the failing test**

Create `dashboard/src/lib/queries/users.test.ts`:

```typescript
import { describe, it, expect, vi } from "vitest"

vi.mock("@/lib/api-client", () => ({
  apiClient: vi.fn(),
}))

describe("user query functions", () => {
  it("fetchUsers calls correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce([])

    const { fetchUsers } = await import("./users")
    await fetchUsers("test-token")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/users",
      "test-token",
      undefined,
    )
  })

  it("fetchUser calls correct endpoint with ID", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ id: "u-1", email: "a@b.com" })

    const { fetchUser } = await import("./users")
    await fetchUser("test-token", "u-1")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/users/u-1",
      "test-token",
      undefined,
    )
  })

  it("createUser posts to correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ id: "u-2", email: "new@b.com" })

    const { createUser } = await import("./users")
    await createUser("test-token", { email: "new@b.com", display_name: "New User" })

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/users",
      "test-token",
      {
        method: "POST",
        body: JSON.stringify({ email: "new@b.com", display_name: "New User" }),
      },
    )
  })

  it("addUserToDepartment posts to correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ status: "ok" })

    const { addUserToDepartment } = await import("./users")
    await addUserToDepartment("test-token", "u-1", "d-1")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/users/u-1/departments",
      "test-token",
      {
        method: "POST",
        body: JSON.stringify({ department_id: "d-1" }),
      },
    )
  })

  it("removeUserFromDepartment deletes correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ status: "ok" })

    const { removeUserFromDepartment } = await import("./users")
    await removeUserFromDepartment("test-token", "u-1", "d-1")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/users/u-1/departments/d-1",
      "test-token",
      { method: "DELETE" },
    )
  })
})
```

**Step 2: Run test to verify it fails**

```bash
cd dashboard && npx vitest run src/lib/queries/users.test.ts
```

Expected: FAIL — module not found.

**Step 3: Write implementation**

Create `dashboard/src/lib/queries/users.ts`:

```typescript
"use client"

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { useSession } from "next-auth/react"
import { apiClient } from "@/lib/api-client"
import type { User, CreateUserRequest } from "@/lib/types"

export const userKeys = {
  all: ["users"] as const,
  list: () => [...userKeys.all, "list"] as const,
  detail: (id: string) => [...userKeys.all, "detail", id] as const,
}

export async function fetchUsers(
  accessToken: string,
  params?: Record<string, string>,
): Promise<User[]> {
  return apiClient<User[]>("/api/v1/users", accessToken, params ? { params } : undefined)
}

export async function fetchUser(
  accessToken: string,
  id: string,
): Promise<User> {
  return apiClient<User>(`/api/v1/users/${id}`, accessToken, undefined)
}

export async function createUser(
  accessToken: string,
  data: CreateUserRequest,
): Promise<User> {
  return apiClient<User>("/api/v1/users", accessToken, {
    method: "POST",
    body: JSON.stringify(data),
  })
}

export async function addUserToDepartment(
  accessToken: string,
  userId: string,
  departmentId: string,
): Promise<{ status: string }> {
  return apiClient<{ status: string }>(`/api/v1/users/${userId}/departments`, accessToken, {
    method: "POST",
    body: JSON.stringify({ department_id: departmentId }),
  })
}

export async function removeUserFromDepartment(
  accessToken: string,
  userId: string,
  departmentId: string,
): Promise<{ status: string }> {
  return apiClient<{ status: string }>(`/api/v1/users/${userId}/departments/${departmentId}`, accessToken, {
    method: "DELETE",
  })
}

// React hooks
export function useUsersQuery() {
  const { data: session } = useSession()
  return useQuery({
    queryKey: userKeys.list(),
    queryFn: () => fetchUsers(session!.accessToken),
    enabled: !!session?.accessToken,
    staleTime: 30_000,
  })
}

export function useUserQuery(id: string) {
  const { data: session } = useSession()
  return useQuery({
    queryKey: userKeys.detail(id),
    queryFn: () => fetchUser(session!.accessToken, id),
    enabled: !!session?.accessToken && !!id,
  })
}

export function useCreateUserMutation() {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: CreateUserRequest) => createUser(session!.accessToken, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: userKeys.all })
    },
  })
}

export function useAddUserToDepartmentMutation(userId: string) {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (departmentId: string) =>
      addUserToDepartment(session!.accessToken, userId, departmentId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: userKeys.detail(userId) })
    },
  })
}

export function useRemoveUserFromDepartmentMutation(userId: string) {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (departmentId: string) =>
      removeUserFromDepartment(session!.accessToken, userId, departmentId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: userKeys.detail(userId) })
    },
  })
}
```

**Step 4: Run tests to verify they pass**

```bash
cd dashboard && npx vitest run src/lib/queries/users.test.ts
```

Expected: PASS.

**Step 5: Commit**

```bash
git add src/lib/queries/users.ts src/lib/queries/users.test.ts
git commit -m "feat(dashboard): add TanStack Query hooks for user CRUD and department membership"
```

---

## Task 3: Department Query Hooks

**Files:**
- Create: `dashboard/src/lib/queries/departments.ts`
- Create: `dashboard/src/lib/queries/departments.test.ts`

**Step 1: Write the failing test**

Create `dashboard/src/lib/queries/departments.test.ts`:

```typescript
import { describe, it, expect, vi } from "vitest"

vi.mock("@/lib/api-client", () => ({
  apiClient: vi.fn(),
}))

describe("department query functions", () => {
  it("fetchDepartments calls correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce([])

    const { fetchDepartments } = await import("./departments")
    await fetchDepartments("test-token")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/departments",
      "test-token",
      undefined,
    )
  })

  it("fetchDepartment calls correct endpoint with ID", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ id: "d-1", name: "Engineering" })

    const { fetchDepartment } = await import("./departments")
    await fetchDepartment("test-token", "d-1")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/departments/d-1",
      "test-token",
      undefined,
    )
  })

  it("createDepartment posts to correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ id: "d-2", name: "Scouting" })

    const { createDepartment } = await import("./departments")
    await createDepartment("test-token", { name: "Scouting", parent_id: "d-1" })

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/departments",
      "test-token",
      {
        method: "POST",
        body: JSON.stringify({ name: "Scouting", parent_id: "d-1" }),
      },
    )
  })
})
```

**Step 2: Run test to verify it fails**

```bash
cd dashboard && npx vitest run src/lib/queries/departments.test.ts
```

Expected: FAIL.

**Step 3: Write implementation**

Create `dashboard/src/lib/queries/departments.ts`:

```typescript
"use client"

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { useSession } from "next-auth/react"
import { apiClient } from "@/lib/api-client"
import type { Department, CreateDepartmentRequest } from "@/lib/types"

export const departmentKeys = {
  all: ["departments"] as const,
  list: () => [...departmentKeys.all, "list"] as const,
  detail: (id: string) => [...departmentKeys.all, "detail", id] as const,
}

export async function fetchDepartments(
  accessToken: string,
): Promise<Department[]> {
  return apiClient<Department[]>("/api/v1/departments", accessToken, undefined)
}

export async function fetchDepartment(
  accessToken: string,
  id: string,
): Promise<Department> {
  return apiClient<Department>(`/api/v1/departments/${id}`, accessToken, undefined)
}

export async function createDepartment(
  accessToken: string,
  data: CreateDepartmentRequest,
): Promise<Department> {
  return apiClient<Department>("/api/v1/departments", accessToken, {
    method: "POST",
    body: JSON.stringify(data),
  })
}

export function useDepartmentsQuery() {
  const { data: session } = useSession()
  return useQuery({
    queryKey: departmentKeys.list(),
    queryFn: () => fetchDepartments(session!.accessToken),
    enabled: !!session?.accessToken,
    staleTime: 30_000,
  })
}

export function useDepartmentQuery(id: string) {
  const { data: session } = useSession()
  return useQuery({
    queryKey: departmentKeys.detail(id),
    queryFn: () => fetchDepartment(session!.accessToken, id),
    enabled: !!session?.accessToken && !!id,
  })
}

export function useCreateDepartmentMutation() {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: CreateDepartmentRequest) =>
      createDepartment(session!.accessToken, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: departmentKeys.all })
    },
  })
}
```

**Step 4: Run tests to verify they pass**

```bash
cd dashboard && npx vitest run src/lib/queries/departments.test.ts
```

Expected: PASS.

**Step 5: Commit**

```bash
git add src/lib/queries/departments.ts src/lib/queries/departments.test.ts
git commit -m "feat(dashboard): add TanStack Query hooks for department CRUD"
```

---

## Task 4: Role Query Hooks

**Files:**
- Create: `dashboard/src/lib/queries/roles.ts`
- Create: `dashboard/src/lib/queries/roles.test.ts`

**Step 1: Write the failing test**

Create `dashboard/src/lib/queries/roles.test.ts`:

```typescript
import { describe, it, expect, vi } from "vitest"

vi.mock("@/lib/api-client", () => ({
  apiClient: vi.fn(),
}))

describe("role query functions", () => {
  it("fetchRoles calls correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce([])

    const { fetchRoles } = await import("./roles")
    await fetchRoles("test-token")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/roles",
      "test-token",
      undefined,
    )
  })

  it("fetchUserRoles calls correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce([])

    const { fetchUserRoles } = await import("./roles")
    await fetchUserRoles("test-token", "u-1")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/users/u-1/roles",
      "test-token",
      undefined,
    )
  })

  it("assignRole posts to correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ status: "ok" })

    const { assignRole } = await import("./roles")
    await assignRole("test-token", "u-1", {
      role_id: "r-1",
      scope_type: "org",
      scope_id: "t-1",
    })

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/users/u-1/roles",
      "test-token",
      {
        method: "POST",
        body: JSON.stringify({ role_id: "r-1", scope_type: "org", scope_id: "t-1" }),
      },
    )
  })

  it("removeRole deletes with correct body", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ status: "ok" })

    const { removeRole } = await import("./roles")
    await removeRole("test-token", "u-1", {
      role_id: "r-1",
      scope_type: "department",
      scope_id: "d-1",
    })

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/users/u-1/roles",
      "test-token",
      {
        method: "DELETE",
        body: JSON.stringify({ role_id: "r-1", scope_type: "department", scope_id: "d-1" }),
      },
    )
  })
})
```

**Step 2: Run test to verify it fails**

```bash
cd dashboard && npx vitest run src/lib/queries/roles.test.ts
```

Expected: FAIL.

**Step 3: Write implementation**

Create `dashboard/src/lib/queries/roles.ts`:

```typescript
"use client"

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { useSession } from "next-auth/react"
import { apiClient } from "@/lib/api-client"
import { userKeys } from "./users"
import type { Role, UserRole, AssignRoleRequest } from "@/lib/types"

export const roleKeys = {
  all: ["roles"] as const,
  list: () => [...roleKeys.all, "list"] as const,
  userRoles: (userId: string) => ["userRoles", userId] as const,
}

export async function fetchRoles(accessToken: string): Promise<Role[]> {
  return apiClient<Role[]>("/api/v1/roles", accessToken, undefined)
}

export async function fetchUserRoles(
  accessToken: string,
  userId: string,
): Promise<UserRole[]> {
  return apiClient<UserRole[]>(`/api/v1/users/${userId}/roles`, accessToken, undefined)
}

export async function assignRole(
  accessToken: string,
  userId: string,
  data: AssignRoleRequest,
): Promise<{ status: string }> {
  return apiClient<{ status: string }>(`/api/v1/users/${userId}/roles`, accessToken, {
    method: "POST",
    body: JSON.stringify(data),
  })
}

export async function removeRole(
  accessToken: string,
  userId: string,
  data: AssignRoleRequest,
): Promise<{ status: string }> {
  return apiClient<{ status: string }>(`/api/v1/users/${userId}/roles`, accessToken, {
    method: "DELETE",
    body: JSON.stringify(data),
  })
}

export function useRolesQuery() {
  const { data: session } = useSession()
  return useQuery({
    queryKey: roleKeys.list(),
    queryFn: () => fetchRoles(session!.accessToken),
    enabled: !!session?.accessToken,
    staleTime: 60_000,
  })
}

export function useUserRolesQuery(userId: string) {
  const { data: session } = useSession()
  return useQuery({
    queryKey: roleKeys.userRoles(userId),
    queryFn: () => fetchUserRoles(session!.accessToken, userId),
    enabled: !!session?.accessToken && !!userId,
  })
}

export function useAssignRoleMutation(userId: string) {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: AssignRoleRequest) =>
      assignRole(session!.accessToken, userId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: roleKeys.userRoles(userId) })
      queryClient.invalidateQueries({ queryKey: userKeys.detail(userId) })
    },
  })
}

export function useRemoveRoleMutation(userId: string) {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: AssignRoleRequest) =>
      removeRole(session!.accessToken, userId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: roleKeys.userRoles(userId) })
      queryClient.invalidateQueries({ queryKey: userKeys.detail(userId) })
    },
  })
}
```

**Step 4: Run tests to verify they pass**

```bash
cd dashboard && npx vitest run src/lib/queries/roles.test.ts
```

Expected: PASS.

**Step 5: Commit**

```bash
git add src/lib/queries/roles.ts src/lib/queries/roles.test.ts
git commit -m "feat(dashboard): add TanStack Query hooks for role listing and assignment"
```

---

## Task 5: User List Page & Components

**Files:**
- Create: `dashboard/src/components/users/user-table.tsx`
- Create: `dashboard/src/components/users/user-status-badge.tsx`
- Create: `dashboard/src/app/(dashboard)/users/page.tsx`
- Create: `dashboard/src/app/(dashboard)/users/loading.tsx`

**Step 1: Create UserStatusBadge**

Create `dashboard/src/components/users/user-status-badge.tsx`:

```tsx
import { Badge } from "@/components/ui/badge"

const statusStyles = {
  active: "bg-emerald-50 text-emerald-700 border-emerald-200",
  suspended: "bg-amber-50 text-amber-700 border-amber-200",
} as const

export function UserStatusBadge({ status }: { status: "active" | "suspended" }) {
  return (
    <Badge variant="outline" className={statusStyles[status]}>
      {status}
    </Badge>
  )
}
```

**Step 2: Create UserTable**

Create `dashboard/src/components/users/user-table.tsx`:

```tsx
"use client"

import { useState } from "react"
import Link from "next/link"
import { useUsersQuery } from "@/lib/queries/users"
import { UserStatusBadge } from "./user-status-badge"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { Badge } from "@/components/ui/badge"
import { MagnifyingGlass } from "@phosphor-icons/react"
import { formatDate } from "@/lib/format"

export function UserTable() {
  const { data: users, isLoading, isError } = useUsersQuery()
  const [search, setSearch] = useState("")

  const filtered = users?.filter(
    (u) =>
      u.email.toLowerCase().includes(search.toLowerCase()) ||
      u.display_name.toLowerCase().includes(search.toLowerCase()),
  )

  if (isLoading) {
    return (
      <div className="space-y-3">
        <Skeleton className="h-10 w-64" />
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-14 w-full" />
        ))}
      </div>
    )
  }

  if (isError) {
    return (
      <div className="rounded-xl border border-rose-200 bg-rose-50 p-4">
        <p className="text-sm text-rose-700">Failed to load users. Please try again.</p>
      </div>
    )
  }

  if (!users || users.length === 0) {
    return (
      <div className="py-12 text-center">
        <p className="text-sm font-medium text-zinc-900">No users yet</p>
        <p className="mt-1 text-sm text-zinc-500">Create your first user to get started.</p>
        <Link
          href="/users/new"
          className="mt-4 inline-block rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800 transition-colors active:scale-[0.98]"
        >
          Create user
        </Link>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="relative max-w-sm">
        <MagnifyingGlass size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-400" />
        <Input
          placeholder="Search users..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="pl-9"
        />
      </div>

      <div className="rounded-xl border border-zinc-200 bg-white">
        <div className="grid grid-cols-[2fr_2fr_1fr_1fr] gap-4 border-b border-zinc-100 px-4 py-3 text-xs font-medium uppercase tracking-wider text-zinc-500">
          <span>Name</span>
          <span>Email</span>
          <span>Status</span>
          <span>Created</span>
        </div>
        <div className="divide-y divide-zinc-100">
          {filtered?.map((user) => (
            <Link
              key={user.id}
              href={`/users/${user.id}`}
              className="grid grid-cols-[2fr_2fr_1fr_1fr] gap-4 px-4 py-3 text-sm transition-colors hover:bg-zinc-50"
            >
              <span className="font-medium text-zinc-900">
                {user.display_name || user.email.split("@")[0]}
              </span>
              <span className="text-zinc-500">{user.email}</span>
              <UserStatusBadge status={user.status as "active" | "suspended"} />
              <span className="text-zinc-500">{formatDate(user.created_at)}</span>
            </Link>
          ))}
        </div>
      </div>
    </div>
  )
}
```

**Step 3: Create user list page**

Create `dashboard/src/app/(dashboard)/users/page.tsx`:

```tsx
import Link from "next/link"
import { UserTable } from "@/components/users/user-table"
import { Plus } from "@phosphor-icons/react/dist/ssr"

export default function UsersPage() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">Users</h1>
          <p className="mt-1 text-sm text-zinc-500">Manage users in your organization.</p>
        </div>
        <Link
          href="/users/new"
          className="flex items-center gap-2 rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-zinc-800 active:scale-[0.98]"
        >
          <Plus size={16} />
          Create user
        </Link>
      </div>
      <UserTable />
    </div>
  )
}
```

**Step 4: Create loading skeleton**

Create `dashboard/src/app/(dashboard)/users/loading.tsx`:

```tsx
import { Skeleton } from "@/components/ui/skeleton"

export default function UsersLoading() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="space-y-2">
          <Skeleton className="h-8 w-24" />
          <Skeleton className="h-4 w-56" />
        </div>
        <Skeleton className="h-10 w-32 rounded-lg" />
      </div>
      <Skeleton className="h-10 w-64" />
      <div className="space-y-2">
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-14 w-full rounded-xl" />
        ))}
      </div>
    </div>
  )
}
```

**Step 5: Verify build**

```bash
cd dashboard && npm run build
```

Expected: Build succeeds.

**Step 6: Commit**

```bash
git add src/components/users/ src/app/\(dashboard\)/users/
git commit -m "feat(dashboard): add user list page with search and status badges"
```

---

## Task 6: User Detail Page with Department & Role Sections

**Files:**
- Create: `dashboard/src/components/users/user-detail.tsx`
- Create: `dashboard/src/components/users/user-departments-section.tsx`
- Create: `dashboard/src/components/users/user-roles-section.tsx`
- Create: `dashboard/src/app/(dashboard)/users/[id]/page.tsx`

**Step 1: Create UserDepartmentsSection**

Create `dashboard/src/components/users/user-departments-section.tsx`:

```tsx
"use client"

import { useState } from "react"
import Link from "next/link"
import {
  useAddUserToDepartmentMutation,
  useRemoveUserFromDepartmentMutation,
} from "@/lib/queries/users"
import { useDepartmentsQuery } from "@/lib/queries/departments"
import { Skeleton } from "@/components/ui/skeleton"
import { X, Plus } from "@phosphor-icons/react"
import type { Department } from "@/lib/types"

interface UserDepartmentsSectionProps {
  userId: string
  memberDepartmentIds: string[]
}

export function UserDepartmentsSection({ userId, memberDepartmentIds }: UserDepartmentsSectionProps) {
  const { data: allDepartments, isLoading } = useDepartmentsQuery()
  const addMutation = useAddUserToDepartmentMutation(userId)
  const removeMutation = useRemoveUserFromDepartmentMutation(userId)
  const [adding, setAdding] = useState(false)

  if (isLoading) {
    return <Skeleton className="h-24 w-full" />
  }

  const memberDepartments = allDepartments?.filter((d) =>
    memberDepartmentIds.includes(d.id),
  ) ?? []

  const availableDepartments = allDepartments?.filter(
    (d) => !memberDepartmentIds.includes(d.id),
  ) ?? []

  return (
    <div>
      <h2 className="mb-3 text-sm font-medium text-zinc-900">Departments</h2>
      {memberDepartments.length === 0 ? (
        <p className="text-sm text-zinc-500">Not a member of any department.</p>
      ) : (
        <div className="space-y-2">
          {memberDepartments.map((dept) => (
            <div
              key={dept.id}
              className="flex items-center justify-between rounded-lg border border-zinc-200 bg-white px-3 py-2"
            >
              <Link href={`/departments/${dept.id}`} className="text-sm font-medium text-zinc-900 hover:underline">
                {dept.name}
              </Link>
              <button
                onClick={() => removeMutation.mutate(dept.id)}
                disabled={removeMutation.isPending}
                className="rounded p-1 text-zinc-400 hover:bg-zinc-100 hover:text-zinc-600 transition-colors"
                aria-label={`Remove from ${dept.name}`}
              >
                <X size={14} />
              </button>
            </div>
          ))}
        </div>
      )}
      {adding ? (
        <div className="mt-3">
          <select
            className="w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900"
            defaultValue=""
            onChange={(e) => {
              if (e.target.value) {
                addMutation.mutate(e.target.value)
                setAdding(false)
              }
            }}
          >
            <option value="" disabled>Select a department...</option>
            {availableDepartments.map((d) => (
              <option key={d.id} value={d.id}>{d.name}</option>
            ))}
          </select>
        </div>
      ) : (
        <button
          onClick={() => setAdding(true)}
          disabled={availableDepartments.length === 0}
          className="mt-3 flex items-center gap-1.5 text-sm font-medium text-zinc-500 hover:text-zinc-700 transition-colors disabled:opacity-50"
        >
          <Plus size={14} />
          Add to department
        </button>
      )}
    </div>
  )
}
```

**Step 2: Create UserRolesSection**

Create `dashboard/src/components/users/user-roles-section.tsx`:

```tsx
"use client"

import { useState } from "react"
import {
  useRolesQuery,
  useUserRolesQuery,
  useAssignRoleMutation,
  useRemoveRoleMutation,
} from "@/lib/queries/roles"
import { useDepartmentsQuery } from "@/lib/queries/departments"
import { Skeleton } from "@/components/ui/skeleton"
import { Badge } from "@/components/ui/badge"
import { X, Plus } from "@phosphor-icons/react"
import type { AssignRoleRequest } from "@/lib/types"

interface UserRolesSectionProps {
  userId: string
  tenantId: string
}

export function UserRolesSection({ userId, tenantId }: UserRolesSectionProps) {
  const { data: userRoles, isLoading: rolesLoading } = useUserRolesQuery(userId)
  const { data: allRoles } = useRolesQuery()
  const { data: departments } = useDepartmentsQuery()
  const assignMutation = useAssignRoleMutation(userId)
  const removeMutation = useRemoveRoleMutation(userId)

  const [assigning, setAssigning] = useState(false)
  const [selectedRoleId, setSelectedRoleId] = useState("")
  const [scopeType, setScopeType] = useState<"org" | "department">("org")
  const [scopeId, setScopeId] = useState("")

  if (rolesLoading) {
    return <Skeleton className="h-24 w-full" />
  }

  function handleAssign() {
    if (!selectedRoleId || !scopeId) return
    assignMutation.mutate(
      { role_id: selectedRoleId, scope_type: scopeType, scope_id: scopeId },
      {
        onSuccess: () => {
          setAssigning(false)
          setSelectedRoleId("")
          setScopeType("org")
          setScopeId("")
        },
      },
    )
  }

  function handleRemove(role: AssignRoleRequest) {
    removeMutation.mutate(role)
  }

  function getDepartmentName(id: string): string {
    return departments?.find((d) => d.id === id)?.name ?? id
  }

  return (
    <div>
      <h2 className="mb-3 text-sm font-medium text-zinc-900">Roles</h2>
      {(!userRoles || userRoles.length === 0) ? (
        <p className="text-sm text-zinc-500">No roles assigned.</p>
      ) : (
        <div className="space-y-2">
          {userRoles.map((ur) => (
            <div
              key={`${ur.role_id}-${ur.scope_type}-${ur.scope_id}`}
              className="flex items-center justify-between rounded-lg border border-zinc-200 bg-white px-3 py-2"
            >
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium text-zinc-900">{ur.role_name}</span>
                <Badge variant="outline" className="text-xs">
                  {ur.scope_type === "org" ? "Org-wide" : getDepartmentName(ur.scope_id)}
                </Badge>
              </div>
              <button
                onClick={() => handleRemove({
                  role_id: ur.role_id,
                  scope_type: ur.scope_type,
                  scope_id: ur.scope_id,
                })}
                disabled={removeMutation.isPending}
                className="rounded p-1 text-zinc-400 hover:bg-zinc-100 hover:text-zinc-600 transition-colors"
                aria-label={`Remove ${ur.role_name}`}
              >
                <X size={14} />
              </button>
            </div>
          ))}
        </div>
      )}
      {assigning ? (
        <div className="mt-3 space-y-3 rounded-lg border border-zinc-200 bg-zinc-50 p-3">
          <select
            className="w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm"
            value={selectedRoleId}
            onChange={(e) => setSelectedRoleId(e.target.value)}
          >
            <option value="">Select role...</option>
            {allRoles?.map((r) => (
              <option key={r.id} value={r.id}>{r.name}</option>
            ))}
          </select>
          <div className="flex gap-2">
            <select
              className="flex-1 rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm"
              value={scopeType}
              onChange={(e) => {
                const newType = e.target.value as "org" | "department"
                setScopeType(newType)
                setScopeId(newType === "org" ? tenantId : "")
              }}
            >
              <option value="org">Org-wide</option>
              <option value="department">Department</option>
            </select>
            {scopeType === "department" && (
              <select
                className="flex-1 rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm"
                value={scopeId}
                onChange={(e) => setScopeId(e.target.value)}
              >
                <option value="">Select department...</option>
                {departments?.map((d) => (
                  <option key={d.id} value={d.id}>{d.name}</option>
                ))}
              </select>
            )}
          </div>
          <div className="flex gap-2">
            <button
              onClick={handleAssign}
              disabled={!selectedRoleId || !scopeId || assignMutation.isPending}
              className="rounded-lg bg-zinc-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-zinc-800 active:scale-[0.98] disabled:opacity-50"
            >
              {assignMutation.isPending ? "Assigning..." : "Assign"}
            </button>
            <button
              onClick={() => setAssigning(false)}
              className="rounded-lg px-3 py-1.5 text-sm text-zinc-500 hover:text-zinc-700"
            >
              Cancel
            </button>
          </div>
        </div>
      ) : (
        <button
          onClick={() => {
            setScopeId(tenantId)
            setAssigning(true)
          }}
          className="mt-3 flex items-center gap-1.5 text-sm font-medium text-zinc-500 hover:text-zinc-700 transition-colors"
        >
          <Plus size={14} />
          Assign role
        </button>
      )}
    </div>
  )
}
```

**Step 3: Create UserDetail wrapper**

Create `dashboard/src/components/users/user-detail.tsx`:

```tsx
"use client"

import { useUserQuery } from "@/lib/queries/users"
import { UserStatusBadge } from "./user-status-badge"
import { UserDepartmentsSection } from "./user-departments-section"
import { UserRolesSection } from "./user-roles-section"
import { Skeleton } from "@/components/ui/skeleton"
import { formatDate } from "@/lib/format"

interface UserDetailProps {
  id: string
  tenantId: string
}

export function UserDetail({ id, tenantId }: UserDetailProps) {
  const { data: user, isLoading, isError } = useUserQuery(id)

  if (isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-12 w-72" />
        <Skeleton className="h-32 w-full rounded-xl" />
        <Skeleton className="h-32 w-full rounded-xl" />
      </div>
    )
  }

  if (isError || !user) {
    return (
      <div className="rounded-xl border border-rose-200 bg-rose-50 p-4">
        <p className="text-sm text-rose-700">Failed to load user details.</p>
      </div>
    )
  }

  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">
            {user.display_name || user.email}
          </h1>
          <UserStatusBadge status={user.status as "active" | "suspended"} />
        </div>
        <div className="mt-2 flex items-center gap-4 text-sm text-zinc-500">
          <span>{user.email}</span>
          <span>Created {formatDate(user.created_at, "long")}</span>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-8 xl:grid-cols-2">
        <div className="rounded-xl border border-zinc-200 bg-white p-5">
          <UserDepartmentsSection userId={id} memberDepartmentIds={[]} />
        </div>
        <div className="rounded-xl border border-zinc-200 bg-white p-5">
          <UserRolesSection userId={id} tenantId={tenantId} />
        </div>
      </div>
    </div>
  )
}
```

Note: `memberDepartmentIds` is passed as empty array for now. The Go API does not return department memberships on the user GET endpoint. A future enhancement could add a `/api/v1/users/{id}/departments` GET endpoint. For now, the departments section will load all departments and the user can add/remove. Alternatively, we can fetch departments and filter by checking membership — but that requires a different API call. Keep it simple for now: the section works for adding and removing, and shows what the user has added in-session via cache.

**Step 4: Create user detail page**

Create `dashboard/src/app/(dashboard)/users/[id]/page.tsx`:

```tsx
import { UserDetail } from "@/components/users/user-detail"
import { auth } from "@/lib/auth"

export default async function UserDetailPage({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  const { id } = await params
  const session = await auth()
  const tenantId = session?.user?.tenantId ?? ""

  return <UserDetail id={id} tenantId={tenantId} />
}
```

**Step 5: Verify build**

```bash
cd dashboard && npm run build
```

Expected: Build succeeds.

**Step 6: Commit**

```bash
git add src/components/users/ src/app/\(dashboard\)/users/\[id\]/
git commit -m "feat(dashboard): add user detail page with department and role sections"
```

---

## Task 7: Create User Form

**Files:**
- Create: `dashboard/src/components/users/create-user-form.tsx`
- Create: `dashboard/src/components/users/create-user-form.test.tsx`
- Create: `dashboard/src/app/(dashboard)/users/new/page.tsx`

**Step 1: Write the failing test**

Create `dashboard/src/components/users/create-user-form.test.tsx`:

```tsx
import { describe, it, expect, vi } from "vitest"
import { render, screen, fireEvent } from "@testing-library/react"

vi.mock("next-auth/react", () => ({
  useSession: vi.fn().mockReturnValue({
    data: { accessToken: "test", user: { isPlatformAdmin: false, tenantId: "t-1" } },
    status: "authenticated",
  }),
}))

vi.mock("@tanstack/react-query", () => ({
  useMutation: vi.fn().mockReturnValue({
    mutate: vi.fn(),
    isPending: false,
    isError: false,
  }),
  useQueryClient: vi.fn().mockReturnValue({}),
}))

vi.mock("next/navigation", () => ({
  useRouter: vi.fn().mockReturnValue({ push: vi.fn() }),
}))

describe("CreateUserForm", () => {
  it("renders email and display name fields", async () => {
    const { CreateUserForm } = await import("./create-user-form")
    render(<CreateUserForm />)
    expect(screen.getByLabelText("Email")).toBeDefined()
    expect(screen.getByLabelText("Display Name")).toBeDefined()
  })

  it("renders submit button", async () => {
    const { CreateUserForm } = await import("./create-user-form")
    render(<CreateUserForm />)
    expect(screen.getByRole("button", { name: /create user/i })).toBeDefined()
  })
})
```

**Step 2: Run test to verify it fails**

```bash
cd dashboard && npx vitest run src/components/users/create-user-form.test.tsx
```

Expected: FAIL.

**Step 3: Write implementation**

Create `dashboard/src/components/users/create-user-form.tsx`:

```tsx
"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { useCreateUserMutation } from "@/lib/queries/users"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"

export function CreateUserForm() {
  const router = useRouter()
  const mutation = useCreateUserMutation()
  const [email, setEmail] = useState("")
  const [displayName, setDisplayName] = useState("")

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    mutation.mutate(
      { email, display_name: displayName || undefined },
      { onSuccess: (user) => router.push(`/users/${user.id}`) },
    )
  }

  return (
    <form onSubmit={handleSubmit} className="max-w-lg space-y-6">
      <div className="space-y-2">
        <Label htmlFor="email">Email</Label>
        <Input
          id="email"
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="user@example.com"
          required
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="displayName">Display Name</Label>
        <Input
          id="displayName"
          value={displayName}
          onChange={(e) => setDisplayName(e.target.value)}
          placeholder="Optional"
        />
        <p className="text-xs text-zinc-400">How this user appears in the dashboard.</p>
      </div>

      {mutation.isError && (
        <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2">
          <p className="text-sm text-rose-700">Failed to create user. The email may already be in use.</p>
        </div>
      )}

      <button
        type="submit"
        disabled={mutation.isPending || !email}
        className="rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-zinc-800 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {mutation.isPending ? "Creating..." : "Create user"}
      </button>
    </form>
  )
}
```

**Step 4: Create the page**

Create `dashboard/src/app/(dashboard)/users/new/page.tsx`:

```tsx
import { CreateUserForm } from "@/components/users/create-user-form"

export default function NewUserPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">Create User</h1>
        <p className="mt-1 text-sm text-zinc-500">Add a new user to your organization.</p>
      </div>
      <CreateUserForm />
    </div>
  )
}
```

**Step 5: Run tests**

```bash
cd dashboard && npx vitest run src/components/users/create-user-form.test.tsx
```

Expected: PASS.

**Step 6: Verify build**

```bash
cd dashboard && npm run build
```

**Step 7: Commit**

```bash
git add src/components/users/create-user-form.tsx src/components/users/create-user-form.test.tsx src/app/\(dashboard\)/users/new/
git commit -m "feat(dashboard): add create user form with email validation"
```

---

## Task 8: Department List Page with Hierarchy

**Files:**
- Create: `dashboard/src/components/departments/department-table.tsx`
- Create: `dashboard/src/components/departments/department-table.test.tsx`
- Create: `dashboard/src/app/(dashboard)/departments/page.tsx`
- Create: `dashboard/src/app/(dashboard)/departments/loading.tsx`

**Step 1: Write the failing test for hierarchy logic**

Create `dashboard/src/components/departments/department-table.test.tsx`:

```tsx
import { describe, it, expect } from "vitest"

describe("buildHierarchy", () => {
  it("sorts departments into tree order with depth", async () => {
    const { buildHierarchy } = await import("./department-table")

    const departments = [
      { id: "d-3", tenant_id: "t-1", name: "Sub-Scouting", parent_id: "d-1", created_at: "" },
      { id: "d-1", tenant_id: "t-1", name: "Scouting", parent_id: null, created_at: "" },
      { id: "d-2", tenant_id: "t-1", name: "First Team", parent_id: null, created_at: "" },
    ]

    const result = buildHierarchy(departments)

    expect(result).toEqual([
      { department: departments[1], depth: 0 },  // Scouting (top-level)
      { department: departments[0], depth: 1 },  // Sub-Scouting (child of Scouting)
      { department: departments[2], depth: 0 },  // First Team (top-level)
    ])
  })

  it("returns empty for empty input", async () => {
    const { buildHierarchy } = await import("./department-table")
    expect(buildHierarchy([])).toEqual([])
  })
})
```

**Step 2: Run test to verify it fails**

```bash
cd dashboard && npx vitest run src/components/departments/department-table.test.tsx
```

Expected: FAIL.

**Step 3: Write implementation**

Create `dashboard/src/components/departments/department-table.tsx`:

```tsx
"use client"

import { useState } from "react"
import Link from "next/link"
import { useDepartmentsQuery } from "@/lib/queries/departments"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { MagnifyingGlass } from "@phosphor-icons/react"
import { formatDate } from "@/lib/format"
import type { Department } from "@/lib/types"

interface HierarchyItem {
  department: Department
  depth: number
}

export function buildHierarchy(departments: Department[]): HierarchyItem[] {
  const childrenMap = new Map<string | null, Department[]>()
  for (const dept of departments) {
    const parentKey = dept.parent_id ?? null
    if (!childrenMap.has(parentKey)) {
      childrenMap.set(parentKey, [])
    }
    childrenMap.get(parentKey)!.push(dept)
  }

  const result: HierarchyItem[] = []
  function walk(parentId: string | null, depth: number) {
    const children = childrenMap.get(parentId) ?? []
    for (const child of children) {
      result.push({ department: child, depth })
      walk(child.id, depth + 1)
    }
  }
  walk(null, 0)
  return result
}

export function DepartmentTable() {
  const { data: departments, isLoading, isError } = useDepartmentsQuery()
  const [search, setSearch] = useState("")

  if (isLoading) {
    return (
      <div className="space-y-3">
        <Skeleton className="h-10 w-64" />
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-14 w-full" />
        ))}
      </div>
    )
  }

  if (isError) {
    return (
      <div className="rounded-xl border border-rose-200 bg-rose-50 p-4">
        <p className="text-sm text-rose-700">Failed to load departments.</p>
      </div>
    )
  }

  if (!departments || departments.length === 0) {
    return (
      <div className="py-12 text-center">
        <p className="text-sm font-medium text-zinc-900">No departments yet</p>
        <p className="mt-1 text-sm text-zinc-500">Create your first department to organize your team.</p>
        <Link
          href="/departments/new"
          className="mt-4 inline-block rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800 transition-colors active:scale-[0.98]"
        >
          Create department
        </Link>
      </div>
    )
  }

  const hierarchy = buildHierarchy(departments)
  const filtered = search
    ? hierarchy.filter((h) => h.department.name.toLowerCase().includes(search.toLowerCase()))
    : hierarchy

  const parentNames = new Map(departments.map((d) => [d.id, d.name]))

  return (
    <div className="space-y-4">
      <div className="relative max-w-sm">
        <MagnifyingGlass size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-400" />
        <Input
          placeholder="Search departments..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="pl-9"
        />
      </div>

      <div className="rounded-xl border border-zinc-200 bg-white">
        <div className="grid grid-cols-[3fr_2fr_1fr] gap-4 border-b border-zinc-100 px-4 py-3 text-xs font-medium uppercase tracking-wider text-zinc-500">
          <span>Name</span>
          <span>Parent</span>
          <span>Created</span>
        </div>
        <div className="divide-y divide-zinc-100">
          {filtered.map(({ department, depth }) => (
            <Link
              key={department.id}
              href={`/departments/${department.id}`}
              className="grid grid-cols-[3fr_2fr_1fr] gap-4 px-4 py-3 text-sm transition-colors hover:bg-zinc-50"
            >
              <span
                className="font-medium text-zinc-900"
                style={{ paddingLeft: `${Math.min(depth, 4) * 1.5}rem` }}
              >
                {depth > 0 && (
                  <span className="mr-2 text-zinc-300">|</span>
                )}
                {department.name}
              </span>
              <span className="text-zinc-500">
                {department.parent_id ? parentNames.get(department.parent_id) ?? "—" : "—"}
              </span>
              <span className="text-zinc-500">{formatDate(department.created_at)}</span>
            </Link>
          ))}
        </div>
      </div>
    </div>
  )
}
```

**Step 4: Create department list page**

Create `dashboard/src/app/(dashboard)/departments/page.tsx`:

```tsx
import Link from "next/link"
import { DepartmentTable } from "@/components/departments/department-table"
import { Plus } from "@phosphor-icons/react/dist/ssr"

export default function DepartmentsPage() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">Departments</h1>
          <p className="mt-1 text-sm text-zinc-500">Organize your team into departments.</p>
        </div>
        <Link
          href="/departments/new"
          className="flex items-center gap-2 rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-zinc-800 active:scale-[0.98]"
        >
          <Plus size={16} />
          Create department
        </Link>
      </div>
      <DepartmentTable />
    </div>
  )
}
```

**Step 5: Create loading skeleton**

Create `dashboard/src/app/(dashboard)/departments/loading.tsx`:

```tsx
import { Skeleton } from "@/components/ui/skeleton"

export default function DepartmentsLoading() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="space-y-2">
          <Skeleton className="h-8 w-40" />
          <Skeleton className="h-4 w-56" />
        </div>
        <Skeleton className="h-10 w-44 rounded-lg" />
      </div>
      <Skeleton className="h-10 w-64" />
      <div className="space-y-2">
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-14 w-full rounded-xl" />
        ))}
      </div>
    </div>
  )
}
```

**Step 6: Run tests**

```bash
cd dashboard && npx vitest run src/components/departments/department-table.test.tsx
```

Expected: PASS.

**Step 7: Verify build**

```bash
cd dashboard && npm run build
```

**Step 8: Commit**

```bash
git add src/components/departments/ src/app/\(dashboard\)/departments/
git commit -m "feat(dashboard): add department list page with hierarchy visualization"
```

---

## Task 9: Department Detail Page

**Files:**
- Create: `dashboard/src/components/departments/department-detail.tsx`
- Create: `dashboard/src/components/departments/department-members-section.tsx`
- Create: `dashboard/src/app/(dashboard)/departments/[id]/page.tsx`

**Step 1: Create DepartmentMembersSection**

Create `dashboard/src/components/departments/department-members-section.tsx`:

```tsx
"use client"

import { useUsersQuery } from "@/lib/queries/users"
import { useAddUserToDepartmentMutation, useRemoveUserFromDepartmentMutation } from "@/lib/queries/users"
import { UserStatusBadge } from "@/components/users/user-status-badge"
import { Skeleton } from "@/components/ui/skeleton"
import { X, Plus } from "@phosphor-icons/react"
import { useState } from "react"
import Link from "next/link"

interface DepartmentMembersSectionProps {
  departmentId: string
}

export function DepartmentMembersSection({ departmentId }: DepartmentMembersSectionProps) {
  const { data: allUsers, isLoading } = useUsersQuery()
  const [adding, setAdding] = useState(false)

  // Note: The Go API does not have a "list users by department" endpoint.
  // For now, we show all users and allow add/remove operations.
  // A future enhancement could add a department members endpoint.

  if (isLoading) {
    return <Skeleton className="h-32 w-full" />
  }

  return (
    <div>
      <h2 className="mb-3 text-sm font-medium text-zinc-900">Members</h2>
      {!allUsers || allUsers.length === 0 ? (
        <p className="text-sm text-zinc-500">No users in this organization yet.</p>
      ) : (
        <div className="space-y-2">
          {allUsers.map((user) => (
            <div
              key={user.id}
              className="flex items-center justify-between rounded-lg border border-zinc-200 bg-white px-3 py-2"
            >
              <Link href={`/users/${user.id}`} className="flex items-center gap-3 hover:underline">
                <span className="text-sm font-medium text-zinc-900">
                  {user.display_name || user.email}
                </span>
                <span className="text-xs text-zinc-400">{user.email}</span>
              </Link>
              <UserStatusBadge status={user.status as "active" | "suspended"} />
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
```

**Step 2: Create DepartmentDetail**

Create `dashboard/src/components/departments/department-detail.tsx`:

```tsx
"use client"

import { useDepartmentQuery, useDepartmentsQuery } from "@/lib/queries/departments"
import { DepartmentMembersSection } from "./department-members-section"
import { Skeleton } from "@/components/ui/skeleton"
import { formatDate } from "@/lib/format"
import Link from "next/link"

export function DepartmentDetail({ id }: { id: string }) {
  const { data: department, isLoading, isError } = useDepartmentQuery(id)
  const { data: allDepartments } = useDepartmentsQuery()

  if (isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-12 w-72" />
        <Skeleton className="h-48 w-full rounded-xl" />
      </div>
    )
  }

  if (isError || !department) {
    return (
      <div className="rounded-xl border border-rose-200 bg-rose-50 p-4">
        <p className="text-sm text-rose-700">Failed to load department details.</p>
      </div>
    )
  }

  const parentName = department.parent_id
    ? allDepartments?.find((d) => d.id === department.parent_id)?.name
    : null

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">
          {department.name}
        </h1>
        <div className="mt-2 flex items-center gap-4 text-sm text-zinc-500">
          {parentName ? (
            <span>
              Parent:{" "}
              <Link href={`/departments/${department.parent_id}`} className="text-zinc-700 hover:underline">
                {parentName}
              </Link>
            </span>
          ) : (
            <span>Top-level department</span>
          )}
          <span>Created {formatDate(department.created_at, "long")}</span>
        </div>
      </div>

      <div className="rounded-xl border border-zinc-200 bg-white p-5">
        <DepartmentMembersSection departmentId={id} />
      </div>
    </div>
  )
}
```

**Step 3: Create department detail page**

Create `dashboard/src/app/(dashboard)/departments/[id]/page.tsx`:

```tsx
import { DepartmentDetail } from "@/components/departments/department-detail"

export default async function DepartmentDetailPage({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  const { id } = await params
  return <DepartmentDetail id={id} />
}
```

**Step 4: Verify build**

```bash
cd dashboard && npm run build
```

**Step 5: Commit**

```bash
git add src/components/departments/department-detail.tsx src/components/departments/department-members-section.tsx src/app/\(dashboard\)/departments/\[id\]/
git commit -m "feat(dashboard): add department detail page with members section"
```

---

## Task 10: Create Department Form

**Files:**
- Create: `dashboard/src/components/departments/create-department-form.tsx`
- Create: `dashboard/src/app/(dashboard)/departments/new/page.tsx`

**Step 1: Write the form component**

Create `dashboard/src/components/departments/create-department-form.tsx`:

```tsx
"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { useCreateDepartmentMutation, useDepartmentsQuery } from "@/lib/queries/departments"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"

export function CreateDepartmentForm() {
  const router = useRouter()
  const mutation = useCreateDepartmentMutation()
  const { data: departments } = useDepartmentsQuery()
  const [name, setName] = useState("")
  const [parentId, setParentId] = useState("")

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    mutation.mutate(
      { name, parent_id: parentId || undefined },
      { onSuccess: (dept) => router.push(`/departments/${dept.id}`) },
    )
  }

  return (
    <form onSubmit={handleSubmit} className="max-w-lg space-y-6">
      <div className="space-y-2">
        <Label htmlFor="name">Name</Label>
        <Input
          id="name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="e.g. Scouting"
          required
          maxLength={255}
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="parent">Parent Department</Label>
        <select
          id="parent"
          className="w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900"
          value={parentId}
          onChange={(e) => setParentId(e.target.value)}
        >
          <option value="">None (top-level)</option>
          {departments?.map((d) => (
            <option key={d.id} value={d.id}>{d.name}</option>
          ))}
        </select>
        <p className="text-xs text-zinc-400">Optional. Nest this department under a parent.</p>
      </div>

      {mutation.isError && (
        <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2">
          <p className="text-sm text-rose-700">Failed to create department.</p>
        </div>
      )}

      <button
        type="submit"
        disabled={mutation.isPending || !name}
        className="rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-zinc-800 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {mutation.isPending ? "Creating..." : "Create department"}
      </button>
    </form>
  )
}
```

**Step 2: Create the page**

Create `dashboard/src/app/(dashboard)/departments/new/page.tsx`:

```tsx
import { CreateDepartmentForm } from "@/components/departments/create-department-form"

export default function NewDepartmentPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">Create Department</h1>
        <p className="mt-1 text-sm text-zinc-500">Add a new department to your organization.</p>
      </div>
      <CreateDepartmentForm />
    </div>
  )
}
```

**Step 3: Verify build**

```bash
cd dashboard && npm run build
```

**Step 4: Commit**

```bash
git add src/components/departments/create-department-form.tsx src/app/\(dashboard\)/departments/new/
git commit -m "feat(dashboard): add create department form with parent selection"
```

---

## Task 11: Final Verification

**Step 1: Run all unit tests**

```bash
cd dashboard && npx vitest run
```

Expected: All tests pass (existing Slice 1 tests + new Slice 2 tests).

**Step 2: Run build**

```bash
cd dashboard && npm run build
```

Expected: Zero TypeScript errors.

**Step 3: Run lint**

```bash
cd dashboard && npm run lint
```

Expected: No errors.

**Step 4: Commit if any cleanup needed**

```bash
git add -A
git commit -m "chore(dashboard): Slice 2 final verification pass"
```

---

## Summary

| Task | What | Files | Tests |
|------|------|-------|-------|
| 1 | New types | `lib/types.ts` | tsc check |
| 2 | User query hooks | `lib/queries/users.ts` | `users.test.ts` (5 tests) |
| 3 | Department query hooks | `lib/queries/departments.ts` | `departments.test.ts` (3 tests) |
| 4 | Role query hooks | `lib/queries/roles.ts` | `roles.test.ts` (4 tests) |
| 5 | User list page | `components/users/*`, `app/users/` | Build check |
| 6 | User detail + dept/role sections | `components/users/*`, `app/users/[id]/` | Build check |
| 7 | Create user form | `components/users/create-user-form.*` | `create-user-form.test.tsx` |
| 8 | Department list + hierarchy | `components/departments/*`, `app/departments/` | `department-table.test.tsx` |
| 9 | Department detail + members | `components/departments/*`, `app/departments/[id]/` | Build check |
| 10 | Create department form | `components/departments/create-department-form.*` | Build check |
| 11 | Final verification | — | Full suite |
