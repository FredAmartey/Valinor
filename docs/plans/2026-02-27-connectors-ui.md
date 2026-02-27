# Connectors UI Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a `/connectors` dashboard page where org_admins and dept_heads can list, register, and delete MCP connectors.

**Architecture:** Single server-component page gates on `connectors:read`, passes `canWrite` to a `"use client"` view. Query hooks follow the `channelKeys` factory pattern. Inline collapsible create form + delete with confirmation. No detail page.

**Tech Stack:** Next.js 16 App Router, TypeScript, Tailwind CSS v4, TanStack Query v5, Phosphor Icons

---

### Task 1: Add `CreateConnectorRequest` type

**Files:**
- Modify: `dashboard/src/lib/types.ts:96` (after `Connector` interface)

**Step 1: Add the type**

Insert after the closing `}` of the `Connector` interface (line 96):

```ts
export interface CreateConnectorRequest {
  name: string
  connector_type?: string
  endpoint: string
  auth_config?: Record<string, unknown>
  tools?: string[]
  resources?: string[]
}
```

**Step 2: Verify**

Run: `cd dashboard && npx tsc --noEmit`
Expected: No errors related to types.ts

**Step 3: Commit**

```bash
git add dashboard/src/lib/types.ts
git commit -m "feat(dashboard): add CreateConnectorRequest type"
```

---

### Task 2: Add connector audit labels

**Files:**
- Modify: `dashboard/src/components/audit/audit-labels.ts`

**Step 1: Add connector entries to ACTION_LABELS**

Insert after the role events block (after the `"user_role.revoked"` line, before the closing `}`):

```ts
  // Connector events
  "connector.created": { label: "Connector Created", category: "connector" },
  "connector.deleted": { label: "Connector Deleted", category: "connector" },
```

**Step 2: Add connector category color**

Add to `CATEGORY_COLORS`:

```ts
  connector: "bg-orange-500",
```

**Step 3: Add connector to ACTION_CATEGORIES**

Add before the closing `] as const`:

```ts
  { value: "connector", label: "Connector" },
```

**Step 4: Update the ActionLabel type**

Change the `category` union to include `"connector"`:

```ts
export interface ActionLabel {
  label: string
  category: "channel" | "user" | "agent" | "tenant" | "department" | "role" | "connector"
}
```

**Step 5: Verify**

Run: `cd dashboard && npx tsc --noEmit`
Expected: No type errors

**Step 6: Commit**

```bash
git add dashboard/src/components/audit/audit-labels.ts
git commit -m "feat(dashboard): add connector audit event labels"
```

---

### Task 3: Create connector query hooks

**Files:**
- Create: `dashboard/src/lib/queries/connectors.ts`

**Step 1: Write the query module**

```ts
"use client"

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { useSession } from "next-auth/react"
import { apiClient } from "@/lib/api-client"
import type { Connector, CreateConnectorRequest } from "@/lib/types"

export const connectorKeys = {
  all: ["connectors"] as const,
  list: () => [...connectorKeys.all, "list"] as const,
}

// --- Fetch functions ---

export async function fetchConnectors(accessToken: string): Promise<Connector[]> {
  return apiClient<Connector[]>("/api/v1/connectors", accessToken, undefined)
}

export async function createConnector(
  accessToken: string,
  data: CreateConnectorRequest,
): Promise<Connector> {
  return apiClient<Connector>("/api/v1/connectors", accessToken, {
    method: "POST",
    body: JSON.stringify(data),
  })
}

export async function deleteConnector(accessToken: string, id: string): Promise<void> {
  return apiClient<void>(`/api/v1/connectors/${id}`, accessToken, {
    method: "DELETE",
  })
}

// --- Query hooks ---

export function useConnectorsQuery() {
  const { data: session } = useSession()
  return useQuery({
    queryKey: connectorKeys.list(),
    queryFn: () => fetchConnectors(session!.accessToken),
    enabled: !!session?.accessToken,
    staleTime: 30_000,
  })
}

// --- Mutation hooks ---

export function useCreateConnectorMutation() {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: CreateConnectorRequest) =>
      createConnector(session!.accessToken, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: connectorKeys.all })
    },
  })
}

export function useDeleteConnectorMutation() {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => deleteConnector(session!.accessToken, id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: connectorKeys.all })
    },
  })
}
```

**Step 2: Verify**

Run: `cd dashboard && npx tsc --noEmit`
Expected: No errors

**Step 3: Commit**

```bash
git add dashboard/src/lib/queries/connectors.ts
git commit -m "feat(dashboard): add connector TanStack Query hooks"
```

---

### Task 4: Create connectors view component

**Files:**
- Create: `dashboard/src/components/connectors/connectors-view.tsx`

**Step 1: Write the view component**

This mirrors `links-tab.tsx` — inline create form, card list with delete.

```tsx
"use client"

import { useState } from "react"
import {
  useConnectorsQuery,
  useCreateConnectorMutation,
  useDeleteConnectorMutation,
} from "@/lib/queries/connectors"
import { formatTimeAgo, formatDate } from "@/lib/format"
import { Skeleton } from "@/components/ui/skeleton"
import { Plus, Trash, ArrowCounterClockwise } from "@phosphor-icons/react"
import { ApiError } from "@/lib/api-error"
import type { Connector, CreateConnectorRequest } from "@/lib/types"

const STATUS_PILL: Record<string, string> = {
  active: "bg-emerald-50 text-emerald-700",
  inactive: "bg-zinc-100 text-zinc-500",
}

export function ConnectorsView({ canWrite }: { canWrite: boolean }) {
  const [showCreate, setShowCreate] = useState(false)
  const { data: connectors, isLoading, isError, refetch } = useConnectorsQuery()
  const deleteMutation = useDeleteConnectorMutation()

  const handleDelete = (connector: Connector) => {
    if (!window.confirm(`Delete connector "${connector.name}"? This cannot be undone.`)) return
    deleteMutation.mutate(connector.id)
  }

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-10 w-40" />
        <div className="divide-y divide-zinc-100 rounded-xl border border-zinc-200">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="flex items-center gap-4 px-4 py-3">
              <Skeleton className="h-4 w-32" />
              <Skeleton className="h-4 w-48" />
              <Skeleton className="h-4 w-16" />
              <Skeleton className="h-4 w-20" />
            </div>
          ))}
        </div>
      </div>
    )
  }

  if (isError) {
    return (
      <div className="flex items-center justify-between rounded-xl border border-rose-200 bg-rose-50 p-4">
        <p className="text-sm text-rose-700">Failed to load connectors.</p>
        <button
          onClick={() => refetch()}
          className="flex items-center gap-1.5 rounded-lg bg-rose-100 px-3 py-1.5 text-sm font-medium text-rose-700 hover:bg-rose-200 transition-colors"
        >
          <ArrowCounterClockwise size={14} />
          Retry
        </button>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Toolbar */}
      <div className="flex items-center">
        <div className="flex-1" />
        {canWrite && (
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-1.5 rounded-lg bg-zinc-900 px-3 py-2 text-sm font-medium text-white hover:bg-zinc-800 transition-colors active:scale-[0.98]"
          >
            <Plus size={14} weight="bold" />
            Register connector
          </button>
        )}
      </div>

      {/* Create form */}
      {showCreate && (
        <CreateConnectorForm onClose={() => setShowCreate(false)} />
      )}

      {/* List */}
      {(connectors ?? []).length === 0 ? (
        <div className="py-12 text-center">
          <p className="text-sm font-medium text-zinc-900">No connectors registered</p>
          <p className="mt-1 text-sm text-zinc-500">
            Register an MCP connector to make tools available to agents.
          </p>
        </div>
      ) : (
        <div
          role="table"
          aria-label="Connectors"
          className="divide-y divide-zinc-100 rounded-xl border border-zinc-200 bg-white"
        >
          <div
            role="row"
            className="grid grid-cols-[1fr_1fr_120px_100px_60px] gap-4 px-4 py-2 text-xs font-medium uppercase tracking-wider text-zinc-400"
          >
            <span role="columnheader">Name</span>
            <span role="columnheader">Endpoint</span>
            <span role="columnheader">Status</span>
            <span role="columnheader">Created</span>
            <span role="columnheader" className="text-right">Actions</span>
          </div>
          {(connectors ?? []).map((connector) => (
            <div
              key={connector.id}
              role="row"
              className="grid grid-cols-[1fr_1fr_120px_100px_60px] gap-4 px-4 py-3 text-sm hover:bg-zinc-50 transition-colors"
            >
              <span role="cell" className="self-center">
                <span className="font-medium text-zinc-900">{connector.name}</span>
                {connector.tools.length > 0 && (
                  <span className="ml-2 text-xs text-zinc-400">
                    {connector.tools.length} tool{connector.tools.length !== 1 ? "s" : ""}
                  </span>
                )}
              </span>
              <span
                role="cell"
                className="self-center truncate font-mono text-xs text-zinc-500"
                title={connector.endpoint}
              >
                {connector.endpoint}
              </span>
              <span role="cell" className="self-center">
                <span
                  className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium ${STATUS_PILL[connector.status] ?? "bg-zinc-100 text-zinc-500"}`}
                >
                  {connector.status}
                </span>
              </span>
              <span
                role="cell"
                className="self-center text-zinc-500"
                title={formatDate(connector.created_at, "long")}
              >
                {formatTimeAgo(connector.created_at)}
              </span>
              <span role="cell" className="flex justify-end self-center">
                {canWrite && (
                  <button
                    onClick={() => handleDelete(connector)}
                    disabled={deleteMutation.isPending}
                    className="rounded p-1 text-zinc-400 hover:text-rose-600 transition-colors disabled:opacity-50"
                    title="Delete connector"
                  >
                    <Trash size={16} />
                  </button>
                )}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function CreateConnectorForm({ onClose }: { onClose: () => void }) {
  const mutation = useCreateConnectorMutation()
  const [form, setForm] = useState({
    name: "",
    endpoint: "",
    tools: "",
    auth_config: "",
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    const payload: CreateConnectorRequest = {
      name: form.name.trim(),
      endpoint: form.endpoint.trim(),
      tools: form.tools
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean),
    }
    if (form.auth_config.trim()) {
      try {
        payload.auth_config = JSON.parse(form.auth_config)
      } catch {
        return // let native validation or user fix it
      }
    }
    mutation.mutate(payload, {
      onSuccess: () => onClose(),
    })
  }

  const errorMessage = mutation.isError
    ? (mutation.error instanceof ApiError ? mutation.error.body?.error : null) ??
      "Failed to register connector."
    : null

  return (
    <form
      onSubmit={handleSubmit}
      className="rounded-xl border border-zinc-200 bg-white p-4 space-y-3"
    >
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium text-zinc-900">Register connector</h3>
        <button
          type="button"
          onClick={onClose}
          className="text-sm text-zinc-500 hover:text-zinc-700 transition-colors"
        >
          Cancel
        </button>
      </div>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <div>
          <label className="mb-1 block text-xs font-medium text-zinc-500">Name</label>
          <input
            type="text"
            required
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
            className="w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm text-zinc-900 placeholder:text-zinc-400"
            placeholder="e.g. marcelo-scouting"
          />
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-zinc-500">Endpoint</label>
          <input
            type="url"
            required
            value={form.endpoint}
            onChange={(e) => setForm({ ...form, endpoint: e.target.value })}
            className="w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm text-zinc-900 placeholder:text-zinc-400"
            placeholder="https://api.example.com/mcp"
          />
        </div>
      </div>
      <div>
        <label className="mb-1 block text-xs font-medium text-zinc-500">
          Tools <span className="text-zinc-400">(comma-separated, optional)</span>
        </label>
        <input
          type="text"
          value={form.tools}
          onChange={(e) => setForm({ ...form, tools: e.target.value })}
          className="w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm text-zinc-900 placeholder:text-zinc-400"
          placeholder="search_players, get_report"
        />
      </div>
      <div>
        <label className="mb-1 block text-xs font-medium text-zinc-500">
          Auth config <span className="text-zinc-400">(JSON, optional)</span>
        </label>
        <textarea
          value={form.auth_config}
          onChange={(e) => setForm({ ...form, auth_config: e.target.value })}
          rows={2}
          className="w-full rounded-lg border border-zinc-200 px-3 py-2 font-mono text-xs text-zinc-900 placeholder:text-zinc-400"
          placeholder='{"type": "bearer", "token": "sk-..."}'
        />
      </div>
      <div className="flex justify-end">
        <button
          type="submit"
          disabled={mutation.isPending}
          className="rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800 transition-colors active:scale-[0.98] disabled:opacity-50"
        >
          {mutation.isPending ? "Registering..." : "Register"}
        </button>
      </div>
      {errorMessage && <p className="text-sm text-rose-600">{errorMessage}</p>}
    </form>
  )
}
```

**Step 2: Verify**

Run: `cd dashboard && npx tsc --noEmit`
Expected: No errors

**Step 3: Commit**

```bash
git add dashboard/src/components/connectors/connectors-view.tsx
git commit -m "feat(dashboard): add ConnectorsView component with create/delete"
```

---

### Task 5: Create connectors page

**Files:**
- Create: `dashboard/src/app/(dashboard)/connectors/page.tsx`

**Step 1: Write the server component page**

```tsx
import { auth } from "@/lib/auth"
import { hasPermission } from "@/lib/permissions"
import { ConnectorsView } from "@/components/connectors/connectors-view"
import { Plugs } from "@phosphor-icons/react/dist/ssr"

export default async function ConnectorsPage() {
  const session = await auth()
  const isPlatformAdmin = session?.user?.isPlatformAdmin ?? false
  const roles = session?.user?.roles ?? []

  const canRead = hasPermission(isPlatformAdmin, roles, "connectors:read")

  if (!canRead) {
    return (
      <div className="py-12 text-center">
        <p className="text-sm font-medium text-zinc-900">Access denied</p>
        <p className="mt-1 text-sm text-zinc-500">You do not have permission to manage connectors.</p>
      </div>
    )
  }

  const canWrite = hasPermission(isPlatformAdmin, roles, "connectors:write")

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Plugs size={24} className="text-zinc-400" />
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">Connectors</h1>
          <p className="mt-1 text-sm text-zinc-500">Manage MCP tool connectors available to agents.</p>
        </div>
      </div>
      <ConnectorsView canWrite={canWrite} />
    </div>
  )
}
```

**Step 2: Verify type-check**

Run: `cd dashboard && npx tsc --noEmit`
Expected: No errors

**Step 3: Verify dev server renders**

Run: `cd dashboard && npm run dev`
Navigate to `http://localhost:3000/connectors`
Expected: Page renders with "No connectors registered" empty state (or connector list if seeded)

**Step 4: Commit**

```bash
git add dashboard/src/app/\(dashboard\)/connectors/page.tsx
git commit -m "feat(dashboard): add /connectors page with permission gate"
```

---

### Task 6: Verify full flow end-to-end

**Step 1: Start the Go backend**

Run: `go run ./cmd/valinor`

**Step 2: Start the dashboard**

Run: `cd dashboard && npm run dev`

**Step 3: Test as org_admin (turgon)**

1. Login as `turgon@gondolin.fc`
2. Navigate to `/connectors`
3. Verify "Register connector" button visible
4. Click button, fill in form: name="test-mcp", endpoint="https://example.com/mcp", tools="search,fetch"
5. Submit — connector should appear in list
6. Click delete icon — confirm dialog — connector removed
7. Navigate to `/audit` — verify `connector.created` and `connector.deleted` events appear with labels

**Step 4: Test as read_only (maeglin)**

1. Login as `maeglin@gondolin.fc`
2. Verify `/connectors` link does NOT appear in sidebar
3. Navigate directly to `/connectors` — verify "Access denied" message

**Step 5: Commit (if any fixes needed)**

```bash
git add -A
git commit -m "fix(dashboard): address issues found in connectors E2E verification"
```
