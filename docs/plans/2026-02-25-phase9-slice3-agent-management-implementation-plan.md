# Phase 9 Slice 3: Agent Management — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add Agent Management view to the Valinor admin dashboard with live status updates, inline configuration, provisioning, and destroy.

**Architecture:** Extends the existing Next.js 15 dashboard with new route group, components, and shared TanStack Query hooks for agents. Card grid layout with 10s polling for live health updates. Refactors the overview's local `agentKeys` to a shared hooks file.

**Tech Stack:** Next.js 15 (App Router), TypeScript, Tailwind CSS v4, shadcn/ui, TanStack Query v5, @phosphor-icons/react, Vitest + RTL

**Skills to follow:** `design-taste-frontend`, `vercel-react-best-practices`

**Design doc:** `docs/plans/2026-02-25-phase9-slice3-agent-management-design.md`

**Reference patterns:** `dashboard/src/components/users/`, `dashboard/src/lib/queries/tenants.ts`

---

## Task 1: Add New Types

**Files:**
- Modify: `dashboard/src/lib/types.ts`

**Step 1: Add agent request types**

Append to `dashboard/src/lib/types.ts`:

```typescript
// Agent request types — matches Go internal/orchestrator/handler.go
export interface ProvisionAgentRequest {
  user_id?: string
  department_id?: string
  config?: Record<string, unknown>
}

export interface ConfigureAgentRequest {
  config: Record<string, unknown>
  tool_allowlist: string[]
}
```

Note: `AgentInstance` already exists in this file from Slice 1.

**Step 2: Verify types compile**

```bash
cd dashboard && npx tsc --noEmit
```

Expected: No errors.

**Step 3: Commit**

```bash
git add src/lib/types.ts
git commit -m "feat(dashboard): add ProvisionAgentRequest and ConfigureAgentRequest types"
```

---

## Task 2: Agent Query Hooks (Shared)

**Files:**
- Create: `dashboard/src/lib/queries/agents.ts`
- Create: `dashboard/src/lib/queries/agents.test.ts`
- Modify: `dashboard/src/components/overview/platform-overview.tsx` (remove local `agentKeys`, import from shared)

**Step 1: Write the failing test**

Create `dashboard/src/lib/queries/agents.test.ts`:

```typescript
import { describe, it, expect, vi } from "vitest"

vi.mock("@/lib/api-client", () => ({
  apiClient: vi.fn(),
}))

describe("agent query functions", () => {
  it("fetchAgents calls correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ agents: [] })

    const { fetchAgents } = await import("./agents")
    await fetchAgents("test-token")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/agents",
      "test-token",
      undefined,
    )
  })

  it("fetchAgent calls correct endpoint with ID", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ id: "a-1", status: "running" })

    const { fetchAgent } = await import("./agents")
    await fetchAgent("test-token", "a-1")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/agents/a-1",
      "test-token",
      undefined,
    )
  })

  it("provisionAgent posts to correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ id: "a-2", status: "provisioning" })

    const { provisionAgent } = await import("./agents")
    await provisionAgent("test-token", { user_id: "u-1" })

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/agents",
      "test-token",
      {
        method: "POST",
        body: JSON.stringify({ user_id: "u-1" }),
      },
    )
  })

  it("destroyAgent deletes correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce(undefined)

    const { destroyAgent } = await import("./agents")
    await destroyAgent("test-token", "a-1")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/agents/a-1",
      "test-token",
      { method: "DELETE" },
    )
  })

  it("configureAgent posts config to correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ id: "a-1", status: "running" })

    const { configureAgent } = await import("./agents")
    await configureAgent("test-token", "a-1", {
      config: { model: "gpt-4" },
      tool_allowlist: ["search", "read"],
    })

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/agents/a-1/configure",
      "test-token",
      {
        method: "POST",
        body: JSON.stringify({
          config: { model: "gpt-4" },
          tool_allowlist: ["search", "read"],
        }),
      },
    )
  })
})
```

**Step 2: Run test to verify it fails**

```bash
cd dashboard && npx vitest run src/lib/queries/agents.test.ts
```

Expected: FAIL — module not found.

**Step 3: Write implementation**

Create `dashboard/src/lib/queries/agents.ts`:

```typescript
"use client"

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { useSession } from "next-auth/react"
import { apiClient } from "@/lib/api-client"
import type { AgentInstance, ProvisionAgentRequest, ConfigureAgentRequest } from "@/lib/types"

export const agentKeys = {
  all: ["agents"] as const,
  list: () => [...agentKeys.all, "list"] as const,
  detail: (id: string) => [...agentKeys.all, "detail", id] as const,
}

interface AgentListResponse {
  agents: AgentInstance[]
}

export async function fetchAgents(accessToken: string): Promise<AgentListResponse> {
  return apiClient<AgentListResponse>("/api/v1/agents", accessToken, undefined)
}

export async function fetchAgent(accessToken: string, id: string): Promise<AgentInstance> {
  return apiClient<AgentInstance>(`/api/v1/agents/${id}`, accessToken, undefined)
}

export async function provisionAgent(
  accessToken: string,
  data: ProvisionAgentRequest,
): Promise<AgentInstance> {
  return apiClient<AgentInstance>("/api/v1/agents", accessToken, {
    method: "POST",
    body: JSON.stringify(data),
  })
}

export async function destroyAgent(
  accessToken: string,
  id: string,
): Promise<void> {
  return apiClient<void>(`/api/v1/agents/${id}`, accessToken, {
    method: "DELETE",
  })
}

export async function configureAgent(
  accessToken: string,
  id: string,
  data: ConfigureAgentRequest,
): Promise<AgentInstance> {
  return apiClient<AgentInstance>(`/api/v1/agents/${id}/configure`, accessToken, {
    method: "POST",
    body: JSON.stringify(data),
  })
}

export function useAgentsQuery(statusFilter?: string) {
  const { data: session } = useSession()
  return useQuery({
    queryKey: [...agentKeys.list(), statusFilter ?? "all"],
    queryFn: async () => {
      const res = await fetchAgents(session!.accessToken)
      if (statusFilter && statusFilter !== "all") {
        return { agents: res.agents.filter((a) => a.status === statusFilter) }
      }
      return res
    },
    enabled: !!session?.accessToken,
    refetchInterval: 10_000,
  })
}

export function useAgentQuery(id: string) {
  const { data: session } = useSession()
  return useQuery({
    queryKey: agentKeys.detail(id),
    queryFn: () => fetchAgent(session!.accessToken, id),
    enabled: !!session?.accessToken && !!id,
    refetchInterval: 10_000,
  })
}

export function useProvisionAgentMutation() {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: ProvisionAgentRequest) =>
      provisionAgent(session!.accessToken, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: agentKeys.all })
    },
  })
}

export function useDestroyAgentMutation() {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => destroyAgent(session!.accessToken, id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: agentKeys.all })
    },
  })
}

export function useConfigureAgentMutation(id: string) {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: ConfigureAgentRequest) =>
      configureAgent(session!.accessToken, id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: agentKeys.detail(id) })
      queryClient.invalidateQueries({ queryKey: agentKeys.list() })
    },
  })
}
```

**Step 4: Update platform-overview.tsx to use shared agentKeys**

In `dashboard/src/components/overview/platform-overview.tsx`:
- Remove the local `agentKeys` definition (lines 13-16)
- Add import: `import { agentKeys } from "@/lib/queries/agents"`
- Update the agent query to use `agentKeys.list()` (should already match)

**Step 5: Run tests**

```bash
cd dashboard && npx vitest run src/lib/queries/agents.test.ts
```

Expected: PASS.

**Step 6: Verify build (ensures overview refactor didn't break)**

```bash
cd dashboard && npm run build
```

**Step 7: Commit**

```bash
git add src/lib/queries/agents.ts src/lib/queries/agents.test.ts src/components/overview/platform-overview.tsx
git commit -m "feat(dashboard): add shared agent query hooks and refactor overview imports"
```

---

## Task 3: Agent Status Badge Component

**Files:**
- Create: `dashboard/src/components/agents/agent-status-badge.tsx`
- Create: `dashboard/src/components/agents/agent-status-badge.test.tsx`

**Step 1: Write the failing test**

Create `dashboard/src/components/agents/agent-status-badge.test.tsx`:

```tsx
import { describe, it, expect } from "vitest"
import { render, screen } from "@testing-library/react"

describe("AgentStatusBadge", () => {
  it("renders running status with correct styling", async () => {
    const { AgentStatusBadge } = await import("./agent-status-badge")
    render(<AgentStatusBadge status="running" />)
    const badge = screen.getByText("running")
    expect(badge).toBeDefined()
    expect(badge.className).toContain("emerald")
  })

  it("renders unhealthy status with rose styling", async () => {
    const { AgentStatusBadge } = await import("./agent-status-badge")
    render(<AgentStatusBadge status="unhealthy" />)
    const badge = screen.getByText("unhealthy")
    expect(badge.className).toContain("rose")
  })

  it("renders provisioning status with amber styling", async () => {
    const { AgentStatusBadge } = await import("./agent-status-badge")
    render(<AgentStatusBadge status="provisioning" />)
    const badge = screen.getByText("provisioning")
    expect(badge.className).toContain("amber")
  })
})
```

**Step 2: Run test to verify it fails**

```bash
cd dashboard && npx vitest run src/components/agents/agent-status-badge.test.tsx
```

Expected: FAIL.

**Step 3: Write implementation**

Create `dashboard/src/components/agents/agent-status-badge.tsx`:

```tsx
import { Badge } from "@/components/ui/badge"

type AgentStatus = "warm" | "provisioning" | "running" | "unhealthy" | "destroying" | "destroyed" | "stopped" | "replacing"

const statusStyles: Record<string, string> = {
  running: "bg-emerald-50 text-emerald-700 border-emerald-200",
  warm: "bg-amber-50 text-amber-700 border-amber-200",
  provisioning: "bg-amber-50 text-amber-700 border-amber-200",
  unhealthy: "bg-rose-50 text-rose-700 border-rose-200",
  destroying: "bg-zinc-100 text-zinc-500 border-zinc-200",
  destroyed: "bg-zinc-100 text-zinc-500 border-zinc-200",
  stopped: "bg-zinc-100 text-zinc-500 border-zinc-200",
  replacing: "bg-amber-50 text-amber-700 border-amber-200",
}

export function AgentStatusBadge({ status }: { status: string }) {
  return (
    <Badge variant="outline" className={statusStyles[status] ?? "bg-zinc-100 text-zinc-500 border-zinc-200"}>
      {status}
    </Badge>
  )
}

export function AgentStatusDot({ status }: { status: string }) {
  const dotColors: Record<string, string> = {
    running: "bg-emerald-500",
    warm: "bg-amber-500",
    provisioning: "bg-amber-500",
    unhealthy: "bg-rose-500",
    destroying: "bg-zinc-400",
    destroyed: "bg-zinc-400",
    stopped: "bg-zinc-400",
    replacing: "bg-amber-500",
  }

  const isRunning = status === "running"

  return (
    <span className="relative flex h-2.5 w-2.5">
      {isRunning && (
        <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75" />
      )}
      <span className={`relative inline-flex h-2.5 w-2.5 rounded-full ${dotColors[status] ?? "bg-zinc-400"}`} />
    </span>
  )
}
```

Note: The `animate-ping` for running status creates a subtle pulse effect using CSS (no Framer Motion needed — per design-taste, this is isolated).

**Step 4: Run tests**

```bash
cd dashboard && npx vitest run src/components/agents/agent-status-badge.test.tsx
```

Expected: PASS.

**Step 5: Commit**

```bash
git add src/components/agents/
git commit -m "feat(dashboard): add agent status badge and dot components with pulse animation"
```

---

## Task 4: Agent Card Grid & List Page

**Files:**
- Create: `dashboard/src/components/agents/agent-card.tsx`
- Create: `dashboard/src/components/agents/agent-grid.tsx`
- Create: `dashboard/src/app/(dashboard)/agents/page.tsx`
- Create: `dashboard/src/app/(dashboard)/agents/loading.tsx`

**Step 1: Create AgentCard**

Create `dashboard/src/components/agents/agent-card.tsx`:

```tsx
import Link from "next/link"
import { AgentStatusDot } from "./agent-status-badge"
import { formatDate } from "@/lib/format"
import type { AgentInstance } from "@/lib/types"

function truncateId(id: string): string {
  return id.length > 8 ? `${id.slice(0, 8)}...` : id
}

function formatTimeAgo(dateStr: string | null): string {
  if (!dateStr) return "Never"
  const seconds = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000)
  if (seconds < 60) return `${seconds}s ago`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  return `${hours}h ago`
}

export function AgentCard({ agent }: { agent: AgentInstance }) {
  return (
    <Link
      href={`/agents/${agent.id}`}
      className="rounded-xl border border-zinc-200 bg-white p-4 transition-colors hover:bg-zinc-50 active:scale-[0.99]"
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <AgentStatusDot status={agent.status} />
          <span className="text-sm font-medium text-zinc-900">{agent.status}</span>
        </div>
        <span className="font-mono text-xs text-zinc-400" title={agent.id}>
          {truncateId(agent.id)}
        </span>
      </div>

      <div className="mt-3 space-y-1.5 text-xs text-zinc-500">
        {agent.user_id && (
          <div className="flex justify-between">
            <span>User</span>
            <span className="font-mono text-zinc-700">{truncateId(agent.user_id)}</span>
          </div>
        )}
        {agent.department_id && (
          <div className="flex justify-between">
            <span>Department</span>
            <span className="font-mono text-zinc-700">{truncateId(agent.department_id)}</span>
          </div>
        )}
        <div className="flex justify-between">
          <span>VM Driver</span>
          <span className="text-zinc-700">{agent.vm_id ? "firecracker" : "mock"}</span>
        </div>
        <div className="flex justify-between">
          <span>Last Health</span>
          <span className="font-mono text-zinc-700">{formatTimeAgo(agent.last_health_check)}</span>
        </div>
        <div className="flex justify-between">
          <span>Created</span>
          <span className="text-zinc-700">{formatDate(agent.created_at)}</span>
        </div>
      </div>
    </Link>
  )
}
```

**Step 2: Create AgentGrid**

Create `dashboard/src/components/agents/agent-grid.tsx`:

```tsx
"use client"

import { useState, useDeferredValue } from "react"
import Link from "next/link"
import { useAgentsQuery } from "@/lib/queries/agents"
import { AgentCard } from "./agent-card"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { MagnifyingGlass } from "@phosphor-icons/react"

const STATUS_OPTIONS = ["all", "running", "provisioning", "unhealthy", "warm"] as const

export function AgentGrid() {
  const [statusFilter, setStatusFilter] = useState<string>("all")
  const [search, setSearch] = useState("")
  const deferredSearch = useDeferredValue(search)
  const { data, isLoading, isError } = useAgentsQuery(statusFilter)

  const agents = data?.agents ?? []
  const filtered = deferredSearch
    ? agents.filter(
        (a) =>
          a.id.toLowerCase().includes(deferredSearch.toLowerCase()) ||
          (a.user_id ?? "").toLowerCase().includes(deferredSearch.toLowerCase()),
      )
    : agents

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="flex gap-3">
          <Skeleton className="h-10 w-64" />
          <Skeleton className="h-10 w-40" />
        </div>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-48 rounded-xl" />
          ))}
        </div>
      </div>
    )
  }

  if (isError) {
    return (
      <div className="rounded-xl border border-rose-200 bg-rose-50 p-4">
        <p className="text-sm text-rose-700">Failed to load agents.</p>
      </div>
    )
  }

  if (agents.length === 0 && statusFilter === "all") {
    return (
      <div className="py-12 text-center">
        <p className="text-sm font-medium text-zinc-900">No agents running</p>
        <p className="mt-1 text-sm text-zinc-500">Provision your first agent to get started.</p>
        <Link
          href="/agents/new"
          className="mt-4 inline-block rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800 transition-colors active:scale-[0.98]"
        >
          Provision agent
        </Link>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative max-w-sm flex-1">
          <MagnifyingGlass size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-400" />
          <Input
            placeholder="Search by ID or user..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
        <select
          className="rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900"
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
        >
          {STATUS_OPTIONS.map((s) => (
            <option key={s} value={s}>
              {s === "all" ? "All statuses" : s}
            </option>
          ))}
        </select>
      </div>

      {filtered.length === 0 ? (
        <p className="py-8 text-center text-sm text-zinc-500">
          No agents match your filters.
        </p>
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {filtered.map((agent) => (
            <AgentCard key={agent.id} agent={agent} />
          ))}
        </div>
      )}
    </div>
  )
}
```

**Step 3: Create agent list page**

Create `dashboard/src/app/(dashboard)/agents/page.tsx`:

```tsx
import Link from "next/link"
import { AgentGrid } from "@/components/agents/agent-grid"
import { Plus } from "@phosphor-icons/react/dist/ssr"

export default function AgentsPage() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">Agents</h1>
          <p className="mt-1 text-sm text-zinc-500">Manage AI agent instances.</p>
        </div>
        <Link
          href="/agents/new"
          className="flex items-center gap-2 rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-zinc-800 active:scale-[0.98]"
        >
          <Plus size={16} />
          Provision agent
        </Link>
      </div>
      <AgentGrid />
    </div>
  )
}
```

**Step 4: Create loading skeleton**

Create `dashboard/src/app/(dashboard)/agents/loading.tsx`:

```tsx
import { Skeleton } from "@/components/ui/skeleton"

export default function AgentsLoading() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="space-y-2">
          <Skeleton className="h-8 w-24" />
          <Skeleton className="h-4 w-48" />
        </div>
        <Skeleton className="h-10 w-40 rounded-lg" />
      </div>
      <div className="flex gap-3">
        <Skeleton className="h-10 w-64" />
        <Skeleton className="h-10 w-40" />
      </div>
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
        {Array.from({ length: 6 }).map((_, i) => (
          <Skeleton key={i} className="h-48 rounded-xl" />
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

**Step 6: Commit**

```bash
git add src/components/agents/agent-card.tsx src/components/agents/agent-grid.tsx src/app/\(dashboard\)/agents/
git commit -m "feat(dashboard): add agent card grid with live polling and status filter"
```

---

## Task 5: Agent Detail Page

**Files:**
- Create: `dashboard/src/components/agents/agent-detail.tsx`
- Create: `dashboard/src/components/agents/agent-config-editor.tsx`
- Create: `dashboard/src/app/(dashboard)/agents/[id]/page.tsx`

**Step 1: Create AgentConfigEditor**

Create `dashboard/src/components/agents/agent-config-editor.tsx`:

```tsx
"use client"

import { useState } from "react"
import { useConfigureAgentMutation } from "@/lib/queries/agents"
import { Label } from "@/components/ui/label"

interface AgentConfigEditorProps {
  agentId: string
  currentConfig: Record<string, unknown>
  currentAllowlist: string[]
  onDone: () => void
}

export function AgentConfigEditor({
  agentId,
  currentConfig,
  currentAllowlist,
  onDone,
}: AgentConfigEditorProps) {
  const mutation = useConfigureAgentMutation(agentId)
  const [configJson, setConfigJson] = useState(JSON.stringify(currentConfig, null, 2))
  const [allowlist, setAllowlist] = useState(currentAllowlist.join(", "))
  const [jsonError, setJsonError] = useState("")

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setJsonError("")

    let parsedConfig: Record<string, unknown>
    try {
      parsedConfig = JSON.parse(configJson)
    } catch {
      setJsonError("Invalid JSON")
      return
    }

    const tools = allowlist
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean)

    mutation.mutate(
      { config: parsedConfig, tool_allowlist: tools },
      { onSuccess: () => onDone() },
    )
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="config">Config (JSON)</Label>
        <textarea
          id="config"
          value={configJson}
          onChange={(e) => setConfigJson(e.target.value)}
          rows={8}
          className="w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 font-mono text-xs text-zinc-900 focus:border-zinc-400 focus:outline-none focus:ring-1 focus:ring-zinc-400"
        />
        {jsonError && <p className="text-xs text-rose-600">{jsonError}</p>}
      </div>

      <div className="space-y-2">
        <Label htmlFor="allowlist">Tool Allowlist (comma-separated)</Label>
        <input
          id="allowlist"
          value={allowlist}
          onChange={(e) => setAllowlist(e.target.value)}
          placeholder="tool1, tool2, tool3"
          className="w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 focus:border-zinc-400 focus:outline-none focus:ring-1 focus:ring-zinc-400"
        />
        <p className="text-xs text-zinc-400">Leave empty for no restrictions.</p>
      </div>

      {mutation.isError && (
        <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2">
          <p className="text-sm text-rose-700">Failed to update config. It may violate the runtime policy.</p>
        </div>
      )}

      <div className="flex gap-2">
        <button
          type="submit"
          disabled={mutation.isPending}
          className="rounded-lg bg-zinc-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-zinc-800 active:scale-[0.98] disabled:opacity-50"
        >
          {mutation.isPending ? "Saving..." : "Save config"}
        </button>
        <button
          type="button"
          onClick={onDone}
          className="rounded-lg px-3 py-1.5 text-sm text-zinc-500 hover:text-zinc-700"
        >
          Cancel
        </button>
      </div>
    </form>
  )
}
```

**Step 2: Create AgentDetail**

Create `dashboard/src/components/agents/agent-detail.tsx`:

```tsx
"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { useAgentQuery, useDestroyAgentMutation } from "@/lib/queries/agents"
import { AgentStatusBadge } from "./agent-status-badge"
import { AgentConfigEditor } from "./agent-config-editor"
import { Skeleton } from "@/components/ui/skeleton"
import { Badge } from "@/components/ui/badge"
import { formatDate } from "@/lib/format"
import { Wrench, Trash, Gear } from "@phosphor-icons/react"
import Link from "next/link"

function truncateId(id: string): string {
  return id.length > 12 ? `${id.slice(0, 12)}...` : id
}

function formatTimeAgo(dateStr: string | null): string {
  if (!dateStr) return "Never"
  const seconds = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000)
  if (seconds < 60) return `${seconds}s ago`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  return `${hours}h ago`
}

function parseJsonField(val: string | Record<string, unknown> | null): Record<string, unknown> {
  if (!val) return {}
  if (typeof val === "object") return val
  try { return JSON.parse(val) } catch { return {} }
}

function parseArrayField(val: string | string[] | null): string[] {
  if (!val) return []
  if (Array.isArray(val)) return val
  try { return JSON.parse(val) } catch { return [] }
}

export function AgentDetail({ id }: { id: string }) {
  const router = useRouter()
  const { data: agent, isLoading, isError } = useAgentQuery(id)
  const destroyMutation = useDestroyAgentMutation()
  const [editing, setEditing] = useState(false)
  const [confirmDestroy, setConfirmDestroy] = useState(false)

  if (isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-12 w-72" />
        <Skeleton className="h-24 w-full rounded-xl" />
        <Skeleton className="h-48 w-full rounded-xl" />
      </div>
    )
  }

  if (isError || !agent) {
    return (
      <div className="rounded-xl border border-rose-200 bg-rose-50 p-4">
        <p className="text-sm text-rose-700">Failed to load agent details.</p>
      </div>
    )
  }

  const config = parseJsonField(agent.config)
  const tools = parseArrayField(agent.tool_allowlist)

  function handleDestroy() {
    destroyMutation.mutate(id, {
      onSuccess: () => router.push("/agents"),
    })
  }

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">Agent</h1>
            <AgentStatusBadge status={agent.status} />
          </div>
          <div className="mt-2 flex items-center gap-4 text-sm text-zinc-500">
            <span className="font-mono" title={agent.id}>{truncateId(agent.id)}</span>
            <span>Created {formatDate(agent.created_at, "long")}</span>
          </div>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setEditing(!editing)}
            className="flex items-center gap-1.5 rounded-lg border border-zinc-200 px-3 py-1.5 text-sm font-medium text-zinc-700 hover:bg-zinc-50 transition-colors active:scale-[0.98]"
          >
            <Gear size={14} />
            Configure
          </button>
          {!confirmDestroy ? (
            <button
              onClick={() => setConfirmDestroy(true)}
              className="flex items-center gap-1.5 rounded-lg border border-rose-200 px-3 py-1.5 text-sm font-medium text-rose-600 hover:bg-rose-50 transition-colors active:scale-[0.98]"
            >
              <Trash size={14} />
              Destroy
            </button>
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
      </div>

      {/* Health strip */}
      <div className="flex flex-wrap gap-6 border-t border-zinc-200 pt-4 text-sm">
        <div>
          <span className="text-zinc-500">Last Health Check</span>
          <p className="font-mono text-zinc-900">{formatTimeAgo(agent.last_health_check)}</p>
        </div>
        <div>
          <span className="text-zinc-500">Consecutive Failures</span>
          <p className="font-mono text-zinc-900">{agent.consecutive_failures ?? 0}</p>
        </div>
        <div>
          <span className="text-zinc-500">VM Driver</span>
          <p className="text-zinc-900">{agent.vm_id ? "firecracker" : "mock"}</p>
        </div>
        {agent.vsock_cid && (
          <div>
            <span className="text-zinc-500">vsock CID</span>
            <p className="font-mono text-zinc-900">{agent.vsock_cid}</p>
          </div>
        )}
        {agent.vm_id && (
          <div>
            <span className="text-zinc-500">VM ID</span>
            <p className="font-mono text-zinc-900">{truncateId(agent.vm_id)}</p>
          </div>
        )}
      </div>

      {/* Info */}
      <div className="flex flex-wrap gap-6 text-sm">
        {agent.user_id && (
          <div>
            <span className="text-zinc-500">Assigned User</span>
            <p>
              <Link href={`/users/${agent.user_id}`} className="font-mono text-zinc-900 hover:underline">
                {truncateId(agent.user_id)}
              </Link>
            </p>
          </div>
        )}
        {agent.department_id && (
          <div>
            <span className="text-zinc-500">Department</span>
            <p>
              <Link href={`/departments/${agent.department_id}`} className="font-mono text-zinc-900 hover:underline">
                {truncateId(agent.department_id)}
              </Link>
            </p>
          </div>
        )}
      </div>

      {/* Config editor or viewer */}
      {editing ? (
        <div className="rounded-xl border border-zinc-200 bg-white p-5">
          <AgentConfigEditor
            agentId={id}
            currentConfig={config}
            currentAllowlist={tools}
            onDone={() => setEditing(false)}
          />
        </div>
      ) : (
        <>
          <div>
            <h2 className="mb-3 text-sm font-medium text-zinc-900">Configuration</h2>
            <div className="rounded-xl border border-zinc-200 bg-white p-4">
              <pre className="text-xs font-mono text-zinc-600 overflow-auto">
                {JSON.stringify(config, null, 2)}
              </pre>
            </div>
          </div>

          <div>
            <h2 className="mb-3 text-sm font-medium text-zinc-900">Tool Allowlist</h2>
            <div className="rounded-xl border border-zinc-200 bg-white p-4">
              {tools.length === 0 ? (
                <p className="text-sm text-zinc-500">No tool restrictions.</p>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {tools.map((tool) => (
                    <Badge key={tool} variant="outline" className="font-mono text-xs">
                      <Wrench size={12} className="mr-1" />
                      {tool}
                    </Badge>
                  ))}
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  )
}
```

**Step 3: Create agent detail page**

Create `dashboard/src/app/(dashboard)/agents/[id]/page.tsx`:

```tsx
import { AgentDetail } from "@/components/agents/agent-detail"

export default async function AgentDetailPage({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  const { id } = await params
  return <AgentDetail id={id} />
}
```

**Step 4: Verify build**

```bash
cd dashboard && npm run build
```

**Step 5: Commit**

```bash
git add src/components/agents/agent-detail.tsx src/components/agents/agent-config-editor.tsx src/app/\(dashboard\)/agents/\[id\]/
git commit -m "feat(dashboard): add agent detail page with config editor and destroy"
```

---

## Task 6: Provision Agent Form

**Files:**
- Create: `dashboard/src/components/agents/provision-agent-form.tsx`
- Create: `dashboard/src/components/agents/provision-agent-form.test.tsx`
- Create: `dashboard/src/app/(dashboard)/agents/new/page.tsx`

**Step 1: Write the failing test**

Create `dashboard/src/components/agents/provision-agent-form.test.tsx`:

```tsx
import { describe, it, expect, vi } from "vitest"
import { render, screen } from "@testing-library/react"

vi.mock("next-auth/react", () => ({
  useSession: vi.fn().mockReturnValue({
    data: { accessToken: "test", user: { id: "u-1", isPlatformAdmin: false, tenantId: "t-1" } },
    status: "authenticated",
  }),
}))

vi.mock("@tanstack/react-query", () => ({
  useMutation: vi.fn().mockReturnValue({
    mutate: vi.fn(),
    isPending: false,
    isError: false,
  }),
  useQuery: vi.fn().mockReturnValue({
    data: [],
    isLoading: false,
  }),
  useQueryClient: vi.fn().mockReturnValue({}),
}))

vi.mock("next/navigation", () => ({
  useRouter: vi.fn().mockReturnValue({ push: vi.fn() }),
}))

describe("ProvisionAgentForm", () => {
  it("renders submit button", async () => {
    const { ProvisionAgentForm } = await import("./provision-agent-form")
    render(<ProvisionAgentForm />)
    expect(screen.getByRole("button", { name: /provision agent/i })).toBeDefined()
  })
})
```

**Step 2: Run test to verify it fails**

```bash
cd dashboard && npx vitest run src/components/agents/provision-agent-form.test.tsx
```

Expected: FAIL.

**Step 3: Write implementation**

Create `dashboard/src/components/agents/provision-agent-form.tsx`:

```tsx
"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { useProvisionAgentMutation } from "@/lib/queries/agents"
import { useUsersQuery } from "@/lib/queries/users"
import { useDepartmentsQuery } from "@/lib/queries/departments"
import { useSession } from "next-auth/react"
import { Label } from "@/components/ui/label"

export function ProvisionAgentForm() {
  const router = useRouter()
  const { data: session } = useSession()
  const mutation = useProvisionAgentMutation()
  const { data: users } = useUsersQuery()
  const { data: departments } = useDepartmentsQuery()

  const isPlatformAdmin = session?.user?.isPlatformAdmin ?? false
  const [userId, setUserId] = useState(isPlatformAdmin ? "" : session?.user?.id ?? "")
  const [departmentId, setDepartmentId] = useState("")
  const [configJson, setConfigJson] = useState("{}")
  const [jsonError, setJsonError] = useState("")

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setJsonError("")

    let parsedConfig: Record<string, unknown> | undefined
    if (configJson.trim() && configJson.trim() !== "{}") {
      try {
        parsedConfig = JSON.parse(configJson)
      } catch {
        setJsonError("Invalid JSON")
        return
      }
    }

    mutation.mutate(
      {
        user_id: userId || undefined,
        department_id: departmentId || undefined,
        config: parsedConfig,
      },
      { onSuccess: (agent) => router.push(`/agents/${agent.id}`) },
    )
  }

  return (
    <form onSubmit={handleSubmit} className="max-w-lg space-y-6">
      <div className="space-y-2">
        <Label htmlFor="userId">User</Label>
        {isPlatformAdmin ? (
          <select
            id="userId"
            className="w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900"
            value={userId}
            onChange={(e) => setUserId(e.target.value)}
          >
            <option value="">Auto-assign</option>
            {users?.map((u) => (
              <option key={u.id} value={u.id}>
                {u.display_name || u.email}
              </option>
            ))}
          </select>
        ) : (
          <p className="text-sm text-zinc-500">Assigned to you ({session?.user?.email})</p>
        )}
      </div>

      <div className="space-y-2">
        <Label htmlFor="departmentId">Department</Label>
        <select
          id="departmentId"
          className="w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900"
          value={departmentId}
          onChange={(e) => setDepartmentId(e.target.value)}
        >
          <option value="">None</option>
          {departments?.map((d) => (
            <option key={d.id} value={d.id}>{d.name}</option>
          ))}
        </select>
        <p className="text-xs text-zinc-400">Optional. Scope this agent to a department.</p>
      </div>

      <div className="space-y-2">
        <Label htmlFor="config">Initial Config (JSON)</Label>
        <textarea
          id="config"
          value={configJson}
          onChange={(e) => setConfigJson(e.target.value)}
          rows={4}
          className="w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 font-mono text-xs text-zinc-900 focus:border-zinc-400 focus:outline-none focus:ring-1 focus:ring-zinc-400"
        />
        {jsonError && <p className="text-xs text-rose-600">{jsonError}</p>}
        <p className="text-xs text-zinc-400">Optional. Provide initial agent configuration.</p>
      </div>

      {mutation.isError && (
        <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2">
          <p className="text-sm text-rose-700">Failed to provision agent.</p>
        </div>
      )}

      <button
        type="submit"
        disabled={mutation.isPending}
        className="rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-zinc-800 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {mutation.isPending ? "Provisioning..." : "Provision agent"}
      </button>
    </form>
  )
}
```

**Step 4: Create the page**

Create `dashboard/src/app/(dashboard)/agents/new/page.tsx`:

```tsx
import { ProvisionAgentForm } from "@/components/agents/provision-agent-form"

export default function NewAgentPage() {
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

**Step 5: Run tests**

```bash
cd dashboard && npx vitest run src/components/agents/provision-agent-form.test.tsx
```

Expected: PASS.

**Step 6: Verify build**

```bash
cd dashboard && npm run build
```

**Step 7: Commit**

```bash
git add src/components/agents/provision-agent-form.tsx src/components/agents/provision-agent-form.test.tsx src/app/\(dashboard\)/agents/new/
git commit -m "feat(dashboard): add provision agent form with user and department selection"
```

---

## Task 7: Final Verification

**Step 1: Run all unit tests**

```bash
cd dashboard && npx vitest run
```

Expected: All tests pass.

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

**Step 4: Commit if cleanup needed**

```bash
git add -A
git commit -m "chore(dashboard): Slice 3 agent management final verification"
```

---

## Summary

| Task | What | Files | Tests |
|------|------|-------|-------|
| 1 | Agent request types | `lib/types.ts` | tsc check |
| 2 | Shared agent query hooks | `lib/queries/agents.ts`, overview refactor | `agents.test.ts` (5 tests) |
| 3 | Status badge + dot | `components/agents/agent-status-badge.*` | `agent-status-badge.test.tsx` (3 tests) |
| 4 | Agent card grid + list page | `components/agents/agent-{card,grid}.*`, `app/agents/` | Build check |
| 5 | Agent detail + config editor | `components/agents/agent-{detail,config-editor}.*`, `app/agents/[id]/` | Build check |
| 6 | Provision agent form | `components/agents/provision-agent-form.*`, `app/agents/new/` | `provision-agent-form.test.tsx` |
| 7 | Final verification | — | Full suite |
