# Slice 6b: Audit Dashboard UI — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.
> **Frontend skills:** Before writing any component code, invoke `vercel-react-best-practices`, `design-taste-frontend`, `next-best-practices`.

**Goal:** Build the `/audit` dashboard page with server-side filter bar, table with expandable rows, cursor pagination, and proper permission gating.

**Architecture:** Server component page wrapping a client `AuditLog` component. Filters are passed as query params to the Go API (Slice 6a). TanStack Query manages fetching with filter params included in the query key for automatic refetch. Expandable rows use local state, no routing.

**Tech Stack:** Next.js 16 (App Router), TypeScript, Tailwind CSS v4, TanStack Query v5, @phosphor-icons/react, Vitest + RTL

**Design doc:** `docs/plans/2026-02-26-slice6-audit-dashboard-design.md` (Slice 6b section)

**Existing patterns to follow:**
- Query hooks: `dashboard/src/lib/queries/agents.ts` (factory keys, session token, apiClient)
- List component: `dashboard/src/components/agents/agent-grid.tsx` (filters, skeleton, error, empty states)
- Page: `dashboard/src/app/(dashboard)/agents/page.tsx` (server component, permission check)
- Tests: `dashboard/src/lib/queries/agents.test.ts` (mock apiClient, verify endpoint calls)

**Run all commands from:** `dashboard/` directory (worktree path: `.worktrees/slice6b-audit-dashboard/dashboard/`)

---

### Task 1: Add Types and Response Interface

**Files:**
- Modify: `dashboard/src/lib/types.ts`

**Step 1: Add AuditListResponse and AuditFilters types**

Add after the existing `AuditEvent` interface (around line 69):

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
  limit?: string
}
```

**Step 2: Fix AuditEvent — remove `correlation_id` field**

The Go API does not return `correlation_id` as a top-level field (it's inside `metadata`). Remove line 67 (`correlation_id: string`) from the `AuditEvent` interface.

**Step 3: Verify build**

Run: `cd dashboard && npx tsc --noEmit`
Expected: no errors

**Step 4: Commit**

```bash
git add dashboard/src/lib/types.ts
git commit -m "feat(dashboard): add AuditListResponse and AuditFilters types"
```

---

### Task 2: Create Query Hook

**Files:**
- Create: `dashboard/src/lib/queries/audit.ts`
- Create: `dashboard/src/lib/queries/audit.test.ts`

**Step 1: Write the failing test**

Create `dashboard/src/lib/queries/audit.test.ts`:

```typescript
import { describe, it, expect, vi } from "vitest"

vi.mock("@/lib/api-client", () => ({
  apiClient: vi.fn(),
}))

describe("audit query functions", () => {
  it("fetchAuditEvents calls correct endpoint with no filters", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ events: [], count: 0 })

    const { fetchAuditEvents } = await import("./audit")
    await fetchAuditEvents("test-token")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/audit/events",
      "test-token",
      { params: {} },
    )
  })

  it("fetchAuditEvents passes filter params", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ events: [], count: 0 })

    const { fetchAuditEvents } = await import("./audit")
    await fetchAuditEvents("test-token", {
      action: "user.created",
      resource_type: "user",
      limit: "25",
    })

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/audit/events",
      "test-token",
      {
        params: {
          action: "user.created",
          resource_type: "user",
          limit: "25",
        },
      },
    )
  })

  it("fetchAuditEvents strips undefined filter values", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ events: [], count: 0 })

    const { fetchAuditEvents } = await import("./audit")
    await fetchAuditEvents("test-token", {
      action: "role.created",
      resource_type: undefined,
    })

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/audit/events",
      "test-token",
      {
        params: {
          action: "role.created",
        },
      },
    )
  })
})
```

**Step 2: Run test to verify it fails**

Run: `cd dashboard && npx vitest run src/lib/queries/audit.test.ts`
Expected: FAIL — module `./audit` not found

**Step 3: Write the query hook**

Create `dashboard/src/lib/queries/audit.ts`:

```typescript
"use client"

import { useQuery } from "@tanstack/react-query"
import { useSession } from "next-auth/react"
import { apiClient } from "@/lib/api-client"
import type { AuditListResponse, AuditFilters } from "@/lib/types"

export const auditKeys = {
  all: ["auditEvents"] as const,
  list: (filters?: AuditFilters) => [...auditKeys.all, "list", filters ?? {}] as const,
}

export async function fetchAuditEvents(
  accessToken: string,
  filters?: AuditFilters,
): Promise<AuditListResponse> {
  const params: Record<string, string> = {}
  if (filters) {
    for (const [key, value] of Object.entries(filters)) {
      if (value !== undefined && value !== "") {
        params[key] = value
      }
    }
  }
  return apiClient<AuditListResponse>("/api/v1/audit/events", accessToken, { params })
}

export function useAuditEventsQuery(filters?: AuditFilters) {
  const { data: session } = useSession()
  return useQuery({
    queryKey: auditKeys.list(filters),
    queryFn: () => fetchAuditEvents(session!.accessToken, filters),
    enabled: !!session?.accessToken,
    staleTime: 30_000,
  })
}
```

**Step 4: Run test to verify it passes**

Run: `cd dashboard && npx vitest run src/lib/queries/audit.test.ts`
Expected: PASS (3 tests)

**Step 5: Commit**

```bash
git add dashboard/src/lib/queries/audit.ts dashboard/src/lib/queries/audit.test.ts
git commit -m "feat(dashboard): add audit events query hook and tests"
```

---

### Task 3: Create Action Label Mapping

**Files:**
- Create: `dashboard/src/components/audit/audit-labels.ts`

**Step 1: Create the label mapping**

```typescript
export interface ActionLabel {
  label: string
  category: "channel" | "user" | "agent" | "tenant" | "department" | "role"
}

const ACTION_LABELS: Record<string, ActionLabel> = {
  // Channel events
  "channel.message.accepted": { label: "Message Accepted", category: "channel" },
  "channel.message.duplicate": { label: "Message Duplicate", category: "channel" },
  "channel.message.replay_blocked": { label: "Replay Blocked", category: "channel" },
  "channel.webhook.ignored": { label: "Webhook Ignored", category: "channel" },
  "channel.webhook.rejected_signature": { label: "Signature Rejected", category: "channel" },
  "channel.action_denied_unverified": { label: "Denied (Unverified)", category: "channel" },
  "channel.action_executed": { label: "Action Executed", category: "channel" },
  "channel.action_denied_rbac": { label: "Denied (RBAC)", category: "channel" },
  "channel.action_denied_no_agent": { label: "Denied (No Agent)", category: "channel" },
  "channel.action_denied_sentinel": { label: "Denied (Sentinel)", category: "channel" },
  "channel.action_dispatch_failed": { label: "Dispatch Failed", category: "channel" },

  // User events
  "user.created": { label: "User Created", category: "user" },
  "user.updated": { label: "User Updated", category: "user" },
  "user.suspended": { label: "User Suspended", category: "user" },
  "user.reactivated": { label: "User Reactivated", category: "user" },

  // Agent events
  "agent.provisioned": { label: "Agent Provisioned", category: "agent" },
  "agent.updated": { label: "Agent Updated", category: "agent" },
  "agent.destroyed": { label: "Agent Destroyed", category: "agent" },

  // Tenant events
  "tenant.created": { label: "Tenant Created", category: "tenant" },
  "tenant.updated": { label: "Tenant Updated", category: "tenant" },
  "tenant.suspended": { label: "Tenant Suspended", category: "tenant" },

  // Department events
  "department.created": { label: "Department Created", category: "department" },
  "department.updated": { label: "Department Updated", category: "department" },
  "department.deleted": { label: "Department Deleted", category: "department" },

  // Role events
  "role.created": { label: "Role Created", category: "role" },
  "role.updated": { label: "Role Updated", category: "role" },
  "role.deleted": { label: "Role Deleted", category: "role" },
  "user_role.assigned": { label: "Role Assigned", category: "role" },
  "user_role.revoked": { label: "Role Revoked", category: "role" },
}

const CATEGORY_COLORS: Record<string, string> = {
  channel: "bg-blue-500",
  user: "bg-emerald-500",
  agent: "bg-amber-500",
  tenant: "bg-violet-500",
  department: "bg-cyan-500",
  role: "bg-rose-500",
}

export function getActionLabel(action: string): ActionLabel {
  return ACTION_LABELS[action] ?? { label: action, category: "channel" }
}

export function getCategoryColor(category: string): string {
  return CATEGORY_COLORS[category] ?? "bg-zinc-400"
}

export const SOURCE_LABELS: Record<string, string> = {
  api: "API",
  whatsapp: "WhatsApp",
  telegram: "Telegram",
  slack: "Slack",
  system: "System",
}

export const ACTION_CATEGORIES = [
  { value: "", label: "All actions" },
  { value: "channel", label: "Channel" },
  { value: "user", label: "User" },
  { value: "agent", label: "Agent" },
  { value: "tenant", label: "Tenant" },
  { value: "department", label: "Department" },
  { value: "role", label: "Role" },
] as const

export const RESOURCE_TYPES = [
  { value: "", label: "All resources" },
  { value: "user", label: "User" },
  { value: "agent", label: "Agent" },
  { value: "tenant", label: "Tenant" },
  { value: "department", label: "Department" },
  { value: "role", label: "Role" },
  { value: "connector", label: "Connector" },
] as const

export const SOURCES = [
  { value: "", label: "All sources" },
  { value: "api", label: "API" },
  { value: "whatsapp", label: "WhatsApp" },
  { value: "telegram", label: "Telegram" },
  { value: "slack", label: "Slack" },
  { value: "system", label: "System" },
] as const
```

**Step 2: Verify build**

Run: `cd dashboard && npx tsc --noEmit`
Expected: no errors

**Step 3: Commit**

```bash
git add dashboard/src/components/audit/audit-labels.ts
git commit -m "feat(dashboard): add audit event action labels and category mappings"
```

---

### Task 4: Create Audit Log Component

**Files:**
- Create: `dashboard/src/components/audit/audit-log.tsx`

This is the main client component with filters, table, expandable rows, and pagination.

**Step 1: Create the component**

Create `dashboard/src/components/audit/audit-log.tsx`:

```typescript
"use client"

import { useState, useDeferredValue } from "react"
import { useAuditEventsQuery } from "@/lib/queries/audit"
import { formatTimeAgo, formatDate, truncateId } from "@/lib/format"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { MagnifyingGlass, CaretDown, CaretUp, Copy, ArrowLeft, ArrowRight } from "@phosphor-icons/react"
import type { AuditEvent, AuditFilters } from "@/lib/types"
import {
  getActionLabel,
  getCategoryColor,
  SOURCE_LABELS,
  RESOURCE_TYPES,
  SOURCES,
} from "./audit-labels"

const PAGE_SIZE = 50

export function AuditLog() {
  const [actionFilter, setActionFilter] = useState("")
  const [resourceType, setResourceType] = useState("")
  const [sourceFilter, setSourceFilter] = useState("")
  const [search, setSearch] = useState("")
  const deferredSearch = useDeferredValue(search)
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [cursor, setCursor] = useState<{ after?: string; before?: string }>({})

  const filters: AuditFilters = {
    ...(actionFilter ? { action: actionFilter } : {}),
    ...(resourceType ? { resource_type: resourceType } : {}),
    ...(sourceFilter ? { source: sourceFilter } : {}),
    ...cursor,
    limit: String(PAGE_SIZE),
  }

  const { data, isLoading, isError } = useAuditEventsQuery(filters)
  const events = data?.events ?? []

  const filtered = deferredSearch
    ? events.filter(
        (e) =>
          e.action.toLowerCase().includes(deferredSearch.toLowerCase()) ||
          (e.resource_id ?? "").toLowerCase().includes(deferredSearch.toLowerCase()) ||
          (e.user_id ?? "").toLowerCase().includes(deferredSearch.toLowerCase()),
      )
    : events

  const hasFilters = actionFilter || resourceType || sourceFilter || search
  const clearFilters = () => {
    setActionFilter("")
    setResourceType("")
    setSourceFilter("")
    setSearch("")
    setCursor({})
  }

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="flex gap-3">
          <Skeleton className="h-10 w-64" />
          <Skeleton className="h-10 w-36" />
          <Skeleton className="h-10 w-36" />
          <Skeleton className="h-10 w-36" />
        </div>
        <div className="divide-y divide-zinc-100 rounded-xl border border-zinc-200">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="flex items-center gap-4 px-4 py-3">
              <Skeleton className="h-4 w-20" />
              <Skeleton className="h-4 w-32" />
              <Skeleton className="h-4 w-24" />
              <Skeleton className="h-4 w-20" />
              <Skeleton className="h-4 w-16" />
            </div>
          ))}
        </div>
      </div>
    )
  }

  if (isError) {
    return (
      <div className="rounded-xl border border-rose-200 bg-rose-50 p-4">
        <p className="text-sm text-rose-700">Failed to load audit events.</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative max-w-xs flex-1">
          <MagnifyingGlass size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-400" />
          <Input
            placeholder="Search by ID..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
        <select
          className="rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900"
          value={resourceType}
          onChange={(e) => { setResourceType(e.target.value); setCursor({}) }}
        >
          {RESOURCE_TYPES.map((r) => (
            <option key={r.value} value={r.value}>{r.label}</option>
          ))}
        </select>
        <select
          className="rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900"
          value={sourceFilter}
          onChange={(e) => { setSourceFilter(e.target.value); setCursor({}) }}
        >
          {SOURCES.map((s) => (
            <option key={s.value} value={s.value}>{s.label}</option>
          ))}
        </select>
        {hasFilters && (
          <button
            onClick={clearFilters}
            className="rounded-lg px-3 py-2 text-sm text-zinc-500 hover:text-zinc-900 transition-colors"
          >
            Clear filters
          </button>
        )}
      </div>

      {/* Table */}
      {filtered.length === 0 ? (
        <div className="py-12 text-center">
          <p className="text-sm font-medium text-zinc-900">
            {hasFilters ? "No events match your filters" : "No events recorded yet"}
          </p>
          <p className="mt-1 text-sm text-zinc-500">
            {hasFilters ? "Try adjusting your filters." : "Audit events will appear here as actions occur."}
          </p>
          {hasFilters && (
            <button
              onClick={clearFilters}
              className="mt-3 text-sm font-medium text-zinc-900 underline underline-offset-4 hover:text-zinc-700"
            >
              Clear filters
            </button>
          )}
        </div>
      ) : (
        <>
          <div className="divide-y divide-zinc-100 rounded-xl border border-zinc-200 bg-white">
            {/* Header */}
            <div className="grid grid-cols-[140px_1fr_1fr_1fr_100px] gap-4 px-4 py-2 text-xs font-medium uppercase tracking-wider text-zinc-400">
              <span>Time</span>
              <span>Action</span>
              <span>Resource</span>
              <span>Actor</span>
              <span>Source</span>
            </div>
            {filtered.map((event) => (
              <AuditRow
                key={event.id}
                event={event}
                expanded={expandedId === event.id}
                onToggle={() => setExpandedId(expandedId === event.id ? null : event.id)}
              />
            ))}
          </div>

          {/* Pagination */}
          <div className="flex items-center justify-between">
            <p className="text-sm text-zinc-500">
              {data?.count ?? 0} event{(data?.count ?? 0) !== 1 ? "s" : ""}
            </p>
            <div className="flex gap-2">
              {cursor.before && (
                <button
                  onClick={() => setCursor({})}
                  className="flex items-center gap-1 rounded-lg border border-zinc-200 px-3 py-1.5 text-sm text-zinc-700 hover:bg-zinc-50 transition-colors"
                >
                  <ArrowLeft size={14} /> Newer
                </button>
              )}
              {events.length === PAGE_SIZE && (
                <button
                  onClick={() => setCursor({ before: events[events.length - 1].created_at })}
                  className="flex items-center gap-1 rounded-lg border border-zinc-200 px-3 py-1.5 text-sm text-zinc-700 hover:bg-zinc-50 transition-colors"
                >
                  Older <ArrowRight size={14} />
                </button>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  )
}

function AuditRow({
  event,
  expanded,
  onToggle,
}: {
  event: AuditEvent
  expanded: boolean
  onToggle: () => void
}) {
  const actionLabel = getActionLabel(event.action)
  const categoryColor = getCategoryColor(actionLabel.category)

  return (
    <div>
      <button
        onClick={onToggle}
        className="grid w-full grid-cols-[140px_1fr_1fr_1fr_100px] gap-4 px-4 py-3 text-left text-sm hover:bg-zinc-50 transition-colors"
      >
        <span className="text-zinc-500" title={formatDate(event.created_at, "long")}>
          {formatTimeAgo(event.created_at)}
        </span>
        <span className="flex items-center gap-2">
          <span className={`inline-block h-2 w-2 rounded-full ${categoryColor}`} />
          <span className="text-zinc-900">{actionLabel.label}</span>
        </span>
        <span className="text-zinc-600">
          {event.resource_type ?? "—"}
          {event.resource_id && (
            <span className="ml-1 font-mono text-xs text-zinc-400">
              {truncateId(event.resource_id)}
            </span>
          )}
        </span>
        <span className="font-mono text-xs text-zinc-500">
          {event.user_id ? truncateId(event.user_id) : "System"}
        </span>
        <span className="flex items-center justify-between">
          <span className="rounded-full bg-zinc-100 px-2 py-0.5 text-xs font-medium text-zinc-600">
            {SOURCE_LABELS[event.source] ?? event.source}
          </span>
          {expanded ? <CaretUp size={14} className="text-zinc-400" /> : <CaretDown size={14} className="text-zinc-400" />}
        </span>
      </button>
      {expanded && <AuditRowDetail event={event} />}
    </div>
  )
}

function AuditRowDetail({ event }: { event: AuditEvent }) {
  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  return (
    <div className="border-t border-zinc-100 bg-zinc-50 px-4 py-3">
      <div className="grid grid-cols-2 gap-x-8 gap-y-2 text-sm">
        <DetailField label="Event ID" value={event.id} copyable onCopy={copyToClipboard} />
        {event.resource_id && (
          <DetailField label="Resource ID" value={event.resource_id} copyable onCopy={copyToClipboard} />
        )}
        {event.user_id && (
          <DetailField label="Actor ID" value={event.user_id} copyable onCopy={copyToClipboard} />
        )}
        <DetailField label="Timestamp" value={formatDate(event.created_at, "long")} />
        {event.metadata && Object.keys(event.metadata).length > 0 && (
          <div className="col-span-2 mt-2">
            <span className="text-xs font-medium uppercase tracking-wider text-zinc-400">Metadata</span>
            <div className="mt-1 space-y-1">
              {Object.entries(event.metadata).map(([key, value]) => (
                <div key={key} className="flex gap-2 text-sm">
                  <span className="font-mono text-zinc-500">{key}:</span>
                  <span className="font-mono text-zinc-700">
                    {typeof value === "string" ? value : JSON.stringify(value)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

function DetailField({
  label,
  value,
  copyable,
  onCopy,
}: {
  label: string
  value: string
  copyable?: boolean
  onCopy?: (text: string) => void
}) {
  return (
    <div>
      <span className="text-xs font-medium uppercase tracking-wider text-zinc-400">{label}</span>
      <div className="flex items-center gap-1.5 mt-0.5">
        <span className="font-mono text-sm text-zinc-700">{value}</span>
        {copyable && onCopy && (
          <button
            onClick={() => onCopy(value)}
            className="rounded p-0.5 text-zinc-400 hover:text-zinc-600 transition-colors"
            title="Copy"
          >
            <Copy size={12} />
          </button>
        )}
      </div>
    </div>
  )
}
```

**Step 2: Verify build**

Run: `cd dashboard && npx tsc --noEmit`
Expected: no errors

**Step 3: Commit**

```bash
git add dashboard/src/components/audit/audit-log.tsx
git commit -m "feat(dashboard): add AuditLog component with filters, table, and expandable rows"
```

---

### Task 5: Create Audit Page

**Files:**
- Create: `dashboard/src/app/(dashboard)/audit/page.tsx`

**Step 1: Create the page**

```typescript
import { auth } from "@/lib/auth"
import { hasPermission } from "@/lib/permissions"
import { AuditLog } from "@/components/audit/audit-log"
import { ClockCounterClockwise } from "@phosphor-icons/react/dist/ssr"

export default async function AuditPage() {
  const session = await auth()
  const canRead = hasPermission(
    session?.user?.isPlatformAdmin ?? false,
    session?.user?.roles ?? [],
    "audit:read",
  )

  if (!canRead) {
    return (
      <div className="py-12 text-center">
        <p className="text-sm font-medium text-zinc-900">Access denied</p>
        <p className="mt-1 text-sm text-zinc-500">You do not have permission to view audit logs.</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <ClockCounterClockwise size={24} className="text-zinc-400" />
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">Audit Log</h1>
          <p className="mt-1 text-sm text-zinc-500">Track system activities and changes.</p>
        </div>
      </div>
      <AuditLog />
    </div>
  )
}
```

**Step 2: Verify the page renders**

Run: `cd dashboard && npm run build`
Expected: build succeeds with zero errors

**Step 3: Commit**

```bash
git add dashboard/src/app/\(dashboard\)/audit/page.tsx
git commit -m "feat(dashboard): add /audit page with permission gating"
```

---

### Task 6: Fix Nav Permission Gating

**Files:**
- Modify: `dashboard/src/components/nav/sidebar.tsx`

**Step 1: Add `audit:read` permission check**

In `sidebar.tsx`, add a `useCan("audit:read")` check and gate the Audit Log nav item separately from connectors. Replace the TODO comment block.

Change from:
```typescript
const canReadConnectors = useCan("connectors:read")
```

To:
```typescript
const canReadConnectors = useCan("connectors:read")
const canReadAudit = useCan("audit:read")
```

And in the `tenantAdminNav` array, split Audit Log out of the `canReadConnectors` block:

```typescript
const tenantAdminNav = [
  { href: "/", icon: <ChartBar size={20} />, label: "Overview" },
  ...(canReadUsers
    ? [
        { href: "/users", icon: <Users size={20} />, label: "Users" },
        { href: "/departments", icon: <TreeStructure size={20} />, label: "Departments" },
      ]
    : []),
  { href: "/agents", icon: <Robot size={20} />, label: "Agents" },
  ...(canReadConnectors
    ? [
        { href: "/rbac", icon: <ShieldCheck size={20} />, label: "RBAC" },
        { href: "/channels", icon: <ChatCircle size={20} />, label: "Channels" },
        { href: "/connectors", icon: <Plugs size={20} />, label: "Connectors" },
      ]
    : []),
  ...(canReadAudit
    ? [{ href: "/audit", icon: <ClockCounterClockwise size={20} />, label: "Audit Log" }]
    : []),
]
```

Remove the TODO comment about RBAC and Audit Log being gated by `connectors:read`.

**Step 2: Verify build**

Run: `cd dashboard && npx tsc --noEmit`
Expected: no errors

**Step 3: Commit**

```bash
git add dashboard/src/components/nav/sidebar.tsx
git commit -m "fix(dashboard): gate Audit Log nav item by audit:read permission"
```

---

### Task 7: Add Component Tests

**Files:**
- Create: `dashboard/src/components/audit/audit-log.test.tsx`

**Step 1: Write tests**

```typescript
import { describe, it, expect, vi } from "vitest"
import { render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"

// Mock next-auth
vi.mock("next-auth/react", () => ({
  useSession: () => ({
    data: { accessToken: "test-token", user: { isPlatformAdmin: false, roles: [] } },
  }),
}))

// Mock TanStack Query
const mockUseAuditEventsQuery = vi.fn()
vi.mock("@/lib/queries/audit", () => ({
  useAuditEventsQuery: (...args: unknown[]) => mockUseAuditEventsQuery(...args),
}))

import { AuditLog } from "./audit-log"

describe("AuditLog", () => {
  it("shows loading skeletons when loading", () => {
    mockUseAuditEventsQuery.mockReturnValue({
      data: undefined,
      isLoading: true,
      isError: false,
    })

    render(<AuditLog />)
    // Skeletons render as divs with animate-pulse
    const skeletons = document.querySelectorAll('[class*="animate-pulse"]')
    expect(skeletons.length).toBeGreaterThan(0)
  })

  it("shows error state on failure", () => {
    mockUseAuditEventsQuery.mockReturnValue({
      data: undefined,
      isLoading: false,
      isError: true,
    })

    render(<AuditLog />)
    expect(screen.getByText("Failed to load audit events.")).toBeInTheDocument()
  })

  it("shows empty state when no events", () => {
    mockUseAuditEventsQuery.mockReturnValue({
      data: { events: [], count: 0 },
      isLoading: false,
      isError: false,
    })

    render(<AuditLog />)
    expect(screen.getByText("No events recorded yet")).toBeInTheDocument()
  })

  it("renders events in table", () => {
    mockUseAuditEventsQuery.mockReturnValue({
      data: {
        events: [
          {
            id: "evt-1",
            tenant_id: "t-1",
            user_id: "u-1",
            action: "user.created",
            resource_type: "user",
            resource_id: "u-2",
            metadata: { email: "test@example.com" },
            source: "api",
            created_at: new Date().toISOString(),
          },
        ],
        count: 1,
      },
      isLoading: false,
      isError: false,
    })

    render(<AuditLog />)
    expect(screen.getByText("User Created")).toBeInTheDocument()
    expect(screen.getByText("API")).toBeInTheDocument()
    expect(screen.getByText("1 event")).toBeInTheDocument()
  })

  it("expands row to show details on click", async () => {
    const user = userEvent.setup()
    mockUseAuditEventsQuery.mockReturnValue({
      data: {
        events: [
          {
            id: "evt-1",
            tenant_id: "t-1",
            user_id: null,
            action: "tenant.created",
            resource_type: "tenant",
            resource_id: "t-2",
            metadata: { name: "Gondolin FC" },
            source: "api",
            created_at: new Date().toISOString(),
          },
        ],
        count: 1,
      },
      isLoading: false,
      isError: false,
    })

    render(<AuditLog />)
    await user.click(screen.getByText("Tenant Created"))
    expect(screen.getByText("name:")).toBeInTheDocument()
    expect(screen.getByText("Gondolin FC")).toBeInTheDocument()
  })
})
```

**Step 2: Run tests**

Run: `cd dashboard && npx vitest run src/components/audit/audit-log.test.tsx`
Expected: PASS (5 tests)

**Step 3: Commit**

```bash
git add dashboard/src/components/audit/audit-log.test.tsx
git commit -m "test(dashboard): add AuditLog component tests"
```

---

### Task 8: Final Verification

**Step 1: Run all dashboard tests**

Run: `cd dashboard && npx vitest run`
Expected: ALL PASS

**Step 2: Build**

Run: `cd dashboard && npm run build`
Expected: success with zero errors

**Step 3: Run linting**

Run: `cd dashboard && npx tsc --noEmit`
Expected: no errors

**Step 4: Commit any remaining changes**

If any files were auto-formatted or needed adjustment, stage and commit.

---

## Verification Commands

```bash
cd dashboard

# Type check
npx tsc --noEmit

# Unit tests
npx vitest run

# Build
npm run build
```
