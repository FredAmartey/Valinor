# Overview Page UX — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the admin-only "Platform Overview" with a unified, role-adaptive overview page that shows each user role appropriate content — warm greeting, relevant stat cards, and a personal or org-wide activity feed.

**Architecture:** The SSR page (`page.tsx`) reads session data and passes role/permissions info to a new `Overview` component. The component conditionally renders stat cards and activity feeds based on role. A new Go endpoint `GET /api/v1/me/activity` returns the current user's own audit events without RBAC gating.

**Tech Stack:** Next.js 16 (App Router), React, TanStack Query v5, Tailwind CSS v4, Go 1.22, PostgreSQL (pgx/v5)

**Design doc:** `docs/plans/2026-03-05-overview-page-ux-design.md`

---

### Task 1: Add `GET /api/v1/me/activity` handler (Go backend)

**Files:**
- Create: `internal/audit/my_activity_handler.go`
- Modify: `internal/platform/server/server.go:318-325`
- Modify: `cmd/valinor/main.go` (if handler needs wiring)

**Step 1: Create the handler file**

Create `internal/audit/my_activity_handler.go`:

```go
package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/platform/database"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
)

// HandleMyActivity returns audit events for the authenticated user only.
// GET /api/v1/me/activity?limit=10
func (h *Handler) HandleMyActivity(w http.ResponseWriter, r *http.Request) {
	identity := auth.GetIdentity(r.Context())
	if identity == nil {
		writeAuditJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	tenantIDStr := middleware.GetTenantID(r.Context())
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		writeAuditJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid tenant context"})
		return
	}

	userID, err := uuid.Parse(identity.UserID)
	if err != nil {
		writeAuditJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid user identity"})
		return
	}

	limit := 10
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, parseErr := strconv.Atoi(raw); parseErr == nil && n > 0 && n <= 50 {
			limit = n
		}
	}

	params := ListEventsParams{
		TenantID: tenantID,
		UserID:   &userID,
		Limit:    limit,
	}

	if h.pool == nil {
		writeAuditJSON(w, http.StatusOK, map[string]any{"events": []any{}, "count": 0})
		return
	}

	var events []map[string]any
	queryErr := database.WithTenantConnection(r.Context(), h.pool, tenantIDStr, func(ctx context.Context, q database.Querier) error {
		sql, args := buildListQuery(params)
		rows, qErr := q.Query(ctx, sql, args...)
		if qErr != nil {
			return qErr
		}
		defer rows.Close()

		for rows.Next() {
			var (
				id, tid    uuid.UUID
				uid, resID *uuid.UUID
				action     string
				resType    *string
				metadata   json.RawMessage
				source     string
				createdAt  time.Time
			)
			if scanErr := rows.Scan(&id, &tid, &uid, &action, &resType, &resID, &metadata, &source, &createdAt); scanErr != nil {
				slog.Warn("skipping audit event: scan error", "error", scanErr)
				continue
			}
			events = append(events, map[string]any{
				"id":            id,
				"tenant_id":     tid,
				"user_id":       uid,
				"action":        action,
				"resource_type": resType,
				"resource_id":   resID,
				"metadata":      metadata,
				"source":        source,
				"created_at":    createdAt,
			})
		}
		return nil
	})

	if queryErr != nil {
		writeAuditJSON(w, http.StatusInternalServerError, map[string]string{"error": "query failed"})
		return
	}

	if events == nil {
		events = []map[string]any{}
	}

	writeAuditJSON(w, http.StatusOK, map[string]any{"events": events, "count": len(events)})
}
```

**Step 2: Register the route**

In `internal/platform/server/server.go`, add after the audit routes block (after line 325):

```go
// My activity (authenticated, no RBAC — scoped to own user)
if deps.AuditHandler != nil {
    protectedMux.HandleFunc("GET /api/v1/me/activity",
        deps.AuditHandler.HandleMyActivity,
    )
}
```

Note: No RBAC middleware — the handler scopes to the authenticated user's own data.

**Step 3: Verify Go builds**

Run: `cd /Users/fred/Documents/Valinor && go build ./...`
Expected: No errors.

**Step 4: Commit**

```bash
git add internal/audit/my_activity_handler.go internal/platform/server/server.go
git commit -m "feat: add GET /api/v1/me/activity endpoint for personal activity feed"
```

---

### Task 2: Rename `PlatformOverview` to `Overview` and make role-adaptive

**Files:**
- Create: `dashboard/src/components/overview/overview.tsx` (new file, replacing platform-overview.tsx)
- Modify: `dashboard/src/app/(dashboard)/page.tsx`

**Step 1: Create the new Overview component**

Create `dashboard/src/components/overview/overview.tsx`:

```tsx
"use client"

import { useQuery } from "@tanstack/react-query"
import { apiClient } from "@/lib/api-client"
import { useCan } from "@/components/providers/permission-provider"
import { tenantKeys } from "@/lib/queries/tenants"
import { agentKeys, fetchAgents } from "@/lib/queries/agents"
import { StatCard } from "./stat-card"
import { RecentEvents } from "./recent-events"
import { Skeleton } from "@/components/ui/skeleton"
import { Buildings, Robot, Warning, Users, ChatCircle, Heartbeat } from "@phosphor-icons/react"
import type { Tenant, AgentInstance } from "@/lib/types"

interface OverviewProps {
  userName: string
  isPlatformAdmin: boolean
  hasTenant: boolean
  initialTenants: Tenant[]
  initialAgents: AgentInstance[]
}

function getSubtitle(isPlatformAdmin: boolean, canReadUsers: boolean): string {
  if (isPlatformAdmin) return "Platform health and activity across all tenants."
  if (canReadUsers) return "Here\u2019s what\u2019s happening in your organization."
  return "Here\u2019s what\u2019s happening with your agents."
}

export function Overview({
  userName,
  isPlatformAdmin,
  hasTenant,
  initialTenants,
  initialAgents,
}: OverviewProps) {
  const canReadUsers = useCan("users:read")
  const canReadAudit = useCan("audit:read")
  const canReadConnectors = useCan("connectors:read")

  const { data: tenants, isLoading: tenantsLoading } = useQuery({
    queryKey: tenantKeys.list(),
    queryFn: () => apiClient<Tenant[]>("/api/v1/tenants"),
    initialData: initialTenants,
    refetchInterval: 30_000,
    enabled: isPlatformAdmin,
  })

  const { data: agentData, isLoading: agentsLoading } = useQuery({
    queryKey: agentKeys.list(),
    queryFn: () => fetchAgents(),
    initialData: { agents: initialAgents },
    refetchInterval: 30_000,
  })

  const agents = agentData?.agents ?? []
  const firstName = userName.split(" ")[0] || userName

  const statCards = buildStatCards({
    isPlatformAdmin,
    canReadUsers,
    canReadConnectors,
    tenants: tenants ?? [],
    agents,
  })

  const isLoading = (isPlatformAdmin && tenantsLoading) || agentsLoading

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">
          Welcome back, {firstName}
        </h1>
        <p className="mt-1 text-sm text-zinc-500">
          {getSubtitle(isPlatformAdmin, canReadUsers)}
        </p>
      </div>

      {isLoading ? (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
          {Array.from({ length: statCards.length || 2 }).map((_, i) => (
            <Skeleton key={i} className="h-28 rounded-xl" />
          ))}
        </div>
      ) : (
        <div className={`grid grid-cols-1 gap-4 md:grid-cols-2 ${statCards.length > 2 ? "xl:grid-cols-4" : ""}`}>
          {statCards.map((card) => (
            <StatCard key={card.label} {...card} />
          ))}
        </div>
      )}

      <div className={isPlatformAdmin ? "grid grid-cols-1 gap-6 xl:grid-cols-[2fr_1fr]" : ""}>
        <div>
          <h2 className="mb-3 text-sm font-medium text-zinc-900">Recent Activity</h2>
          <div className="rounded-xl border border-zinc-200 bg-white p-4">
            <RecentEvents canReadAudit={canReadAudit} hasTenant={hasTenant} />
          </div>
        </div>
        {isPlatformAdmin && (
          <div>
            <h2 className="mb-3 text-sm font-medium text-zinc-900">Quick Stats</h2>
            <div className="rounded-xl border border-zinc-200 bg-white p-4">
              <div className="space-y-3 text-sm">
                <div className="flex justify-between">
                  <span className="text-zinc-500">Suspended Tenants</span>
                  <span className="font-mono text-zinc-900">
                    {tenants?.filter((t) => t.status === "suspended").length ?? 0}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-zinc-500">Archived Tenants</span>
                  <span className="font-mono text-zinc-900">
                    {tenants?.filter((t) => t.status === "archived").length ?? 0}
                  </span>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

function buildStatCards({
  isPlatformAdmin,
  canReadUsers,
  canReadConnectors,
  tenants,
  agents,
}: {
  isPlatformAdmin: boolean
  canReadUsers: boolean
  canReadConnectors: boolean
  tenants: Tenant[]
  agents: AgentInstance[]
}) {
  const totalAgents = agents.length
  const healthyAgents = agents.filter((a) => a.status === "running" || a.status === "warm").length
  const unhealthyAgents = agents.filter((a) => a.status === "unhealthy").length

  if (isPlatformAdmin) {
    const activeTenants = tenants.filter((t) => t.status === "active").length
    return [
      { label: "Total Tenants", value: tenants.length, icon: <Buildings size={20} /> },
      { label: "Active Tenants", value: activeTenants, icon: <Buildings size={20} /> },
      { label: "Running Agents", value: totalAgents, icon: <Robot size={20} /> },
      { label: "Unhealthy Agents", value: unhealthyAgents, icon: <Warning size={20} /> },
    ]
  }

  if (canReadUsers) {
    // org_admin / dept_head — show broader stats
    return [
      { label: "Running Agents", value: totalAgents, icon: <Robot size={20} /> },
      { label: "Unhealthy Agents", value: unhealthyAgents, icon: <Warning size={20} /> },
      ...(canReadUsers ? [{ label: "Total Users", value: "—", icon: <Users size={20} /> }] : []),
      ...(canReadConnectors ? [{ label: "Active Channels", value: "—", icon: <ChatCircle size={20} /> }] : []),
    ]
  }

  // standard_user / read_only
  return [
    { label: "Running Agents", value: totalAgents, icon: <Robot size={20} /> },
    { label: "Agents Online", value: healthyAgents, icon: <Heartbeat size={20} /> },
  ]
}
```

Note: The "Total Users" and "Active Channels" cards show "—" for now. These require SSR data fetching that we can add later when the user/channel list endpoints are available on the overview. This keeps the layout correct without adding unnecessary API calls.

**Step 2: Update the page to use Overview**

Replace `dashboard/src/app/(dashboard)/page.tsx`:

```tsx
import { api } from "@/lib/api"
import { auth } from "@/lib/auth"
import { Overview } from "@/components/overview/overview"
import type { Tenant, AgentInstance } from "@/lib/types"

export default async function OverviewPage() {
  const session = await auth()
  const isPlatformAdmin = session?.user?.isPlatformAdmin ?? false

  const [tenants, agents] = await Promise.all([
    isPlatformAdmin
      ? api<Tenant[]>("/api/v1/tenants").catch(() => [] as Tenant[])
      : ([] as Tenant[]),
    api<{ agents: AgentInstance[] }>("/api/v1/agents")
      .then((r) => r.agents)
      .catch((err) => {
        console.error("Failed to fetch agents for overview SSR:", err)
        return [] as AgentInstance[]
      }),
  ])

  return (
    <Overview
      userName={session?.user?.name ?? ""}
      isPlatformAdmin={isPlatformAdmin}
      hasTenant={!!session?.user?.tenantId}
      initialTenants={tenants}
      initialAgents={agents}
    />
  )
}
```

**Step 3: Verify the build**

Run: `cd /Users/fred/Documents/Valinor/dashboard && npm run build`
Expected: Builds with no errors. The old `platform-overview.tsx` is no longer imported.

**Step 4: Commit**

```bash
git add dashboard/src/components/overview/overview.tsx dashboard/src/app/\(dashboard\)/page.tsx
git commit -m "feat: replace PlatformOverview with role-adaptive Overview component"
```

---

### Task 3: Update RecentEvents to support personal activity feed

**Files:**
- Modify: `dashboard/src/components/overview/recent-events.tsx`

**Step 1: Update RecentEvents to accept props and switch data source**

Replace `dashboard/src/components/overview/recent-events.tsx`:

```tsx
"use client"

import { useQuery } from "@tanstack/react-query"
import { apiClient } from "@/lib/api-client"
import { ApiError } from "@/lib/api-error"
import { Skeleton } from "@/components/ui/skeleton"
import { formatTimeAgo } from "@/lib/format"
import type { AuditEvent } from "@/lib/types"

interface RecentEventsProps {
  canReadAudit: boolean
  hasTenant: boolean
}

export function RecentEvents({ canReadAudit, hasTenant }: RecentEventsProps) {
  const endpoint = canReadAudit ? "/api/v1/audit/events" : "/api/v1/me/activity"
  const queryKey = canReadAudit ? ["audit", "recent"] : ["me", "activity"]

  const { data: events, isLoading, isError, error } = useQuery({
    queryKey,
    queryFn: () =>
      apiClient<{ count: number; events: AuditEvent[] }>(endpoint, {
        params: { limit: "10" },
      }),
    select: (data) => data.events,
    enabled: hasTenant,
    refetchInterval: 30_000,
    retry: (failureCount, err) => {
      if (err instanceof ApiError && (err.status === 403 || err.status === 401)) return false
      return failureCount < 3
    },
  })

  if (!hasTenant) {
    return (
      <div className="py-8 text-center">
        <p className="text-sm text-zinc-500">No activity to show yet.</p>
      </div>
    )
  }

  if (isLoading) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-10 w-full" />
        ))}
      </div>
    )
  }

  if (isError && error instanceof ApiError && (error.status === 403 || error.status === 401)) {
    return (
      <div className="py-8 text-center">
        <p className="text-sm text-zinc-500">No activity to show yet.</p>
      </div>
    )
  }

  if (isError) {
    return (
      <p className="text-sm text-zinc-500">Failed to load recent activity.</p>
    )
  }

  if (!events || events.length === 0) {
    return (
      <div className="py-8 text-center">
        <p className="text-sm text-zinc-500">No activity recorded yet.</p>
        <p className="mt-1 text-xs text-zinc-400">
          Activity appears here as you interact with the platform.
        </p>
      </div>
    )
  }

  return (
    <div className="divide-y divide-zinc-100">
      {events.map((event) => (
        <div key={event.id} className="flex items-center justify-between py-2.5">
          <div className="flex items-center gap-3">
            <span className="text-sm font-medium text-zinc-900">{event.action}</span>
            {event.resource_type && (
              <span className="text-xs text-zinc-400">{event.resource_type}</span>
            )}
          </div>
          <span className="text-xs text-zinc-400 font-mono">
            {formatTimeAgo(event.created_at)}
          </span>
        </div>
      ))}
    </div>
  )
}
```

Key changes:
- Accepts `canReadAudit` and `hasTenant` props
- Switches between `/api/v1/audit/events` (org-wide) and `/api/v1/me/activity` (personal)
- Different query keys for cache separation
- Graceful empty states instead of permission error messages

**Step 2: Verify the build**

Run: `cd /Users/fred/Documents/Valinor/dashboard && npm run build`
Expected: Builds with no errors.

**Step 3: Commit**

```bash
git add dashboard/src/components/overview/recent-events.tsx
git commit -m "feat: switch RecentEvents between org-wide audit and personal activity feed"
```

---

### Task 4: Clean up old PlatformOverview

**Files:**
- Delete: `dashboard/src/components/overview/platform-overview.tsx`

**Step 1: Verify no other imports reference the old file**

Run: `grep -r "platform-overview" /Users/fred/Documents/Valinor/dashboard/src/`
Expected: No matches (page.tsx was updated in Task 2).

**Step 2: Delete the old file**

```bash
rm dashboard/src/components/overview/platform-overview.tsx
```

**Step 3: Verify build**

Run: `cd /Users/fred/Documents/Valinor/dashboard && npm run build`
Expected: Builds with no errors.

**Step 4: Commit**

```bash
git add -u dashboard/src/components/overview/platform-overview.tsx
git commit -m "chore: remove old PlatformOverview component"
```

---

### Task 5: Verify end-to-end

**Step 1: Start Go backend**

Run: `cd /Users/fred/Documents/Valinor && go run ./cmd/valinor`

**Step 2: Start dashboard**

Run: `cd /Users/fred/Documents/Valinor/dashboard && npm run dev`

**Step 3: Test as platform admin**

1. Go to `http://localhost:3000/login`
2. Sign in as `turgon@gondolin.fc`
3. Verify: heading says "Welcome back, Turgon", subtitle says "Platform health and activity across all tenants."
4. Verify: 4 stat cards — Total Tenants, Active Tenants, Running Agents, Unhealthy Agents
5. Verify: Recent Activity shows org-wide audit events
6. Verify: Quick Stats panel shows Suspended/Archived tenant counts

**Step 4: Test as standard user**

1. Sign out, sign in as `glorfindel@gondolin.fc`
2. Verify: heading says "Welcome back, Glorfindel", subtitle says "Here's what's happening with your agents."
3. Verify: 2 stat cards — Running Agents, Agents Online
4. Verify: Recent Activity calls `/api/v1/me/activity` (check Network tab)
5. Verify: No Quick Stats panel
6. Verify: No tenant-related data visible

**Step 5: Test as dept_head**

1. Sign out, sign in as `ecthelion@gondolin.fc`
2. Verify: heading says "Welcome back, Ecthelion", subtitle says "Here's what's happening in your organization."
3. Verify: stat cards include Running Agents, Unhealthy Agents, Total Users, Active Channels
4. Verify: Recent Activity shows org-wide audit events (dept_head has `audit:read`)

**Step 6: Commit final state if any adjustments were needed**

```bash
git add -A
git commit -m "fix: adjustments from end-to-end verification"
```
