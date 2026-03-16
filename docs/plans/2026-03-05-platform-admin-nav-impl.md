# Platform Admin Tenant Navigation Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Allow platform admins to drill into any tenant's resources (read-only) and impersonate tenants in emergencies.

**Architecture:** Nested routes under `/tenants/[id]/...` with a tenant-scoped sidebar layout. Backend exposes path-based `GET /api/v1/tenants/{id}/{resource}` routes gated to platform admins via `RequirePlatformAdmin`. Existing table components get `tenantId` + `readOnly` props. Emergency impersonation issues a short-lived JWT with tenant context.

**Tech Stack:** Go 1.26, Next.js 16 (App Router), TanStack Query v5, Tailwind CSS v4, shadcn/ui, @phosphor-icons/react

---

### Task 1: Backend — Platform Admin Tenant Resource Proxy

Create a generic handler that wraps existing list handlers, extracting the tenant ID from the URL path and setting tenant context.

**Files:**
- Create: `internal/platform/admin/tenant_proxy.go`
- Create: `internal/platform/admin/tenant_proxy_test.go`
- Modify: `internal/platform/server/server.go`
- Modify: `internal/platform/server/dependencies.go` (if it exists, otherwise `server.go`)

**Step 1: Write the failing tests**

Create `internal/platform/admin/tenant_proxy_test.go`:

```go
package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/heimdall-ai/heimdall/internal/auth"
)

func TestTenantProxy_NoPlatformAdmin(t *testing.T) {
	proxy := NewTenantProxy(nil)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := proxy.Wrap(inner)
	req := httptest.NewRequest("GET", "/api/v1/tenants/abc-123/users", nil)
	// No identity — should 401
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestTenantProxy_NonPlatformAdmin(t *testing.T) {
	proxy := NewTenantProxy(nil)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := proxy.Wrap(inner)
	req := httptest.NewRequest("GET", "/api/v1/tenants/abc-123/users", nil)
	identity := &auth.Identity{UserID: "user-1", IsPlatformAdmin: false}
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestTenantProxy_InvalidTenantID(t *testing.T) {
	proxy := NewTenantProxy(nil)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := proxy.Wrap(inner)
	req := httptest.NewRequest("GET", "/api/v1/tenants/not-a-uuid/users", nil)
	identity := &auth.Identity{UserID: "user-1", IsPlatformAdmin: true}
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenantProxy_SetsTenantContext(t *testing.T) {
	proxy := NewTenantProxy(nil)
	var gotTenantID string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTenantID = middleware.GetTenantID(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	tenantID := "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
	handler := proxy.Wrap(inner)
	req := httptest.NewRequest("GET", "/api/v1/tenants/"+tenantID+"/users", nil)
	identity := &auth.Identity{UserID: "user-1", IsPlatformAdmin: true}
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, tenantID, gotTenantID)
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/platform/admin/... -v -count=1`
Expected: FAIL (package doesn't exist yet)

**Step 3: Write the implementation**

Create `internal/platform/admin/tenant_proxy.go`:

```go
package admin

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/heimdall-ai/heimdall/internal/auth"
	"github.com/heimdall-ai/heimdall/internal/platform/middleware"
)

// TenantProxy wraps handlers to extract tenant ID from the URL path
// and set tenant context. Only accessible to platform admins.
type TenantProxy struct {
	pool *pgxpool.Pool
}

func NewTenantProxy(pool *pgxpool.Pool) *TenantProxy {
	return &TenantProxy{pool: pool}
}

// Wrap returns a handler that extracts {id} from /api/v1/tenants/{id}/...
// validates the caller is a platform admin, and sets tenant context.
func (p *TenantProxy) Wrap(inner http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity := auth.GetIdentity(r.Context())
		if identity == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
			return
		}
		if !identity.IsPlatformAdmin {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "platform admin required"})
			return
		}

		tenantID := r.PathValue("id")
		if _, err := uuid.Parse(tenantID); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid tenant ID"})
			return
		}

		ctx := middleware.WithTenantID(r.Context(), tenantID)
		inner.ServeHTTP(w, r.WithContext(ctx))
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/platform/admin/... -v -count=1`
Expected: PASS (4 tests)

**Step 5: Register routes in server.go**

Add to `internal/platform/server/server.go` after existing platform admin routes (around line 171):

```go
// Platform admin tenant drill-down (read-only)
if deps.Pool != nil {
    tenantProxy := admin.NewTenantProxy(deps.Pool)

    if deps.UserHandler != nil {
        protectedMux.Handle("GET /api/v1/tenants/{id}/users",
            tenantProxy.Wrap(http.HandlerFunc(deps.UserHandler.HandleList)),
        )
    }
    if deps.DepartmentHandler != nil {
        protectedMux.Handle("GET /api/v1/tenants/{id}/departments",
            tenantProxy.Wrap(http.HandlerFunc(deps.DepartmentHandler.HandleList)),
        )
    }
    if deps.AgentHandler != nil {
        protectedMux.Handle("GET /api/v1/tenants/{id}/agents",
            tenantProxy.Wrap(http.HandlerFunc(deps.AgentHandler.HandleList)),
        )
    }
    if deps.ChannelHandler != nil {
        protectedMux.Handle("GET /api/v1/tenants/{id}/channels",
            tenantProxy.Wrap(http.HandlerFunc(deps.ChannelHandler.HandleList)),
        )
    }
    if deps.ConnectorHandler != nil {
        protectedMux.Handle("GET /api/v1/tenants/{id}/connectors",
            tenantProxy.Wrap(http.HandlerFunc(deps.ConnectorHandler.HandleList)),
        )
    }
    if deps.RBACHandler != nil {
        protectedMux.Handle("GET /api/v1/tenants/{id}/rbac/roles",
            tenantProxy.Wrap(http.HandlerFunc(deps.RBACHandler.HandleListRoles)),
        )
    }
    if deps.AuditHandler != nil {
        protectedMux.Handle("GET /api/v1/tenants/{id}/audit/events",
            tenantProxy.Wrap(http.HandlerFunc(deps.AuditHandler.HandleListEvents)),
        )
    }
}
```

Add the import: `"github.com/heimdall-ai/heimdall/internal/platform/admin"`

**Step 6: Verify build**

Run: `go build ./...`
Expected: Success

**Step 7: Commit**

```bash
git add internal/platform/admin/ internal/platform/server/server.go
git commit -m "feat: add platform admin tenant resource proxy routes

Read-only GET routes under /api/v1/tenants/{id}/... gated to
platform admins. Extracts tenant ID from path, sets tenant context,
delegates to existing handlers."
```

---

### Task 2: Frontend — TenantContext Provider & Drill-Down Layout

Create a context provider for tenant drill-down pages and a layout with a tenant-scoped sidebar.

**Files:**
- Create: `dashboard/src/components/providers/tenant-drill-context.tsx`
- Create: `dashboard/src/app/(dashboard)/tenants/[id]/(drill)/layout.tsx`
- Create: `dashboard/src/components/nav/tenant-sidebar.tsx`

**Step 1: Create TenantDrillContext provider**

Create `dashboard/src/components/providers/tenant-drill-context.tsx`:

```typescript
"use client"

import { createContext, useContext } from "react"

interface TenantDrillContextValue {
  tenantId: string
  tenantName: string
}

const TenantDrillContext = createContext<TenantDrillContextValue | null>(null)

export function TenantDrillProvider({
  tenantId,
  tenantName,
  children,
}: TenantDrillContextValue & { children: React.ReactNode }) {
  return (
    <TenantDrillContext.Provider value={{ tenantId, tenantName }}>
      {children}
    </TenantDrillContext.Provider>
  )
}

export function useTenantDrill() {
  const ctx = useContext(TenantDrillContext)
  if (!ctx) throw new Error("useTenantDrill must be used within TenantDrillProvider")
  return ctx
}
```

**Step 2: Create TenantSidebar component**

Create `dashboard/src/components/nav/tenant-sidebar.tsx`:

```typescript
"use client"

import Link from "next/link"
import { SidebarItem } from "./sidebar-item"
import {
  ArrowLeft,
  Users,
  TreeStructure,
  ShieldCheck,
  Robot,
  ChatCircle,
  Plugs,
  ClockCounterClockwise,
} from "@phosphor-icons/react"

interface TenantSidebarProps {
  tenantId: string
  tenantName: string
}

export function TenantSidebar({ tenantId, tenantName }: TenantSidebarProps) {
  const base = `/tenants/${tenantId}`

  const items = [
    { href: `${base}/users`, icon: <Users size={20} />, label: "Users" },
    { href: `${base}/departments`, icon: <TreeStructure size={20} />, label: "Departments" },
    { href: `${base}/rbac`, icon: <ShieldCheck size={20} />, label: "RBAC" },
    { href: `${base}/agents`, icon: <Robot size={20} />, label: "Agents" },
    { href: `${base}/channels`, icon: <ChatCircle size={20} />, label: "Channels" },
    { href: `${base}/connectors`, icon: <Plugs size={20} />, label: "Connectors" },
    { href: `${base}/audit`, icon: <ClockCounterClockwise size={20} />, label: "Audit Log" },
  ]

  return (
    <aside className="flex h-full w-60 flex-col border-r border-zinc-200 bg-white">
      <div className="flex h-14 items-center border-b border-zinc-200 px-4">
        <span className="text-lg font-semibold tracking-tight text-zinc-900">Heimdall</span>
      </div>
      <nav className="flex flex-1 flex-col p-3">
        <Link
          href="/tenants"
          className="mb-2 flex items-center gap-2 rounded-lg px-3 py-2 text-sm text-zinc-500 transition-colors hover:bg-zinc-100 hover:text-zinc-900"
        >
          <ArrowLeft size={16} />
          Back to Tenants
        </Link>
        <div className="mb-2 px-3">
          <p className="truncate text-xs font-medium uppercase tracking-wider text-zinc-400">
            {tenantName}
          </p>
        </div>
        <div className="flex flex-col gap-1">
          {items.map((item) => (
            <SidebarItem key={item.href} {...item} />
          ))}
        </div>
      </nav>
    </aside>
  )
}
```

**Step 3: Create drill-down layout**

Create `dashboard/src/app/(dashboard)/tenants/[id]/(drill)/layout.tsx`:

```typescript
import { api } from "@/lib/api"
import { auth } from "@/lib/auth"
import { redirect } from "next/navigation"
import { TenantDrillProvider } from "@/components/providers/tenant-drill-context"
import { TenantSidebar } from "@/components/nav/tenant-sidebar"
import type { Tenant } from "@/lib/types"

export default async function TenantDrillLayout({
  children,
  params,
}: {
  children: React.ReactNode
  params: Promise<{ id: string }>
}) {
  const { id } = await params
  const session = await auth()

  if (!session?.user?.isPlatformAdmin) {
    redirect("/")
  }

  let tenant: Tenant
  try {
    tenant = await api<Tenant>(`/api/v1/tenants/${id}`, {
      headers: { Cookie: "" }, // server-side fetch uses service auth
    })
  } catch {
    redirect("/tenants")
  }

  return (
    <TenantDrillProvider tenantId={id} tenantName={tenant.name}>
      <div className="flex h-screen">
        <TenantSidebar tenantId={id} tenantName={tenant.name} />
        <main className="flex-1 overflow-y-auto p-6">
          <div className="mb-4 rounded-lg border border-amber-200 bg-amber-50 px-4 py-2 text-sm text-amber-800">
            Viewing {tenant.name} — Read only
          </div>
          {children}
        </main>
      </div>
    </TenantDrillProvider>
  )
}
```

**Step 4: Verify dashboard builds**

Run: `cd dashboard && npm run build`
Expected: Success (no pages using the layout yet, but it should compile)

**Step 5: Commit**

```bash
git add dashboard/src/components/providers/tenant-drill-context.tsx \
  dashboard/src/components/nav/tenant-sidebar.tsx \
  "dashboard/src/app/(dashboard)/tenants/[id]/(drill)/layout.tsx"
git commit -m "feat: add tenant drill-down layout with scoped sidebar

TenantDrillProvider context, TenantSidebar with back link and
sub-nav items, and layout with read-only banner. Platform admin
only — redirects non-admins."
```

---

### Task 3: Frontend — Update Query Hooks for Cross-Tenant Fetching

Modify query hooks to accept an optional `tenantId` that routes API calls to `/api/v1/tenants/{id}/...`.

**Files:**
- Modify: `dashboard/src/lib/queries/users.ts`
- Modify: `dashboard/src/lib/queries/agents.ts`
- Modify: `dashboard/src/lib/queries/tenants.ts` (if department/channel queries are here, otherwise their respective files)

**Step 1: Update user query hooks**

In `dashboard/src/lib/queries/users.ts`, modify the key factory and fetch function:

```typescript
export const userKeys = {
  all: ["users"] as const,
  list: (tenantId?: string) => [...userKeys.all, "list", tenantId ?? "self"] as const,
  detail: (id: string) => [...userKeys.all, "detail", id] as const,
  userDepartments: (id: string) => [...userKeys.all, "departments", id] as const,
}

export async function fetchUsers(params?: Record<string, string>, tenantId?: string) {
  const path = tenantId
    ? `/api/v1/tenants/${tenantId}/users`
    : "/api/v1/users"
  return apiClient<User[]>(path, { params })
}

export function useUsersQuery(tenantId?: string) {
  const { data: session } = useSession()
  return useQuery({
    queryKey: userKeys.list(tenantId),
    queryFn: () => fetchUsers(undefined, tenantId),
    enabled: !!session,
    staleTime: 30_000,
  })
}
```

Apply the same pattern to agents, departments, channels, connectors, audit, and RBAC query hooks. Each gets:
- `tenantId` param in the key factory `list()` call
- `tenantId` param in the fetch function that switches the API path
- `tenantId` param in the hook

**Step 2: Verify dashboard builds**

Run: `cd dashboard && npm run build`
Expected: Success (existing call sites pass no `tenantId`, so behavior unchanged)

**Step 3: Commit**

```bash
git add dashboard/src/lib/queries/
git commit -m "feat: add tenantId param to query hooks for cross-tenant fetching

When tenantId is provided, API calls route to
/api/v1/tenants/{id}/{resource} instead of /api/v1/{resource}.
Existing call sites unchanged (pass no tenantId)."
```

---

### Task 4: Frontend — Add readOnly + tenantId Props to Table Components

Update existing table components to accept `tenantId` and `readOnly` props.

**Files:**
- Modify: `dashboard/src/components/users/user-table.tsx`
- Modify: `dashboard/src/components/agents/agent-table.tsx` (or similar)
- Modify: similar table components for departments, channels, connectors

**Step 1: Update UserTable**

In `dashboard/src/components/users/user-table.tsx`, add props:

```typescript
interface UserTableProps {
  tenantId?: string
  readOnly?: boolean
  basePath?: string // for links, e.g. "/tenants/abc/users" instead of "/users"
}

export function UserTable({ tenantId, readOnly, basePath = "/users" }: UserTableProps) {
  const { data: users, isLoading, isError } = useUsersQuery(tenantId)
  // ...existing filter/search logic...

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        {/* existing search input */}
        {!readOnly && (
          <Link href={`${basePath}/new`} className="...">
            <Plus size={16} />
            Create user
          </Link>
        )}
      </div>
      {/* existing table rendering, update links to use basePath */}
      {filteredUsers.map((user) => (
        <Link key={user.id} href={`${basePath}/${user.id}`}>
          {/* ...existing row content... */}
        </Link>
      ))}
    </div>
  )
}
```

Apply the same pattern to AgentTable, DepartmentTable, ChannelTable, ConnectorTable. Each gets:
- `tenantId?: string` — passed to the query hook
- `readOnly?: boolean` — hides create/edit/delete UI
- `basePath?: string` — customizes link destinations

**Step 2: Verify existing pages still work**

Run: `cd dashboard && npm run build`
Expected: Success (existing pages pass no props, defaults apply)

**Step 3: Commit**

```bash
git add dashboard/src/components/
git commit -m "feat: add tenantId, readOnly, basePath props to table components

Existing pages pass no props (defaults). Drill-down pages will
pass tenantId for cross-tenant queries, readOnly to hide mutations,
and basePath to scope links."
```

---

### Task 5: Frontend — Create Drill-Down Pages

Create the route pages under `/tenants/[id]/(drill)/` that render the existing table components with drill-down props.

**Files:**
- Create: `dashboard/src/app/(dashboard)/tenants/[id]/(drill)/users/page.tsx`
- Create: `dashboard/src/app/(dashboard)/tenants/[id]/(drill)/departments/page.tsx`
- Create: `dashboard/src/app/(dashboard)/tenants/[id]/(drill)/agents/page.tsx`
- Create: `dashboard/src/app/(dashboard)/tenants/[id]/(drill)/channels/page.tsx`
- Create: `dashboard/src/app/(dashboard)/tenants/[id]/(drill)/connectors/page.tsx`
- Create: `dashboard/src/app/(dashboard)/tenants/[id]/(drill)/rbac/page.tsx`
- Create: `dashboard/src/app/(dashboard)/tenants/[id]/(drill)/audit/page.tsx`

**Step 1: Create the users drill-down page**

Create `dashboard/src/app/(dashboard)/tenants/[id]/(drill)/users/page.tsx`:

```typescript
import { UserTable } from "@/components/users/user-table"

export default async function TenantUsersPage({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  const { id } = await params

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">Users</h1>
        <p className="mt-1 text-sm text-zinc-500">Users in this tenant.</p>
      </div>
      <UserTable tenantId={id} readOnly basePath={`/tenants/${id}/users`} />
    </div>
  )
}
```

**Step 2: Create remaining pages**

Same pattern for each resource — only the component, title, and path change:

| Page | Component | Title |
|------|-----------|-------|
| `departments/page.tsx` | `<DepartmentTable>` | "Departments" |
| `agents/page.tsx` | `<AgentTable>` | "Agents" |
| `channels/page.tsx` | `<ChannelTable>` | "Channels" |
| `connectors/page.tsx` | `<ConnectorTable>` | "Connectors" |
| `rbac/page.tsx` | `<RBACTable>` (or `<RoleList>`) | "Roles & Permissions" |
| `audit/page.tsx` | `<RecentEvents>` | "Audit Log" |

Each passes `tenantId={id} readOnly basePath={/tenants/${id}/{resource}}`.

**Step 3: Verify dashboard builds**

Run: `cd dashboard && npm run build`
Expected: Success

**Step 4: Commit**

```bash
git add "dashboard/src/app/(dashboard)/tenants/[id]/(drill)/"
git commit -m "feat: add tenant drill-down pages for all resources

Seven pages under /tenants/[id]/ rendering existing table
components with tenantId, readOnly, and basePath props."
```

---

### Task 6: Frontend — Make Tenant Detail Stats Clickable

Update the existing tenant detail page so stat cards link to the drill-down sub-pages.

**Files:**
- Modify: `dashboard/src/components/tenants/tenant-detail.tsx`

**Step 1: Update stat cards to be links**

In `dashboard/src/components/tenants/tenant-detail.tsx`, wrap each stat card in a `<Link>`:

```typescript
import Link from "next/link"

// In the stats grid section, replace static cards with links:
const stats = [
  { label: "Users", value: tenant.user_count ?? 0, href: `/tenants/${id}/users` },
  { label: "Departments", value: tenant.department_count ?? 0, href: `/tenants/${id}/departments` },
  { label: "Agents", value: tenant.agent_count ?? 0, href: `/tenants/${id}/agents` },
  { label: "Connectors", value: tenant.connector_count ?? 0, href: `/tenants/${id}/connectors` },
]

// Render:
{stats.map((stat) => (
  <Link
    key={stat.label}
    href={stat.href}
    className="rounded-xl border border-zinc-200 bg-white p-4 transition-colors hover:border-zinc-300 hover:bg-zinc-50"
  >
    <p className="text-sm text-zinc-500">{stat.label}</p>
    <p className="mt-1 text-2xl font-semibold text-zinc-900">{stat.value}</p>
  </Link>
))}
```

**Step 2: Verify dashboard builds**

Run: `cd dashboard && npm run build`
Expected: Success

**Step 3: Commit**

```bash
git add dashboard/src/components/tenants/tenant-detail.tsx
git commit -m "feat: make tenant detail stats clickable into drill-down pages"
```

---

### Task 7: Backend — Impersonation Endpoint

Add `POST /api/v1/tenants/{id}/impersonate` that issues a short-lived JWT scoped to the target tenant.

**Files:**
- Create: `internal/platform/admin/impersonate.go`
- Create: `internal/platform/admin/impersonate_test.go`
- Modify: `internal/platform/server/server.go`

**Step 1: Write the failing tests**

Create `internal/platform/admin/impersonate_test.go`:

```go
package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/heimdall-ai/heimdall/internal/auth"
)

func TestHandleImpersonate_NotPlatformAdmin(t *testing.T) {
	h := NewImpersonateHandler(nil, nil)
	req := httptest.NewRequest("POST", "/api/v1/tenants/abc/impersonate", nil)
	identity := &auth.Identity{UserID: "user-1", IsPlatformAdmin: false}
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	w := httptest.NewRecorder()

	h.Handle(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestHandleImpersonate_InvalidTenantID(t *testing.T) {
	h := NewImpersonateHandler(nil, nil)
	req := httptest.NewRequest("POST", "/api/v1/tenants/not-a-uuid/impersonate", nil)
	identity := &auth.Identity{UserID: "user-1", IsPlatformAdmin: true}
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	w := httptest.NewRecorder()

	h.Handle(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/platform/admin/... -run TestHandleImpersonate -v -count=1`
Expected: FAIL

**Step 3: Write the implementation**

Create `internal/platform/admin/impersonate.go`:

```go
package admin

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/heimdall-ai/heimdall/internal/auth"
)

type ImpersonateHandler struct {
	tokenSvc *auth.TokenService
	pool     interface{} // *pgxpool.Pool — used for tenant validation
}

func NewImpersonateHandler(tokenSvc *auth.TokenService, pool interface{}) *ImpersonateHandler {
	return &ImpersonateHandler{tokenSvc: tokenSvc, pool: pool}
}

type impersonateResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	TenantID    string `json:"tenant_id"`
	TenantName  string `json:"tenant_name"`
}

func (h *ImpersonateHandler) Handle(w http.ResponseWriter, r *http.Request) {
	identity := auth.GetIdentity(r.Context())
	if identity == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}
	if !identity.IsPlatformAdmin {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "platform admin required"})
		return
	}

	tenantID := r.PathValue("id")
	if _, err := uuid.Parse(tenantID); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid tenant ID"})
		return
	}

	// TODO: validate tenant exists via pool query
	// TODO: generate short-lived JWT with tenantID, org_admin roles, 30min TTL
	// TODO: audit log the impersonation event

	slog.Warn("platform admin impersonation",
		"impersonator_id", identity.UserID,
		"target_tenant_id", tenantID,
	)

	// Placeholder — full implementation depends on TokenService.GenerateImpersonationToken
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error": fmt.Sprintf("impersonation for tenant %s not yet wired", tenantID),
	})
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/platform/admin/... -run TestHandleImpersonate -v -count=1`
Expected: PASS (2 tests)

**Step 5: Register route in server.go**

Add after the tenant proxy routes:

```go
// Emergency impersonation
if deps.TokenSvc != nil && deps.Pool != nil {
    impersonateHandler := admin.NewImpersonateHandler(deps.TokenSvc, deps.Pool)
    protectedMux.Handle("POST /api/v1/tenants/{id}/impersonate",
        auth.RequirePlatformAdmin(http.HandlerFunc(impersonateHandler.Handle)),
    )
}
```

**Step 6: Verify build**

Run: `go build ./...`
Expected: Success

**Step 7: Commit**

```bash
git add internal/platform/admin/impersonate.go \
  internal/platform/admin/impersonate_test.go \
  internal/platform/server/server.go
git commit -m "feat: add impersonation endpoint scaffold (POST /api/v1/tenants/{id}/impersonate)

Platform admin only. Validates identity and tenant ID. Full JWT
generation and audit logging to be wired in follow-up."
```

---

### Task 8: Frontend — Impersonation UI

Add the "Enter Tenant" button, confirmation dialog, red banner, and exit flow.

**Files:**
- Create: `dashboard/src/components/tenants/impersonation-banner.tsx`
- Modify: `dashboard/src/components/tenants/tenant-detail.tsx`
- Modify: `dashboard/src/app/(dashboard)/layout.tsx`

**Step 1: Create impersonation banner**

Create `dashboard/src/components/tenants/impersonation-banner.tsx`:

```typescript
"use client"

import { useRouter } from "next/navigation"
import { Warning } from "@phosphor-icons/react"

interface ImpersonationBannerProps {
  tenantName: string
  onExit: () => void
}

export function ImpersonationBanner({ tenantName, onExit }: ImpersonationBannerProps) {
  return (
    <div className="flex items-center justify-between bg-red-600 px-4 py-2 text-sm text-white">
      <div className="flex items-center gap-2">
        <Warning size={16} weight="fill" />
        <span>
          Impersonating <strong>{tenantName}</strong> — Emergency access
        </span>
      </div>
      <button
        onClick={onExit}
        className="rounded border border-red-400 px-3 py-1 text-xs font-medium transition-colors hover:bg-red-700"
      >
        Exit
      </button>
    </div>
  )
}
```

**Step 2: Add "Enter Tenant" button to tenant detail**

In `dashboard/src/components/tenants/tenant-detail.tsx`, add after the header section:

```typescript
import { Warning } from "@phosphor-icons/react"

// In the header area, add:
<button
  onClick={() => setShowImpersonateDialog(true)}
  className="flex items-center gap-2 rounded-lg border border-red-200 bg-red-50 px-4 py-2 text-sm font-medium text-red-700 transition-colors hover:bg-red-100"
>
  <Warning size={16} />
  Enter Tenant
</button>

// Add confirmation dialog:
{showImpersonateDialog && (
  <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
    <div className="w-full max-w-md rounded-xl bg-white p-6 shadow-xl">
      <h3 className="text-lg font-semibold text-zinc-900">Emergency Access</h3>
      <p className="mt-2 text-sm text-zinc-600">
        You are about to enter <strong>{tenant.name}</strong> with full admin
        privileges. All actions will be logged in the audit trail.
      </p>
      <div className="mt-6 flex justify-end gap-3">
        <button
          onClick={() => setShowImpersonateDialog(false)}
          className="rounded-lg px-4 py-2 text-sm text-zinc-600 hover:bg-zinc-100"
        >
          Cancel
        </button>
        <button
          onClick={handleImpersonate}
          className="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-700"
        >
          Enter Tenant
        </button>
      </div>
    </div>
  </div>
)}
```

**Step 3: Verify dashboard builds**

Run: `cd dashboard && npm run build`
Expected: Success

**Step 4: Commit**

```bash
git add dashboard/src/components/tenants/impersonation-banner.tsx \
  dashboard/src/components/tenants/tenant-detail.tsx \
  dashboard/src/app/(dashboard)/layout.tsx
git commit -m "feat: add impersonation UI — Enter Tenant button, confirmation dialog, red banner

Emergency access flow with warning dialog and persistent red
banner during impersonation. Exit button drops session."
```

---

### Task 9: End-to-End Verification

**Step 1: Start backend**

Run: `go run ./cmd/heimdall`

**Step 2: Start dashboard**

Run: `cd dashboard && npm run dev`

**Step 3: Manual test — drill-down**

1. Login as `turgon@gondolin.fc` (platform admin)
2. Navigate to Tenants → click "Gondolin FC"
3. Click "Users" stat card → should navigate to `/tenants/{id}/users`
4. Sidebar should show tenant sub-nav with "← Back to Tenants"
5. "Read only" banner should be visible
6. User table should load with no create/edit buttons
7. Click "← Back to Tenants" → should return to `/tenants`

**Step 4: Manual test — API security**

```bash
# As non-platform-admin, try tenant drill-down API
curl -H "Authorization: Bearer $NON_ADMIN_TOKEN" \
  http://localhost:8080/api/v1/tenants/$TENANT_ID/users
# Expected: 403 Forbidden

# As platform admin, try tenant drill-down API
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:8080/api/v1/tenants/$TENANT_ID/users
# Expected: 200 with user list
```

**Step 5: Commit any final fixes**

```bash
git add -A
git commit -m "fix: address issues found during e2e verification"
```
