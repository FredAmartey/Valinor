# Phase 9 Dashboard Slice 1 — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Deliver the Valinor admin dashboard shell with auth, overview dashboard, and tenant management views.

**Architecture:** Separate Next.js 15 process in `dashboard/` talking to the Valinor Go API over HTTP. Server Components by default, `"use client"` only for interactive leaves. TanStack Query for client-side server state, NextAuth.js v5 for auth wrapping Valinor's OIDC flow.

**Tech Stack:** Next.js 15 (App Router), TypeScript (strict), Tailwind CSS v4, shadcn/ui, TanStack Query v5, NextAuth.js v5 (beta), Geist font, @phosphor-icons/react, Vitest, Playwright

**Skills to follow during implementation:**
- `design-taste-frontend` — UI engineering rules (DESIGN_VARIANCE: 8, MOTION_INTENSITY: 6, VISUAL_DENSITY: 4)
- `vercel-react-best-practices` — 57 React/Next.js performance rules (see `~/.claude/skills/vercel-react-best-practices/rules/`)

**Design doc:** `docs/plans/2026-02-24-phase9-admin-dashboard-design.md`

---

## Task 1: Scaffold Next.js Project

**Files:**
- Create: `dashboard/` (entire directory via create-next-app)
- Modify: `dashboard/tsconfig.json` (enable strict mode)
- Modify: `dashboard/src/app/globals.css` (Tailwind v4 theme)
- Modify: `dashboard/src/app/layout.tsx` (Geist font variables)

**Step 1: Create the Next.js project**

Run from repo root:

```bash
cd /Users/fred/Documents/Valinor
npx create-next-app@latest dashboard --yes
```

Expected: Project created at `dashboard/` with TypeScript, Tailwind v4, ESLint, App Router, Turbopack.

**Step 2: Enable TypeScript strict mode**

Edit `dashboard/tsconfig.json`, set `"strict": true` in `compilerOptions`.

**Step 3: Configure Tailwind v4 theme with Geist fonts and design tokens**

Edit `dashboard/src/app/globals.css`:

```css
@import "tailwindcss";

@theme {
  --font-sans: var(--font-geist-sans);
  --font-mono: var(--font-geist-mono);

  /* Zinc neutral palette */
  --color-surface: #fafafa;
  --color-surface-raised: #ffffff;
  --color-border: #e4e4e7;
  --color-border-subtle: #f4f4f5;

  /* Single accent: Emerald */
  --color-accent: #059669;
  --color-accent-light: #d1fae5;
  --color-accent-foreground: #ffffff;

  /* Alert: muted Rose */
  --color-alert: #e11d48;
  --color-alert-light: #ffe4e6;
  --color-alert-foreground: #ffffff;
}
```

Verify `dashboard/src/app/layout.tsx` already imports `Geist` and `Geist_Mono` from `next/font/google` with CSS variables `--font-geist-sans` and `--font-geist-mono` (create-next-app does this by default).

**Step 4: Verify build**

```bash
cd dashboard && npm run build
```

Expected: Build succeeds with zero errors.

**Step 5: Commit**

```bash
git add dashboard/
git commit -m "feat(dashboard): scaffold Next.js 15 project with Tailwind v4 and Geist fonts"
```

---

## Task 2: Install Dependencies

**Files:**
- Modify: `dashboard/package.json`

**Step 1: Install runtime dependencies**

```bash
cd dashboard
npm install @tanstack/react-query next-auth@beta @phosphor-icons/react
```

**Step 2: Install dev dependencies**

```bash
npm install -D @tanstack/react-query-devtools vitest @vitejs/plugin-react jsdom @testing-library/react @testing-library/dom vite-tsconfig-paths
```

**Step 3: Initialize shadcn/ui**

```bash
npx shadcn@latest init
```

When prompted:
- Style: New York
- Base color: Zinc
- CSS variables: Yes

This creates `dashboard/components.json` and `dashboard/src/lib/utils.ts`.

**Step 4: Add initial shadcn components**

```bash
npx shadcn@latest add button input label card table badge dropdown-menu sheet skeleton separator avatar
```

**Step 5: Create Vitest config**

Create `dashboard/vitest.config.mts`:

```typescript
import { defineConfig } from "vitest/config"
import react from "@vitejs/plugin-react"
import tsconfigPaths from "vite-tsconfig-paths"

export default defineConfig({
  plugins: [tsconfigPaths(), react()],
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
  },
})
```

**Step 6: Add test scripts to package.json**

Add to `dashboard/package.json` scripts:

```json
{
  "test": "vitest",
  "test:run": "vitest run"
}
```

**Step 7: Verify**

```bash
npm run build
```

Expected: Build succeeds.

**Step 8: Commit**

```bash
git add -A
git commit -m "feat(dashboard): install TanStack Query, NextAuth, shadcn/ui, Vitest"
```

---

## Task 3: TypeScript Types (API Contract)

**Files:**
- Create: `dashboard/src/lib/types.ts`

**Step 1: Define types matching the Go API responses**

Create `dashboard/src/lib/types.ts`:

```typescript
// Tenant types — matches Go internal/tenant/handler.go responses
export interface Tenant {
  id: string
  name: string
  slug: string
  status: "active" | "suspended" | "archived"
  settings: Record<string, unknown>
  created_at: string
  updated_at: string
}

export interface TenantCreateRequest {
  name: string
  slug: string
}

// User types — matches Go internal/tenant/user_handler.go responses
export interface User {
  id: string
  tenant_id: string
  email: string
  display_name: string
  oidc_subject: string
  oidc_issuer: string
  status: "active" | "suspended"
  is_platform_admin: boolean
  created_at: string
}

// Department types
export interface Department {
  id: string
  tenant_id: string
  name: string
  parent_id: string | null
  created_at: string
}

// Agent types — matches Go internal/orchestrator/handler.go responses
export interface AgentInstance {
  id: string
  tenant_id: string
  department_id: string | null
  user_id: string
  vm_id: string
  connection_id: string
  status: "provisioning" | "running" | "unhealthy" | "stopped" | "replacing"
  config: Record<string, unknown>
  vsock_cid: number
  tool_allowlist: string[]
  created_at: string
  last_health_check: string
}

// Audit types — matches Go internal/audit/handler.go responses
export interface AuditEvent {
  id: string
  tenant_id: string
  user_id: string | null
  action: string
  resource_type: string | null
  resource_id: string | null
  metadata: Record<string, unknown> | null
  source: string
  correlation_id: string
  created_at: string
}

// Connector types — matches Go internal/connectors/handler.go responses
export interface Connector {
  id: string
  tenant_id: string
  name: string
  connector_type: string
  endpoint: string
  resources: unknown[]
  tools: unknown[]
  status: "active" | "inactive"
  created_at: string
}

// Channel link types — matches Go internal/channels/handler.go responses
export interface ChannelLink {
  id: string
  tenant_id: string
  user_id: string
  platform: "slack" | "whatsapp" | "telegram"
  platform_user_id: string
  status: "pending_verification" | "verified" | "revoked"
  created_at: string
}

// API error shape
export interface ApiErrorResponse {
  error: string
  details?: Record<string, string>
}

// Paginated list wrapper (if API returns counts)
export interface ListResponse<T> {
  items: T[]
  total?: number
}

// Overview stats (aggregated on client from multiple endpoints)
export interface OverviewStats {
  tenantCount: number
  activeTenantCount: number
  agentCount: number
  unhealthyAgentCount: number
  userCount: number
  recentAuditEvents: AuditEvent[]
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
git commit -m "feat(dashboard): add TypeScript types matching Go API responses"
```

---

## Task 4: API Client (Server-Side)

**Files:**
- Create: `dashboard/src/lib/api.ts`
- Create: `dashboard/src/lib/api.test.ts`

**Step 1: Write the failing test**

Create `dashboard/src/lib/api.test.ts`:

```typescript
import { describe, it, expect, vi, beforeEach } from "vitest"

// We will test the ApiError class and the buildUrl helper
describe("ApiError", () => {
  it("captures status and body", async () => {
    const { ApiError } = await import("./api")
    const err = new ApiError(422, { error: "validation failed", details: { name: "required" } })
    expect(err.status).toBe(422)
    expect(err.body.error).toBe("validation failed")
    expect(err.message).toBe("API error 422: validation failed")
  })
})

describe("buildUrl", () => {
  it("constructs full URL from path", async () => {
    const { buildUrl } = await import("./api")
    const url = buildUrl("/api/v1/tenants")
    expect(url).toContain("/api/v1/tenants")
  })

  it("appends query params", async () => {
    const { buildUrl } = await import("./api")
    const url = buildUrl("/api/v1/tenants", { status: "active", limit: "10" })
    expect(url).toContain("status=active")
    expect(url).toContain("limit=10")
  })
})
```

**Step 2: Run test to verify it fails**

```bash
cd dashboard && npx vitest run src/lib/api.test.ts
```

Expected: FAIL — module `./api` not found or exports missing.

**Step 3: Write the implementation**

Create `dashboard/src/lib/api.ts`:

```typescript
import { auth } from "@/lib/auth"
import type { ApiErrorResponse } from "@/lib/types"

const API_BASE_URL = process.env.VALINOR_API_URL ?? "http://localhost:8080"

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: ApiErrorResponse,
  ) {
    super(`API error ${status}: ${body.error}`)
    this.name = "ApiError"
  }
}

export function buildUrl(path: string, params?: Record<string, string>): string {
  const url = new URL(path, API_BASE_URL)
  if (params) {
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== "") {
        url.searchParams.set(key, value)
      }
    }
  }
  return url.toString()
}

/**
 * Server-side API client. Used in Server Components and Server Actions.
 * Gets access token from NextAuth session automatically.
 */
export async function api<T>(
  path: string,
  options?: RequestInit & { params?: Record<string, string> },
): Promise<T> {
  const session = await auth()
  const { params, ...fetchOptions } = options ?? {}
  const url = buildUrl(path, params)

  const res = await fetch(url, {
    ...fetchOptions,
    headers: {
      "Content-Type": "application/json",
      ...(session?.accessToken ? { Authorization: `Bearer ${session.accessToken}` } : {}),
      ...fetchOptions.headers,
    },
  })

  if (!res.ok) {
    let body: ApiErrorResponse
    try {
      body = await res.json()
    } catch {
      body = { error: res.statusText }
    }
    throw new ApiError(res.status, body)
  }

  // Handle 204 No Content
  if (res.status === 204) {
    return undefined as T
  }

  return res.json()
}
```

Note: This file imports from `@/lib/auth` which does not exist yet. The test uses `ApiError` and `buildUrl` which do not depend on auth. The full `api()` function will be integration-tested later with Playwright.

**Step 4: Run tests to verify they pass**

```bash
cd dashboard && npx vitest run src/lib/api.test.ts
```

Expected: PASS (the test only imports `ApiError` and `buildUrl`, which don't need auth).

If the test fails because the dynamic import pulls in auth, mock it:

Add to the top of the test file:

```typescript
vi.mock("@/lib/auth", () => ({
  auth: vi.fn().mockResolvedValue({ accessToken: "test-token" }),
}))
```

**Step 5: Commit**

```bash
git add src/lib/api.ts src/lib/api.test.ts
git commit -m "feat(dashboard): add server-side API client with typed errors"
```

---

## Task 5: API Client (Client-Side)

**Files:**
- Create: `dashboard/src/lib/api-client.ts`
- Create: `dashboard/src/lib/api-client.test.ts`

**Step 1: Write the failing test**

Create `dashboard/src/lib/api-client.test.ts`:

```typescript
import { describe, it, expect, vi, beforeEach } from "vitest"
import { ApiError } from "./api"

// Mock fetch globally
const mockFetch = vi.fn()
vi.stubGlobal("fetch", mockFetch)

describe("apiClient", () => {
  beforeEach(() => {
    mockFetch.mockReset()
  })

  it("makes GET request with correct URL", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: () => Promise.resolve([{ id: "1", name: "Test Tenant" }]),
    })

    const { apiClient } = await import("./api-client")
    const result = await apiClient("/api/v1/tenants", "test-token")
    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining("/api/v1/tenants"),
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: "Bearer test-token",
        }),
      }),
    )
    expect(result).toEqual([{ id: "1", name: "Test Tenant" }])
  })

  it("throws ApiError on non-ok response", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 403,
      statusText: "Forbidden",
      json: () => Promise.resolve({ error: "insufficient permissions" }),
    })

    const { apiClient } = await import("./api-client")
    await expect(apiClient("/api/v1/tenants", "test-token")).rejects.toThrow(ApiError)
  })

  it("sends POST body as JSON", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 201,
      json: () => Promise.resolve({ id: "2", name: "New Tenant" }),
    })

    const { apiClient } = await import("./api-client")
    await apiClient("/api/v1/tenants", "test-token", {
      method: "POST",
      body: JSON.stringify({ name: "New Tenant", slug: "new-tenant" }),
    })

    expect(mockFetch).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ name: "New Tenant", slug: "new-tenant" }),
      }),
    )
  })
})
```

**Step 2: Run test to verify it fails**

```bash
cd dashboard && npx vitest run src/lib/api-client.test.ts
```

Expected: FAIL — `./api-client` not found.

**Step 3: Write the implementation**

Create `dashboard/src/lib/api-client.ts`:

```typescript
import { ApiError, buildUrl } from "@/lib/api"
import type { ApiErrorResponse } from "@/lib/types"

const API_BASE_URL = process.env.NEXT_PUBLIC_VALINOR_API_URL ?? "http://localhost:8080"

/**
 * Client-side API function. Used in "use client" components via TanStack Query.
 * Caller must pass the access token (from useSession).
 */
export async function apiClient<T>(
  path: string,
  accessToken: string,
  options?: RequestInit & { params?: Record<string, string> },
): Promise<T> {
  const { params, ...fetchOptions } = options ?? {}

  const url = new URL(path, API_BASE_URL)
  if (params) {
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== "") {
        url.searchParams.set(key, value)
      }
    }
  }

  const res = await fetch(url.toString(), {
    ...fetchOptions,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${accessToken}`,
      ...fetchOptions.headers,
    },
  })

  if (!res.ok) {
    let body: ApiErrorResponse
    try {
      body = await res.json()
    } catch {
      body = { error: res.statusText }
    }
    throw new ApiError(res.status, body)
  }

  if (res.status === 204) {
    return undefined as T
  }

  return res.json()
}
```

**Step 4: Run tests to verify they pass**

```bash
cd dashboard && npx vitest run src/lib/api-client.test.ts
```

Expected: PASS.

**Step 5: Commit**

```bash
git add src/lib/api-client.ts src/lib/api-client.test.ts
git commit -m "feat(dashboard): add client-side API client for TanStack Query"
```

---

## Task 6: NextAuth Configuration

**Files:**
- Create: `dashboard/src/lib/auth.ts`
- Create: `dashboard/src/middleware.ts`
- Create: `dashboard/src/app/api/auth/[...nextauth]/route.ts`
- Modify: `dashboard/.env.local` (create)

**Step 1: Create environment file**

Create `dashboard/.env.local`:

```
VALINOR_API_URL=http://localhost:8080
NEXT_PUBLIC_VALINOR_API_URL=http://localhost:8080
AUTH_SECRET=dev-secret-change-in-production-must-be-32-chars
AUTH_URL=http://localhost:3000
```

Ensure `dashboard/.gitignore` includes `.env.local` (create-next-app should already do this).

**Step 2: Create NextAuth configuration**

Create `dashboard/src/lib/auth.ts`:

```typescript
import NextAuth from "next-auth"
import type { NextAuthConfig } from "next-auth"
import type { JWT } from "next-auth/jwt"

// Extend the built-in types
declare module "next-auth" {
  interface Session {
    accessToken: string
    user: {
      id: string
      email: string
      name: string
      tenantId: string | null
      isPlatformAdmin: boolean
    }
  }
}

declare module "next-auth/jwt" {
  interface JWT {
    accessToken: string
    refreshToken: string
    expiresAt: number
    userId: string
    tenantId: string | null
    isPlatformAdmin: boolean
  }
}

const VALINOR_API_URL = process.env.VALINOR_API_URL ?? "http://localhost:8080"

export const authConfig: NextAuthConfig = {
  providers: [
    {
      id: "valinor",
      name: "Valinor",
      type: "oidc",
      issuer: VALINOR_API_URL,
      clientId: process.env.AUTH_VALINOR_CLIENT_ID ?? "dashboard",
      clientSecret: process.env.AUTH_VALINOR_CLIENT_SECRET ?? "",
      authorization: { url: `${VALINOR_API_URL}/auth/login`, params: { scope: "openid profile email" } },
      token: { url: `${VALINOR_API_URL}/auth/callback` },
      userinfo: { url: `${VALINOR_API_URL}/api/v1/users/me` },
      profile(profile) {
        return {
          id: profile.sub ?? profile.id,
          email: profile.email,
          name: profile.display_name ?? profile.name ?? profile.email,
          tenantId: profile.tenant_id ?? null,
          isPlatformAdmin: profile.is_platform_admin ?? false,
        }
      },
    },
  ],
  callbacks: {
    async jwt({ token, account, profile }) {
      // Initial sign-in: persist tokens from the OIDC flow
      if (account) {
        token.accessToken = account.access_token ?? ""
        token.refreshToken = account.refresh_token ?? ""
        token.expiresAt = account.expires_at ?? 0
        token.userId = (profile as Record<string, unknown>)?.id as string ?? ""
        token.tenantId = (profile as Record<string, unknown>)?.tenant_id as string ?? null
        token.isPlatformAdmin = (profile as Record<string, unknown>)?.is_platform_admin as boolean ?? false
        return token
      }

      // Token still valid
      if (Date.now() < token.expiresAt * 1000) {
        return token
      }

      // Token expired: refresh via Valinor API
      try {
        const res = await fetch(`${VALINOR_API_URL}/auth/token/refresh`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ refresh_token: token.refreshToken }),
        })
        if (!res.ok) throw new Error("refresh failed")
        const data = await res.json()
        token.accessToken = data.access_token
        token.refreshToken = data.refresh_token ?? token.refreshToken
        token.expiresAt = data.expires_at ?? Math.floor(Date.now() / 1000) + 3600
        return token
      } catch {
        // Refresh failed — force re-login
        return { ...token, error: "RefreshTokenError" }
      }
    },
    async session({ session, token }) {
      session.accessToken = token.accessToken
      session.user.id = token.userId
      session.user.tenantId = token.tenantId
      session.user.isPlatformAdmin = token.isPlatformAdmin
      return session
    },
  },
  pages: {
    signIn: "/login",
  },
}

export const { handlers, auth, signIn, signOut } = NextAuth(authConfig)
```

**Step 3: Create the NextAuth API route**

Create `dashboard/src/app/api/auth/[...nextauth]/route.ts`:

```typescript
import { handlers } from "@/lib/auth"

export const { GET, POST } = handlers
```

**Step 4: Create NextAuth middleware**

Create `dashboard/src/middleware.ts`:

```typescript
export { auth as middleware } from "@/lib/auth"

export const config = {
  matcher: [
    // Protect all routes except public ones
    "/((?!login|api/auth|_next/static|_next/image|favicon.ico).*)",
  ],
}
```

**Step 5: Verify build**

```bash
cd dashboard && npm run build
```

Expected: Build succeeds (auth won't function without a running Valinor API, but it should compile).

**Step 6: Commit**

```bash
git add src/lib/auth.ts src/middleware.ts src/app/api/auth/ .env.local
git commit -m "feat(dashboard): configure NextAuth v5 with Valinor OIDC provider"
```

---

## Task 7: Providers (Query + Session)

**Files:**
- Create: `dashboard/src/providers/query-provider.tsx`
- Create: `dashboard/src/providers/session-provider.tsx`
- Create: `dashboard/src/providers/index.tsx`

**Step 1: Create QueryProvider**

Create `dashboard/src/providers/query-provider.tsx`:

```tsx
"use client"

import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { ReactQueryDevtools } from "@tanstack/react-query-devtools"
import { useState, type ReactNode } from "react"

export function QueryProvider({ children }: { children: ReactNode }) {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            staleTime: 30_000,
            retry: 1,
          },
        },
      }),
  )

  return (
    <QueryClientProvider client={queryClient}>
      {children}
      <ReactQueryDevtools initialIsOpen={false} />
    </QueryClientProvider>
  )
}
```

Note: `useState` with initializer function follows `rerender-lazy-state-init` from vercel-react-best-practices.

**Step 2: Create SessionProvider wrapper**

Create `dashboard/src/providers/session-provider.tsx`:

```tsx
"use client"

import { SessionProvider as NextAuthSessionProvider } from "next-auth/react"
import type { ReactNode } from "react"

export function SessionProvider({ children }: { children: ReactNode }) {
  return <NextAuthSessionProvider>{children}</NextAuthSessionProvider>
}
```

**Step 3: Create combined Providers component**

Create `dashboard/src/providers/index.tsx`:

```tsx
"use client"

import { SessionProvider } from "./session-provider"
import { QueryProvider } from "./query-provider"
import type { ReactNode } from "react"

export function Providers({ children }: { children: ReactNode }) {
  return (
    <SessionProvider>
      <QueryProvider>{children}</QueryProvider>
    </SessionProvider>
  )
}
```

**Step 4: Verify build**

```bash
cd dashboard && npm run build
```

Expected: Build succeeds.

**Step 5: Commit**

```bash
git add src/providers/
git commit -m "feat(dashboard): add QueryClient and Session providers"
```

---

## Task 8: Navigation Shell — Sidebar Component

**Files:**
- Create: `dashboard/src/components/nav/sidebar.tsx`
- Create: `dashboard/src/components/nav/sidebar-item.tsx`
- Create: `dashboard/src/components/nav/sidebar.test.tsx`

**Step 1: Write the failing test**

Create `dashboard/src/components/nav/sidebar.test.tsx`:

```tsx
import { describe, it, expect, vi } from "vitest"
import { render, screen } from "@testing-library/react"

// Mock next-auth
vi.mock("next-auth/react", () => ({
  useSession: vi.fn().mockReturnValue({
    data: {
      user: {
        id: "user-1",
        name: "Test Admin",
        email: "admin@test.com",
        isPlatformAdmin: true,
        tenantId: null,
      },
    },
    status: "authenticated",
  }),
}))

// Mock next/navigation
vi.mock("next/navigation", () => ({
  usePathname: vi.fn().mockReturnValue("/"),
}))

describe("Sidebar", () => {
  it("renders Overview link for all users", async () => {
    const { Sidebar } = await import("./sidebar")
    render(<Sidebar />)
    expect(screen.getByText("Overview")).toBeDefined()
  })

  it("renders Tenants link for platform admin", async () => {
    const { Sidebar } = await import("./sidebar")
    render(<Sidebar />)
    expect(screen.getByText("Tenants")).toBeDefined()
  })
})
```

**Step 2: Run test to verify it fails**

```bash
cd dashboard && npx vitest run src/components/nav/sidebar.test.tsx
```

Expected: FAIL — module not found.

**Step 3: Write SidebarItem component**

Create `dashboard/src/components/nav/sidebar-item.tsx`:

```tsx
"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { cn } from "@/lib/utils"
import type { ReactNode } from "react"

interface SidebarItemProps {
  href: string
  icon: ReactNode
  label: string
}

export function SidebarItem({ href, icon, label }: SidebarItemProps) {
  const pathname = usePathname()
  const isActive = pathname === href || (href !== "/" && pathname.startsWith(href))

  return (
    <Link
      href={href}
      className={cn(
        "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
        isActive
          ? "bg-zinc-100 text-zinc-900"
          : "text-zinc-500 hover:bg-zinc-50 hover:text-zinc-700",
      )}
    >
      <span className="flex h-5 w-5 shrink-0 items-center justify-center">{icon}</span>
      <span>{label}</span>
    </Link>
  )
}
```

**Step 4: Write Sidebar component**

Create `dashboard/src/components/nav/sidebar.tsx`:

```tsx
"use client"

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

const tenantAdminNav = [
  { href: "/", icon: <ChartBar size={20} />, label: "Overview" },
  { href: "/users", icon: <Users size={20} />, label: "Users" },
  { href: "/departments", icon: <TreeStructure size={20} />, label: "Departments" },
  { href: "/agents", icon: <Robot size={20} />, label: "Agents" },
  { href: "/rbac", icon: <ShieldCheck size={20} />, label: "RBAC" },
  { href: "/channels", icon: <ChatCircle size={20} />, label: "Channels" },
  { href: "/connectors", icon: <Plugs size={20} />, label: "Connectors" },
  { href: "/audit", icon: <ClockCounterClockwise size={20} />, label: "Audit Log" },
]

export function Sidebar() {
  const { data: session } = useSession()
  const isPlatformAdmin = session?.user?.isPlatformAdmin ?? false
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

**Step 5: Run tests to verify they pass**

```bash
cd dashboard && npx vitest run src/components/nav/sidebar.test.tsx
```

Expected: PASS.

**Step 6: Commit**

```bash
git add src/components/nav/
git commit -m "feat(dashboard): add sidebar navigation with role-based items"
```

---

## Task 9: Navigation Shell — Top Bar & User Menu

**Files:**
- Create: `dashboard/src/components/nav/top-bar.tsx`
- Create: `dashboard/src/components/nav/user-menu.tsx`
- Create: `dashboard/src/components/nav/breadcrumbs.tsx`

**Step 1: Create Breadcrumbs (Server Component)**

Create `dashboard/src/components/nav/breadcrumbs.tsx`:

```tsx
"use client"

import { usePathname } from "next/navigation"
import Link from "next/link"
import { CaretRight } from "@phosphor-icons/react"

function formatSegment(segment: string): string {
  return segment
    .replace(/-/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase())
}

export function Breadcrumbs() {
  const pathname = usePathname()
  const segments = pathname.split("/").filter(Boolean)

  if (segments.length === 0) return null

  return (
    <nav className="flex items-center gap-1.5 text-sm text-zinc-500">
      <Link href="/" className="hover:text-zinc-700 transition-colors">
        Home
      </Link>
      {segments.map((segment, index) => {
        const href = "/" + segments.slice(0, index + 1).join("/")
        const isLast = index === segments.length - 1
        return (
          <span key={href} className="flex items-center gap-1.5">
            <CaretRight size={12} className="text-zinc-400" />
            {isLast ? (
              <span className="text-zinc-900 font-medium">{formatSegment(segment)}</span>
            ) : (
              <Link href={href} className="hover:text-zinc-700 transition-colors">
                {formatSegment(segment)}
              </Link>
            )}
          </span>
        )
      })}
    </nav>
  )
}
```

**Step 2: Create UserMenu**

Create `dashboard/src/components/nav/user-menu.tsx`:

```tsx
"use client"

import { useSession, signOut } from "next-auth/react"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import { Badge } from "@/components/ui/badge"
import { SignOut } from "@phosphor-icons/react"

function getInitials(name: string): string {
  return name
    .split(" ")
    .map((n) => n[0])
    .join("")
    .toUpperCase()
    .slice(0, 2)
}

export function UserMenu() {
  const { data: session } = useSession()
  if (!session?.user) return null

  const { name, email, isPlatformAdmin } = session.user

  return (
    <DropdownMenu>
      <DropdownMenuTrigger className="flex items-center gap-2 rounded-lg px-2 py-1.5 hover:bg-zinc-50 transition-colors outline-none">
        <Avatar className="h-7 w-7">
          <AvatarFallback className="bg-zinc-200 text-zinc-700 text-xs font-medium">
            {getInitials(name ?? email ?? "?")}
          </AvatarFallback>
        </Avatar>
        <span className="text-sm font-medium text-zinc-700 hidden md:inline">
          {name ?? email}
        </span>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-56">
        <div className="px-2 py-1.5">
          <p className="text-sm font-medium text-zinc-900">{name}</p>
          <p className="text-xs text-zinc-500">{email}</p>
          {isPlatformAdmin && (
            <Badge variant="secondary" className="mt-1 text-xs">Platform Admin</Badge>
          )}
        </div>
        <DropdownMenuSeparator />
        <DropdownMenuItem
          onClick={() => signOut({ callbackUrl: "/login" })}
          className="text-zinc-600"
        >
          <SignOut size={16} className="mr-2" />
          Sign out
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
```

**Step 3: Create TopBar**

Create `dashboard/src/components/nav/top-bar.tsx`:

```tsx
import { Breadcrumbs } from "./breadcrumbs"
import { UserMenu } from "./user-menu"

export function TopBar() {
  return (
    <header className="flex h-14 items-center justify-between border-b border-zinc-200 bg-white px-6">
      <Breadcrumbs />
      <UserMenu />
    </header>
  )
}
```

**Step 4: Verify build**

```bash
cd dashboard && npm run build
```

Expected: Build succeeds.

**Step 5: Commit**

```bash
git add src/components/nav/top-bar.tsx src/components/nav/user-menu.tsx src/components/nav/breadcrumbs.tsx
git commit -m "feat(dashboard): add top bar with breadcrumbs and user menu"
```

---

## Task 10: Root Layout Integration

**Files:**
- Modify: `dashboard/src/app/layout.tsx`
- Create: `dashboard/src/app/login/page.tsx`

**Step 1: Update root layout**

Replace `dashboard/src/app/layout.tsx` with:

```tsx
import type { Metadata } from "next"
import { Geist, Geist_Mono } from "next/font/google"
import { Providers } from "@/providers"
import { Sidebar } from "@/components/nav/sidebar"
import { TopBar } from "@/components/nav/top-bar"
import "./globals.css"

const geistSans = Geist({
  subsets: ["latin"],
  variable: "--font-geist-sans",
})

const geistMono = Geist_Mono({
  subsets: ["latin"],
  variable: "--font-geist-mono",
})

export const metadata: Metadata = {
  title: "Valinor Dashboard",
  description: "Admin dashboard for the Valinor AI agent control plane",
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className={`${geistSans.variable} ${geistMono.variable}`}>
      <body className="min-h-[100dvh] bg-zinc-50 font-sans antialiased">
        <Providers>
          <div className="flex min-h-[100dvh]">
            <Sidebar />
            <div className="flex flex-1 flex-col">
              <TopBar />
              <main className="flex-1 px-6 py-6 lg:px-8">
                <div className="mx-auto max-w-[1400px]">{children}</div>
              </main>
            </div>
          </div>
        </Providers>
      </body>
    </html>
  )
}
```

Note: Uses `min-h-[100dvh]` instead of `h-screen` per design-taste rules.

**Step 2: Create login page**

Create `dashboard/src/app/login/page.tsx`:

```tsx
import { signIn } from "@/lib/auth"

export default function LoginPage() {
  return (
    <div className="flex min-h-[100dvh] items-center justify-center bg-zinc-50">
      <div className="w-full max-w-sm space-y-6 text-center">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">
            Valinor Dashboard
          </h1>
          <p className="mt-2 text-sm text-zinc-500">
            Sign in to manage your AI agent infrastructure.
          </p>
        </div>
        <form
          action={async () => {
            "use server"
            await signIn("valinor", { redirectTo: "/" })
          }}
        >
          <button
            type="submit"
            className="w-full rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-zinc-800 active:scale-[0.98]"
          >
            Sign in with SSO
          </button>
        </form>
      </div>
    </div>
  )
}
```

Note: Login page has its own layout (no sidebar). This requires a route group or the middleware redirect handles showing it outside the shell. Since `middleware.ts` excludes `/login` from auth, and the root layout renders the sidebar unconditionally, we need to handle this. Create a login layout that omits the shell:

Create `dashboard/src/app/login/layout.tsx`:

```tsx
export default function LoginLayout({ children }: { children: React.ReactNode }) {
  return children
}
```

And update root layout to conditionally render shell. Simpler approach: use Next.js route groups.

Restructure:
- `dashboard/src/app/(dashboard)/layout.tsx` — shell layout with sidebar + topbar
- `dashboard/src/app/(dashboard)/page.tsx` — overview
- `dashboard/src/app/(auth)/login/page.tsx` — login (no shell)
- `dashboard/src/app/layout.tsx` — root layout (fonts, providers only)

Update root layout `dashboard/src/app/layout.tsx`:

```tsx
import type { Metadata } from "next"
import { Geist, Geist_Mono } from "next/font/google"
import { Providers } from "@/providers"
import "./globals.css"

const geistSans = Geist({
  subsets: ["latin"],
  variable: "--font-geist-sans",
})

const geistMono = Geist_Mono({
  subsets: ["latin"],
  variable: "--font-geist-mono",
})

export const metadata: Metadata = {
  title: "Valinor Dashboard",
  description: "Admin dashboard for the Valinor AI agent control plane",
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`${geistSans.variable} ${geistMono.variable}`}>
      <body className="min-h-[100dvh] bg-zinc-50 font-sans antialiased">
        <Providers>{children}</Providers>
      </body>
    </html>
  )
}
```

Create `dashboard/src/app/(dashboard)/layout.tsx`:

```tsx
import { Sidebar } from "@/components/nav/sidebar"
import { TopBar } from "@/components/nav/top-bar"

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-[100dvh]">
      <Sidebar />
      <div className="flex flex-1 flex-col">
        <TopBar />
        <main className="flex-1 px-6 py-6 lg:px-8">
          <div className="mx-auto max-w-[1400px]">{children}</div>
        </main>
      </div>
    </div>
  )
}
```

Move existing `page.tsx` to `dashboard/src/app/(dashboard)/page.tsx`.

**Step 3: Verify build**

```bash
cd dashboard && npm run build
```

Expected: Build succeeds.

**Step 4: Commit**

```bash
git add src/app/
git commit -m "feat(dashboard): wire root layout with route groups for shell and auth"
```

---

## Task 11: TanStack Query Hooks — Tenants

**Files:**
- Create: `dashboard/src/lib/queries/tenants.ts`
- Create: `dashboard/src/lib/queries/tenants.test.ts`

**Step 1: Write failing test**

Create `dashboard/src/lib/queries/tenants.test.ts`:

```typescript
import { describe, it, expect, vi } from "vitest"

vi.mock("@/lib/api-client", () => ({
  apiClient: vi.fn(),
}))

describe("tenant query functions", () => {
  it("fetchTenants calls correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce([])

    const { fetchTenants } = await import("./tenants")
    await fetchTenants("test-token")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/tenants",
      "test-token",
      undefined,
    )
  })

  it("fetchTenant calls correct endpoint with ID", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ id: "t-1", name: "Acme" })

    const { fetchTenant } = await import("./tenants")
    await fetchTenant("test-token", "t-1")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/tenants/t-1",
      "test-token",
      undefined,
    )
  })

  it("createTenant posts to correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ id: "t-2", name: "New Corp" })

    const { createTenant } = await import("./tenants")
    await createTenant("test-token", { name: "New Corp", slug: "new-corp" })

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/tenants",
      "test-token",
      {
        method: "POST",
        body: JSON.stringify({ name: "New Corp", slug: "new-corp" }),
      },
    )
  })
})
```

**Step 2: Run test to verify it fails**

```bash
cd dashboard && npx vitest run src/lib/queries/tenants.test.ts
```

Expected: FAIL.

**Step 3: Write implementation**

Create `dashboard/src/lib/queries/tenants.ts`:

```typescript
"use client"

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { useSession } from "next-auth/react"
import { apiClient } from "@/lib/api-client"
import type { Tenant, TenantCreateRequest } from "@/lib/types"

// Query key factory
export const tenantKeys = {
  all: ["tenants"] as const,
  list: () => [...tenantKeys.all, "list"] as const,
  detail: (id: string) => [...tenantKeys.all, "detail", id] as const,
}

// Fetch functions (exported for testing)
export async function fetchTenants(
  accessToken: string,
  params?: Record<string, string>,
): Promise<Tenant[]> {
  return apiClient<Tenant[]>("/api/v1/tenants", accessToken, params ? { params } : undefined)
}

export async function fetchTenant(
  accessToken: string,
  id: string,
): Promise<Tenant> {
  return apiClient<Tenant>(`/api/v1/tenants/${id}`, accessToken, undefined)
}

export async function createTenant(
  accessToken: string,
  data: TenantCreateRequest,
): Promise<Tenant> {
  return apiClient<Tenant>("/api/v1/tenants", accessToken, {
    method: "POST",
    body: JSON.stringify(data),
  })
}

// React hooks
export function useTenantsQuery() {
  const { data: session } = useSession()
  return useQuery({
    queryKey: tenantKeys.list(),
    queryFn: () => fetchTenants(session!.accessToken),
    enabled: !!session?.accessToken,
    staleTime: 30_000,
  })
}

export function useTenantQuery(id: string) {
  const { data: session } = useSession()
  return useQuery({
    queryKey: tenantKeys.detail(id),
    queryFn: () => fetchTenant(session!.accessToken, id),
    enabled: !!session?.accessToken && !!id,
  })
}

export function useCreateTenantMutation() {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: TenantCreateRequest) =>
      createTenant(session!.accessToken, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: tenantKeys.all })
    },
  })
}
```

**Step 4: Run tests to verify they pass**

```bash
cd dashboard && npx vitest run src/lib/queries/tenants.test.ts
```

Expected: PASS.

**Step 5: Commit**

```bash
git add src/lib/queries/
git commit -m "feat(dashboard): add TanStack Query hooks for tenant CRUD"
```

---

## Task 12: Overview Dashboard Page

**Files:**
- Create: `dashboard/src/components/overview/stat-card.tsx`
- Create: `dashboard/src/components/overview/recent-events.tsx`
- Create: `dashboard/src/components/overview/platform-overview.tsx`
- Modify: `dashboard/src/app/(dashboard)/page.tsx`

**Step 1: Create StatCard component**

Create `dashboard/src/components/overview/stat-card.tsx`:

```tsx
import type { ReactNode } from "react"

interface StatCardProps {
  label: string
  value: string | number
  icon: ReactNode
  trend?: { value: string; positive: boolean }
}

export function StatCard({ label, value, icon, trend }: StatCardProps) {
  return (
    <div className="rounded-xl border border-zinc-200 bg-white p-5">
      <div className="flex items-center justify-between">
        <span className="text-sm font-medium text-zinc-500">{label}</span>
        <span className="text-zinc-400">{icon}</span>
      </div>
      <p className="mt-2 text-2xl font-semibold tracking-tight text-zinc-900">
        {value}
      </p>
      {trend && (
        <p
          className={`mt-1 text-xs font-medium ${
            trend.positive ? "text-emerald-600" : "text-rose-600"
          }`}
        >
          {trend.value}
        </p>
      )}
    </div>
  )
}
```

**Step 2: Create RecentEvents component**

Create `dashboard/src/components/overview/recent-events.tsx`:

```tsx
"use client"

import { useSession } from "next-auth/react"
import { useQuery } from "@tanstack/react-query"
import { apiClient } from "@/lib/api-client"
import { Skeleton } from "@/components/ui/skeleton"
import type { AuditEvent } from "@/lib/types"

function formatTimeAgo(dateStr: string): string {
  const seconds = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000)
  if (seconds < 60) return `${seconds}s ago`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

export function RecentEvents() {
  const { data: session } = useSession()
  const { data: events, isLoading, isError } = useQuery({
    queryKey: ["audit", "recent"],
    queryFn: () =>
      apiClient<AuditEvent[]>("/api/v1/audit/events", session!.accessToken, {
        params: { limit: "10" },
      }),
    enabled: !!session?.accessToken,
    refetchInterval: 30_000,
  })

  if (isLoading) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-10 w-full" />
        ))}
      </div>
    )
  }

  if (isError) {
    return (
      <p className="text-sm text-zinc-500">Failed to load recent events.</p>
    )
  }

  if (!events || events.length === 0) {
    return (
      <div className="py-8 text-center">
        <p className="text-sm text-zinc-500">No audit events recorded yet.</p>
        <p className="mt-1 text-xs text-zinc-400">
          Events appear here as users interact with the platform.
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

**Step 3: Create PlatformOverview component**

Create `dashboard/src/components/overview/platform-overview.tsx`:

```tsx
"use client"

import { useSession } from "next-auth/react"
import { useQuery } from "@tanstack/react-query"
import { apiClient } from "@/lib/api-client"
import { StatCard } from "./stat-card"
import { RecentEvents } from "./recent-events"
import { Skeleton } from "@/components/ui/skeleton"
import { Buildings, Robot, Users, Warning } from "@phosphor-icons/react"
import type { Tenant, AgentInstance } from "@/lib/types"

export function PlatformOverview() {
  const { data: session } = useSession()

  const { data: tenants, isLoading: tenantsLoading } = useQuery({
    queryKey: ["tenants", "list"],
    queryFn: () => apiClient<Tenant[]>("/api/v1/tenants", session!.accessToken),
    enabled: !!session?.accessToken,
  })

  const { data: agents, isLoading: agentsLoading } = useQuery({
    queryKey: ["agents", "list"],
    queryFn: () => apiClient<AgentInstance[]>("/api/v1/agents", session!.accessToken),
    enabled: !!session?.accessToken,
  })

  const isLoading = tenantsLoading || agentsLoading

  const activeTenants = tenants?.filter((t) => t.status === "active").length ?? 0
  const totalAgents = agents?.length ?? 0
  const unhealthyAgents = agents?.filter((a) => a.status === "unhealthy").length ?? 0

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">
          Platform Overview
        </h1>
        <p className="mt-1 text-sm text-zinc-500">
          System health and recent activity across all tenants.
        </p>
      </div>

      {isLoading ? (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-28 rounded-xl" />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
          <StatCard
            label="Total Tenants"
            value={tenants?.length ?? 0}
            icon={<Buildings size={20} />}
          />
          <StatCard
            label="Active Tenants"
            value={activeTenants}
            icon={<Buildings size={20} />}
          />
          <StatCard
            label="Running Agents"
            value={totalAgents}
            icon={<Robot size={20} />}
          />
          <StatCard
            label="Unhealthy Agents"
            value={unhealthyAgents}
            icon={<Warning size={20} />}
          />
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[2fr_1fr]">
        <div>
          <h2 className="mb-3 text-sm font-medium text-zinc-900">Recent Activity</h2>
          <div className="rounded-xl border border-zinc-200 bg-white p-4">
            <RecentEvents />
          </div>
        </div>
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
      </div>
    </div>
  )
}
```

**Step 4: Wire the overview page**

Update `dashboard/src/app/(dashboard)/page.tsx`:

```tsx
import { PlatformOverview } from "@/components/overview/platform-overview"

export default function OverviewPage() {
  return <PlatformOverview />
}
```

**Step 5: Verify build**

```bash
cd dashboard && npm run build
```

Expected: Build succeeds.

**Step 6: Commit**

```bash
git add src/components/overview/ src/app/\(dashboard\)/page.tsx
git commit -m "feat(dashboard): add overview dashboard with stats and recent events"
```

---

## Task 13: Tenant List Page

**Files:**
- Create: `dashboard/src/components/tenants/tenant-table.tsx`
- Create: `dashboard/src/components/tenants/tenant-status-badge.tsx`
- Create: `dashboard/src/app/(dashboard)/tenants/page.tsx`

**Step 1: Create TenantStatusBadge**

Create `dashboard/src/components/tenants/tenant-status-badge.tsx`:

```tsx
import { Badge } from "@/components/ui/badge"

const statusStyles = {
  active: "bg-emerald-50 text-emerald-700 border-emerald-200",
  suspended: "bg-amber-50 text-amber-700 border-amber-200",
  archived: "bg-zinc-100 text-zinc-500 border-zinc-200",
} as const

export function TenantStatusBadge({ status }: { status: "active" | "suspended" | "archived" }) {
  return (
    <Badge variant="outline" className={statusStyles[status]}>
      {status}
    </Badge>
  )
}
```

**Step 2: Create TenantTable**

Create `dashboard/src/components/tenants/tenant-table.tsx`:

```tsx
"use client"

import { useState } from "react"
import Link from "next/link"
import { useTenantsQuery } from "@/lib/queries/tenants"
import { TenantStatusBadge } from "./tenant-status-badge"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { MagnifyingGlass } from "@phosphor-icons/react"
import type { Tenant } from "@/lib/types"

function formatDate(dateStr: string): string {
  return new Date(dateStr).toLocaleDateString("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
  })
}

export function TenantTable() {
  const { data: tenants, isLoading, isError } = useTenantsQuery()
  const [search, setSearch] = useState("")

  const filtered = tenants?.filter(
    (t) =>
      t.name.toLowerCase().includes(search.toLowerCase()) ||
      t.slug.toLowerCase().includes(search.toLowerCase()),
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
        <p className="text-sm text-rose-700">Failed to load tenants. Please try again.</p>
      </div>
    )
  }

  if (!tenants || tenants.length === 0) {
    return (
      <div className="py-12 text-center">
        <p className="text-sm font-medium text-zinc-900">No tenants yet</p>
        <p className="mt-1 text-sm text-zinc-500">
          Create your first tenant to get started.
        </p>
        <Link
          href="/tenants/new"
          className="mt-4 inline-block rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800 transition-colors active:scale-[0.98]"
        >
          Create tenant
        </Link>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="relative max-w-sm">
        <MagnifyingGlass
          size={16}
          className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-400"
        />
        <Input
          placeholder="Search tenants..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="pl-9"
        />
      </div>

      <div className="rounded-xl border border-zinc-200 bg-white">
        <div className="grid grid-cols-[2fr_1fr_1fr_1fr] gap-4 border-b border-zinc-100 px-4 py-3 text-xs font-medium uppercase tracking-wider text-zinc-500">
          <span>Name</span>
          <span>Slug</span>
          <span>Status</span>
          <span>Created</span>
        </div>
        <div className="divide-y divide-zinc-100">
          {filtered?.map((tenant) => (
            <Link
              key={tenant.id}
              href={`/tenants/${tenant.id}`}
              className="grid grid-cols-[2fr_1fr_1fr_1fr] gap-4 px-4 py-3 text-sm transition-colors hover:bg-zinc-50"
            >
              <span className="font-medium text-zinc-900">{tenant.name}</span>
              <span className="font-mono text-zinc-500">{tenant.slug}</span>
              <TenantStatusBadge status={tenant.status} />
              <span className="text-zinc-500">{formatDate(tenant.created_at)}</span>
            </Link>
          ))}
        </div>
      </div>
    </div>
  )
}
```

**Step 3: Create tenant list page**

Create `dashboard/src/app/(dashboard)/tenants/page.tsx`:

```tsx
import Link from "next/link"
import { TenantTable } from "@/components/tenants/tenant-table"
import { Plus } from "@phosphor-icons/react"

export default function TenantsPage() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">
            Tenants
          </h1>
          <p className="mt-1 text-sm text-zinc-500">
            Manage organizations on the platform.
          </p>
        </div>
        <Link
          href="/tenants/new"
          className="flex items-center gap-2 rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-zinc-800 active:scale-[0.98]"
        >
          <Plus size={16} />
          Create tenant
        </Link>
      </div>
      <TenantTable />
    </div>
  )
}
```

**Step 4: Verify build**

```bash
cd dashboard && npm run build
```

Expected: Build succeeds.

**Step 5: Commit**

```bash
git add src/components/tenants/ src/app/\(dashboard\)/tenants/
git commit -m "feat(dashboard): add tenant list page with search and status badges"
```

---

## Task 14: Tenant Detail Page

**Files:**
- Create: `dashboard/src/components/tenants/tenant-detail.tsx`
- Create: `dashboard/src/app/(dashboard)/tenants/[id]/page.tsx`

**Step 1: Create TenantDetail component**

Create `dashboard/src/components/tenants/tenant-detail.tsx`:

```tsx
"use client"

import { useTenantQuery } from "@/lib/queries/tenants"
import { TenantStatusBadge } from "./tenant-status-badge"
import { Skeleton } from "@/components/ui/skeleton"
import { Buildings, Users, TreeStructure, Robot, Plugs } from "@phosphor-icons/react"

function formatDate(dateStr: string): string {
  return new Date(dateStr).toLocaleDateString("en-US", {
    month: "long",
    day: "numeric",
    year: "numeric",
  })
}

export function TenantDetail({ id }: { id: string }) {
  const { data: tenant, isLoading, isError } = useTenantQuery(id)

  if (isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-12 w-72" />
        <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-20 rounded-xl" />
          ))}
        </div>
      </div>
    )
  }

  if (isError || !tenant) {
    return (
      <div className="rounded-xl border border-rose-200 bg-rose-50 p-4">
        <p className="text-sm text-rose-700">
          Failed to load tenant details. The tenant may not exist.
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">
            {tenant.name}
          </h1>
          <TenantStatusBadge status={tenant.status} />
        </div>
        <div className="mt-2 flex items-center gap-4 text-sm text-zinc-500">
          <span className="font-mono">{tenant.slug}</span>
          <span>Created {formatDate(tenant.created_at)}</span>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <div className="flex items-center gap-3 rounded-xl border border-zinc-200 bg-white p-4">
          <Users size={20} className="text-zinc-400" />
          <div>
            <p className="text-xs text-zinc-500">Users</p>
            <p className="text-lg font-semibold text-zinc-900">--</p>
          </div>
        </div>
        <div className="flex items-center gap-3 rounded-xl border border-zinc-200 bg-white p-4">
          <TreeStructure size={20} className="text-zinc-400" />
          <div>
            <p className="text-xs text-zinc-500">Departments</p>
            <p className="text-lg font-semibold text-zinc-900">--</p>
          </div>
        </div>
        <div className="flex items-center gap-3 rounded-xl border border-zinc-200 bg-white p-4">
          <Robot size={20} className="text-zinc-400" />
          <div>
            <p className="text-xs text-zinc-500">Agents</p>
            <p className="text-lg font-semibold text-zinc-900">--</p>
          </div>
        </div>
        <div className="flex items-center gap-3 rounded-xl border border-zinc-200 bg-white p-4">
          <Plugs size={20} className="text-zinc-400" />
          <div>
            <p className="text-xs text-zinc-500">Connectors</p>
            <p className="text-lg font-semibold text-zinc-900">--</p>
          </div>
        </div>
      </div>

      <div>
        <h2 className="mb-3 text-sm font-medium text-zinc-900">Settings</h2>
        <div className="rounded-xl border border-zinc-200 bg-white p-4">
          <pre className="text-xs font-mono text-zinc-600 overflow-auto">
            {JSON.stringify(tenant.settings, null, 2)}
          </pre>
        </div>
      </div>
    </div>
  )
}
```

Note: Stats show "--" placeholder for now. A future slice will wire up aggregate counts from the tenant-scoped user/department/agent APIs.

**Step 2: Create tenant detail page**

Create `dashboard/src/app/(dashboard)/tenants/[id]/page.tsx`:

```tsx
import { TenantDetail } from "@/components/tenants/tenant-detail"

export default async function TenantDetailPage({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  const { id } = await params
  return <TenantDetail id={id} />
}
```

**Step 3: Verify build**

```bash
cd dashboard && npm run build
```

Expected: Build succeeds.

**Step 4: Commit**

```bash
git add src/components/tenants/tenant-detail.tsx src/app/\(dashboard\)/tenants/\[id\]/
git commit -m "feat(dashboard): add tenant detail page with stats and settings"
```

---

## Task 15: Create Tenant Form

**Files:**
- Create: `dashboard/src/components/tenants/create-tenant-form.tsx`
- Create: `dashboard/src/components/tenants/create-tenant-form.test.tsx`
- Create: `dashboard/src/app/(dashboard)/tenants/new/page.tsx`

**Step 1: Write failing test**

Create `dashboard/src/components/tenants/create-tenant-form.test.tsx`:

```tsx
import { describe, it, expect, vi } from "vitest"
import { render, screen, fireEvent } from "@testing-library/react"

// Mock dependencies
vi.mock("next-auth/react", () => ({
  useSession: vi.fn().mockReturnValue({
    data: { accessToken: "test", user: { isPlatformAdmin: true } },
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

describe("CreateTenantForm", () => {
  it("auto-generates slug from name", async () => {
    const { CreateTenantForm } = await import("./create-tenant-form")
    render(<CreateTenantForm />)

    const nameInput = screen.getByLabelText("Name")
    fireEvent.change(nameInput, { target: { value: "Acme Corporation" } })

    const slugInput = screen.getByLabelText("Slug") as HTMLInputElement
    expect(slugInput.value).toBe("acme-corporation")
  })

  it("renders submit button", async () => {
    const { CreateTenantForm } = await import("./create-tenant-form")
    render(<CreateTenantForm />)
    expect(screen.getByRole("button", { name: /create tenant/i })).toBeDefined()
  })
})
```

**Step 2: Run test to verify it fails**

```bash
cd dashboard && npx vitest run src/components/tenants/create-tenant-form.test.tsx
```

Expected: FAIL.

**Step 3: Write the form component**

Create `dashboard/src/components/tenants/create-tenant-form.tsx`:

```tsx
"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { useCreateTenantMutation } from "@/lib/queries/tenants"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"

function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
}

export function CreateTenantForm() {
  const router = useRouter()
  const mutation = useCreateTenantMutation()
  const [name, setName] = useState("")
  const [slug, setSlug] = useState("")
  const [slugManuallyEdited, setSlugManuallyEdited] = useState(false)

  function handleNameChange(value: string) {
    setName(value)
    if (!slugManuallyEdited) {
      setSlug(slugify(value))
    }
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    mutation.mutate(
      { name, slug },
      { onSuccess: (tenant) => router.push(`/tenants/${tenant.id}`) },
    )
  }

  return (
    <form onSubmit={handleSubmit} className="max-w-lg space-y-6">
      <div className="space-y-2">
        <Label htmlFor="name">Name</Label>
        <Input
          id="name"
          value={name}
          onChange={(e) => handleNameChange(e.target.value)}
          placeholder="e.g. Chelsea FC"
          required
        />
        <p className="text-xs text-zinc-400">The display name for this tenant organization.</p>
      </div>

      <div className="space-y-2">
        <Label htmlFor="slug">Slug</Label>
        <Input
          id="slug"
          value={slug}
          onChange={(e) => {
            setSlug(e.target.value)
            setSlugManuallyEdited(true)
          }}
          placeholder="e.g. chelsea-fc"
          required
          pattern="^[a-z0-9]+(-[a-z0-9]+)*$"
        />
        <p className="text-xs text-zinc-400">
          URL-safe identifier. Auto-generated from name, but you can customize it.
        </p>
      </div>

      {mutation.isError && (
        <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2">
          <p className="text-sm text-rose-700">
            Failed to create tenant. Please check the details and try again.
          </p>
        </div>
      )}

      <button
        type="submit"
        disabled={mutation.isPending || !name || !slug}
        className="rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-zinc-800 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {mutation.isPending ? "Creating..." : "Create tenant"}
      </button>
    </form>
  )
}
```

**Step 4: Run tests to verify they pass**

```bash
cd dashboard && npx vitest run src/components/tenants/create-tenant-form.test.tsx
```

Expected: PASS.

**Step 5: Create the page**

Create `dashboard/src/app/(dashboard)/tenants/new/page.tsx`:

```tsx
import { CreateTenantForm } from "@/components/tenants/create-tenant-form"

export default function NewTenantPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">
          Create Tenant
        </h1>
        <p className="mt-1 text-sm text-zinc-500">
          Provision a new organization on the platform.
        </p>
      </div>
      <CreateTenantForm />
    </div>
  )
}
```

**Step 6: Verify build**

```bash
cd dashboard && npm run build
```

Expected: Build succeeds.

**Step 7: Commit**

```bash
git add src/components/tenants/create-tenant-form.tsx src/components/tenants/create-tenant-form.test.tsx src/app/\(dashboard\)/tenants/new/
git commit -m "feat(dashboard): add create tenant form with auto-slug and validation"
```

---

## Task 16: Loading and Error Boundaries

**Files:**
- Create: `dashboard/src/app/(dashboard)/loading.tsx`
- Create: `dashboard/src/app/(dashboard)/error.tsx`
- Create: `dashboard/src/app/(dashboard)/tenants/loading.tsx`

**Step 1: Create dashboard loading skeleton**

Create `dashboard/src/app/(dashboard)/loading.tsx`:

```tsx
import { Skeleton } from "@/components/ui/skeleton"

export default function DashboardLoading() {
  return (
    <div className="space-y-8">
      <div className="space-y-2">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-4 w-72" />
      </div>
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-28 rounded-xl" />
        ))}
      </div>
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[2fr_1fr]">
        <Skeleton className="h-64 rounded-xl" />
        <Skeleton className="h-64 rounded-xl" />
      </div>
    </div>
  )
}
```

**Step 2: Create error boundary**

Create `dashboard/src/app/(dashboard)/error.tsx`:

```tsx
"use client"

import { ArrowCounterClockwise } from "@phosphor-icons/react"

export default function DashboardError({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  return (
    <div className="flex min-h-[50vh] items-center justify-center">
      <div className="text-center space-y-4">
        <h2 className="text-lg font-semibold text-zinc-900">Something went wrong</h2>
        <p className="text-sm text-zinc-500 max-w-md">
          An unexpected error occurred. This has been logged for investigation.
        </p>
        <button
          onClick={reset}
          className="inline-flex items-center gap-2 rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-zinc-800 active:scale-[0.98]"
        >
          <ArrowCounterClockwise size={16} />
          Try again
        </button>
      </div>
    </div>
  )
}
```

**Step 3: Create tenants loading skeleton**

Create `dashboard/src/app/(dashboard)/tenants/loading.tsx`:

```tsx
import { Skeleton } from "@/components/ui/skeleton"

export default function TenantsLoading() {
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="space-y-2">
          <Skeleton className="h-8 w-32" />
          <Skeleton className="h-4 w-56" />
        </div>
        <Skeleton className="h-10 w-36 rounded-lg" />
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

**Step 4: Verify build**

```bash
cd dashboard && npm run build
```

Expected: Build succeeds.

**Step 5: Commit**

```bash
git add src/app/\(dashboard\)/loading.tsx src/app/\(dashboard\)/error.tsx src/app/\(dashboard\)/tenants/loading.tsx
git commit -m "feat(dashboard): add loading skeletons and error boundary"
```

---

## Task 17: Mobile Responsive Sidebar

**Files:**
- Create: `dashboard/src/components/nav/mobile-sidebar.tsx`
- Modify: `dashboard/src/app/(dashboard)/layout.tsx`

**Step 1: Create mobile sidebar with Sheet**

Create `dashboard/src/components/nav/mobile-sidebar.tsx`:

```tsx
"use client"

import { useState } from "react"
import { Sheet, SheetContent, SheetTrigger } from "@/components/ui/sheet"
import { Sidebar } from "./sidebar"
import { List } from "@phosphor-icons/react"

export function MobileSidebar() {
  const [open, setOpen] = useState(false)

  return (
    <Sheet open={open} onOpenChange={setOpen}>
      <SheetTrigger asChild>
        <button
          className="flex h-9 w-9 items-center justify-center rounded-lg text-zinc-500 hover:bg-zinc-100 lg:hidden"
          aria-label="Open navigation"
        >
          <List size={20} />
        </button>
      </SheetTrigger>
      <SheetContent side="left" className="w-60 p-0">
        <Sidebar />
      </SheetContent>
    </Sheet>
  )
}
```

**Step 2: Update dashboard layout to hide desktop sidebar on mobile**

Update `dashboard/src/app/(dashboard)/layout.tsx`:

```tsx
import { Sidebar } from "@/components/nav/sidebar"
import { TopBar } from "@/components/nav/top-bar"
import { MobileSidebar } from "@/components/nav/mobile-sidebar"

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return (
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
  )
}
```

Update `dashboard/src/components/nav/top-bar.tsx` to remove the `<header>` wrapper since the layout now handles it:

```tsx
import { Breadcrumbs } from "./breadcrumbs"
import { UserMenu } from "./user-menu"

export function TopBar() {
  return (
    <div className="flex flex-1 items-center justify-between">
      <Breadcrumbs />
      <UserMenu />
    </div>
  )
}
```

**Step 3: Verify build**

```bash
cd dashboard && npm run build
```

Expected: Build succeeds.

**Step 4: Commit**

```bash
git add src/components/nav/mobile-sidebar.tsx src/components/nav/top-bar.tsx src/app/\(dashboard\)/layout.tsx
git commit -m "feat(dashboard): add mobile responsive sidebar with Sheet drawer"
```

---

## Task 18: CORS Configuration on Go API

**Files:**
- Modify: `internal/platform/server/server.go`
- Modify: `internal/platform/config/config.go`
- Modify: `config.yaml`

**Step 1: Add CORS config to config.go**

Check existing config structure and add a `cors` section:

```go
// In the server config section
type ServerConfig struct {
    Port string `koanf:"port"`
    Host string `koanf:"host"`
    CORS CORSConfig `koanf:"cors"`
}

type CORSConfig struct {
    AllowedOrigins []string `koanf:"allowed_origins"`
}
```

**Step 2: Add CORS middleware to server.go**

Add a simple CORS middleware that reads allowed origins from config and sets appropriate headers on responses. Apply it as the outermost middleware in the handler chain.

```go
func CORS(allowedOrigins []string) func(http.Handler) http.Handler {
    allowed := make(map[string]bool, len(allowedOrigins))
    for _, o := range allowedOrigins {
        allowed[o] = true
    }
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            origin := r.Header.Get("Origin")
            if allowed[origin] {
                w.Header().Set("Access-Control-Allow-Origin", origin)
                w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
                w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
                w.Header().Set("Access-Control-Allow-Credentials", "true")
                w.Header().Set("Access-Control-Max-Age", "86400")
            }
            if r.Method == http.MethodOptions {
                w.WriteHeader(http.StatusNoContent)
                return
            }
            next.ServeHTTP(w, r)
        })
    }
}
```

**Step 3: Update config.yaml**

```yaml
server:
  port: "8080"
  host: "0.0.0.0"
  cors:
    allowed_origins:
      - "http://localhost:3000"
```

**Step 4: Write test for CORS middleware**

Test that CORS headers are set for allowed origins and OPTIONS returns 204.

**Step 5: Run tests**

```bash
go test ./internal/platform/...
```

Expected: PASS.

**Step 6: Commit**

```bash
git add internal/platform/server/server.go internal/platform/config/config.go config.yaml
git commit -m "feat(api): add CORS middleware for dashboard origin"
```

---

## Task 19: Playwright E2E Setup

**Files:**
- Create: `dashboard/playwright.config.ts`
- Create: `dashboard/tests/e2e/smoke.spec.ts`

**Step 1: Initialize Playwright**

```bash
cd dashboard && npm init playwright@latest -- --quiet
```

**Step 2: Configure playwright.config.ts**

Update `dashboard/playwright.config.ts`:

```typescript
import { defineConfig, devices } from "@playwright/test"

export default defineConfig({
  testDir: "./tests/e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  reporter: "html",
  use: {
    baseURL: "http://localhost:3000",
    trace: "on-first-retry",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: {
    command: "npm run dev",
    url: "http://localhost:3000",
    reuseExistingServer: !process.env.CI,
    timeout: 30_000,
  },
})
```

**Step 3: Write smoke test**

Create `dashboard/tests/e2e/smoke.spec.ts`:

```typescript
import { test, expect } from "@playwright/test"

test.describe("Dashboard smoke tests", () => {
  test("login page renders", async ({ page }) => {
    await page.goto("/login")
    await expect(page.getByText("Valinor Dashboard")).toBeVisible()
    await expect(page.getByText("Sign in with SSO")).toBeVisible()
  })

  test("unauthenticated user is redirected to login", async ({ page }) => {
    await page.goto("/")
    await expect(page).toHaveURL(/login/)
  })
})
```

**Step 4: Add script to package.json**

```json
{
  "test:e2e": "playwright test",
  "test:e2e:ui": "playwright test --ui"
}
```

**Step 5: Commit**

```bash
git add playwright.config.ts tests/ package.json
git commit -m "feat(dashboard): add Playwright E2E setup with smoke tests"
```

---

## Task 20: Final Verification & Cleanup

**Step 1: Run all unit tests**

```bash
cd dashboard && npx vitest run
```

Expected: All tests pass.

**Step 2: Run build**

```bash
cd dashboard && npm run build
```

Expected: Zero TypeScript errors, build succeeds.

**Step 3: Run lint**

```bash
cd dashboard && npm run lint
```

Expected: No errors.

**Step 4: Run E2E smoke tests**

```bash
cd dashboard && npx playwright test
```

Expected: Login page smoke tests pass (auth redirect may fail without running Valinor API, which is expected).

**Step 5: Run Go tests to verify CORS didn't break anything**

```bash
cd /Users/fred/Documents/Valinor && go test ./...
```

Expected: All existing Go tests pass.

**Step 6: Final commit**

```bash
git add -A
git commit -m "chore(dashboard): final verification pass for Phase 9 Slice 1"
```

---

## Summary

| Task | What | Files | Tests |
|------|------|-------|-------|
| 1 | Scaffold Next.js | `dashboard/*` | Build check |
| 2 | Install dependencies | `package.json` | Build check |
| 3 | TypeScript types | `lib/types.ts` | tsc check |
| 4 | Server API client | `lib/api.ts` | `api.test.ts` |
| 5 | Client API client | `lib/api-client.ts` | `api-client.test.ts` |
| 6 | NextAuth config | `lib/auth.ts`, `middleware.ts` | Build check |
| 7 | Providers | `providers/*` | Build check |
| 8 | Sidebar navigation | `components/nav/sidebar*` | `sidebar.test.tsx` |
| 9 | Top bar + user menu | `components/nav/top-bar*` | Build check |
| 10 | Root layout + login | `app/layout.tsx`, `app/(auth)/*` | Build check |
| 11 | TanStack Query hooks | `lib/queries/tenants.ts` | `tenants.test.ts` |
| 12 | Overview dashboard | `components/overview/*` | Build check |
| 13 | Tenant list | `components/tenants/tenant-table*` | Build check |
| 14 | Tenant detail | `components/tenants/tenant-detail*` | Build check |
| 15 | Create tenant form | `components/tenants/create-tenant-form*` | `create-tenant-form.test.tsx` |
| 16 | Loading + error | `app/(dashboard)/loading*` | Build check |
| 17 | Mobile sidebar | `components/nav/mobile-sidebar*` | Build check |
| 18 | CORS on Go API | `internal/platform/server/*` | Go tests |
| 19 | Playwright E2E | `tests/e2e/*` | E2E smoke |
| 20 | Final verification | — | Full suite |
