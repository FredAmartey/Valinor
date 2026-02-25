# Phase 9: Admin Dashboard — Design Document

## Goal

Build the Valinor admin dashboard — a Next.js web application that gives platform admins and tenant admins visibility and control over the Valinor control plane. Phase 9, Slice 1 delivers the application shell (auth, navigation, layout) plus the Overview dashboard and Tenant Management views.

## Scope

### In scope (Slice 1)

- Next.js 15 App Router scaffold with TypeScript strict mode
- Authentication via NextAuth.js v5 wrapping Valinor's existing OIDC + JWT flow
- Navigation shell: collapsible sidebar, top bar with breadcrumbs and user menu
- Overview dashboard (platform admin and tenant admin variants)
- Tenant management: list, detail, create (platform admin only)
- Typed API client with server-side and client-side variants
- TanStack Query v5 for client-side server state
- Skeleton loading states, error boundaries, empty states per section
- Component unit tests (Vitest + RTL) and E2E smoke tests (Playwright)

### Out of scope (future slices)

- User Management view
- Department Management view
- Agent Management view
- RBAC Configuration view
- Audit Dashboard view
- Channels view
- Connectors view
- Visual regression testing
- Performance benchmarks

## Target Users

| Tier | Identification | Dashboard scope |
|------|---------------|-----------------|
| Platform admin | `is_platform_admin: true` on user record | All tenants, global system overview, tenant provisioning |
| Tenant admin | `org_admin` role within their tenant | Own tenant overview, users, departments, agents, channels |

---

## Stack

| Layer | Choice | Rationale |
|-------|--------|-----------|
| Framework | Next.js 15 (App Router) | SSR, layouts, streaming, Suspense, file-based routing |
| Language | TypeScript (strict) | Type safety across API boundary |
| Styling | Tailwind CSS v4 + `@tailwindcss/postcss` | Utility-first, no runtime CSS, v4 native |
| Components | shadcn/ui (customized) | Copy-paste, no version lock-in, full control |
| Server state | TanStack Query v5 | Caching, refetch, deduplication, mutations |
| Auth | NextAuth.js v5 | Native App Router support, custom OIDC provider |
| Fonts | Geist + Geist Mono | High-end sans-serif for dashboard UI |
| Icons | @phosphor-icons/react | Consistent, no emoji, standardized strokeWidth |
| Testing | Vitest + React Testing Library + Playwright | Unit, component, E2E coverage |

---

## Project Structure

```
dashboard/
  src/
    app/
      layout.tsx              # Root layout: fonts, providers, nav shell
      page.tsx                # Overview dashboard (home)
      login/page.tsx          # Login redirect to OIDC
      tenants/
        page.tsx              # Tenant list (platform admin)
        [id]/page.tsx         # Single tenant detail
        new/page.tsx          # Create tenant form
      loading.tsx             # Global loading skeleton
      error.tsx               # Global error boundary
    components/
      ui/                     # shadcn/ui components (customized)
      nav/                    # Sidebar, breadcrumbs, command palette
      overview/               # Overview dashboard widgets
      tenants/                # Tenant-specific components
    lib/
      api.ts                  # Server-side typed API client
      api-client.ts           # Client-side typed API client
      auth.ts                 # NextAuth config + custom OIDC provider
      queries/                # TanStack Query hooks per domain
        tenants.ts
        overview.ts
      types.ts                # TypeScript types matching Go API responses
    providers/
      query-provider.tsx      # "use client" TanStack QueryClientProvider
      session-provider.tsx    # "use client" NextAuth SessionProvider
  tests/
    e2e/                      # Playwright tests
  next.config.ts
  tailwind.config.ts
  tsconfig.json
  package.json
```

---

## Authentication Flow

1. User visits dashboard. NextAuth middleware checks session
2. No session: redirect to `/login`. NextAuth initiates OIDC flow against Valinor `/auth/login`
3. Valinor redirects to external OIDC provider (Google, Okta, etc.)
4. Provider callback hits Valinor `/auth/callback`. Valinor issues JWT (access + refresh)
5. NextAuth receives JWT pair, stores in encrypted HTTP-only session cookie
6. Dashboard API calls attach Valinor JWT as `Authorization: Bearer <token>`
7. Token refresh: NextAuth `jwt` callback checks expiry, calls Valinor `POST /auth/token/refresh` transparently

No standalone auth. Dashboard has zero user/password storage. Purely a client to Valinor's existing OIDC + JWT system.

### Route Protection

- NextAuth middleware on all routes except `/login`
- Platform admin routes (`/tenants/*`): additional `is_platform_admin` claim check
- Tenant-scoped routes: tenant membership check from session

---

## API Client & Data Fetching

### Server-side API client (`lib/api.ts`)

Thin fetch wrapper. Gets session from `getServerSession()`. No caching layer — Next.js request deduplication handles it.

### Client-side API client (`lib/api-client.ts`)

Used in `"use client"` components via TanStack Query. Gets token from NextAuth `useSession()`. TanStack Query handles caching, refetch, deduplication.

### TanStack Query hooks (`lib/queries/*.ts`)

One file per domain. Each exports query hooks and mutation hooks with typed query keys and automatic cache invalidation on mutations.

### Data fetching strategy

| Context | Method | Why |
|---------|--------|-----|
| Server Component initial load | Direct `api()` call | No client JS, streams via Suspense |
| Client interactive data (filter, paginate) | TanStack Query hook | Caching, refetch, optimistic updates |
| Mutations (create, update, delete) | TanStack `useMutation` | Automatic cache invalidation |
| Polling (health, agent status) | TanStack Query `refetchInterval` | Built-in, no manual setInterval |

### Vercel best practices applied

- `async-parallel`: `Promise.all()` for independent fetches in server components
- `server-serialization`: minimize data passed from server to client components
- `async-suspense-boundaries`: each data section in its own `<Suspense>` for streaming
- `bundle-dynamic-imports`: heavy interactive components via `next/dynamic`
- `bundle-barrel-imports`: direct imports only, no barrel files
- `server-parallel-fetching`: restructure components to parallelize fetches

---

## Views

### Overview Dashboard (`/`)

**Platform admin variant:**
- System health strip: API status, DB connection, active VM count (30s refetch)
- Tenant summary: total tenants, active/suspended counts, newest tenants
- Recent audit events: last 10 events across all tenants
- Agent fleet: total running agents, unhealthy count, warm pool size

**Tenant admin variant:**
- Tenant health: active agents, user count, department count
- Recent audit events scoped to tenant
- Channel status: linked platforms, outbox queue depth, failed messages

**Layout:** Asymmetric grid `grid-template-columns: 2fr 1fr` for main/sidebar split.

### Tenant Management

**List view (`/tenants`):** Platform admin only.
- Filterable table: name, slug, status, created date, agent count
- Search with debounced filtering
- Status pills with color coding
- Row click navigates to detail

**Detail view (`/tenants/[id]`):**
- Header: name, slug, status badge, created date
- Stats row: users, departments, agents, connectors (parallel fetch)
- Quick actions: suspend/activate, edit settings

**Create view (`/tenants/new`):**
- Form: name, slug (auto-generated, editable), initial settings
- Label above input, helper text optional, error inline below input

---

## Navigation Shell

### Layout

Top bar (logo, breadcrumbs, user menu) + collapsible sidebar + content area.

### Sidebar

- Expanded on `lg+`, collapsed to icons on `md`, sheet/drawer on `sm`
- Items rendered conditionally by session claims
- Platform admin: Overview, Tenants
- Tenant admin: Overview, Users, Departments, Agents, RBAC, Channels, Connectors, Audit Log
- Active item: `bg-zinc-100` pill. No borders or glows

### Top Bar

- Breadcrumbs derived from route path (Server Component)
- User menu (top-right): initials avatar (`bg-zinc-200 text-zinc-700`), display name, role badge, sign out

### Content Area

- Constrained to `max-w-[1400px] mx-auto` with `px-6 lg:px-8`
- Page content staggered fade-in via CSS `animation-delay`

### Providers

Root layout renders `<Providers>` client component wrapping `SessionProvider` + `QueryProvider`. No global state library beyond these. Local `useState`/`useReducer` for isolated UI.

---

## Design System Rules

Derived from design-taste-frontend skill baseline (DESIGN_VARIANCE: 8, MOTION_INTENSITY: 6, VISUAL_DENSITY: 4).

### Color

- Zinc/Slate neutral base. Single accent: Emerald for healthy/success, muted Rose for alerts/errors
- No purple/neon glows. No AI purple/blue aesthetic
- Saturation under 80% on all accents. No pure black (#000000) — use Zinc-950
- One consistent palette across the entire dashboard

### Typography

- Geist for UI text, Geist Mono for code/data
- Headlines: `tracking-tighter` for tight, premium feel
- Body: `text-base text-zinc-600 leading-relaxed`
- No serif fonts anywhere in the dashboard
- No oversized H1s — hierarchy via weight and color

### Layout

- Asymmetric grids, not equal columns. CSS Grid over flex-math
- Mobile: aggressive single-column fallback (`w-full`, `px-4`) below `md`
- Full-height sections use `min-h-[100dvh]`, never `h-screen`
- Content contained in `max-w-[1400px] mx-auto`

### Components

- Cards only where elevation communicates hierarchy. Otherwise `border-t`, `divide-y`, or spacing
- shadcn/ui customized: radii, colors, shadows match project aesthetic, not defaults
- Forms: label above input, `gap-2` for input blocks, error below
- Status pills, not badges, for tenant/agent status

### Motion

- Skeleton shimmer loaders matching exact layout dimensions (no spinners)
- Staggered fade-in on page content via CSS `animation-delay`
- Spring physics on interactive elements: `type: "spring", stiffness: 100, damping: 20`
- Tactile feedback: `scale-[0.98]` on `:active` for buttons
- All perpetual animations isolated in their own `"use client"` leaf components

### States

- Loading: skeleton loaders per section via Suspense
- Empty: composed illustrations with CTAs
- Error: inline within failed section, retry button, no full-page crashes

### Forbidden

- No emoji anywhere
- No generic avatar SVGs — initials-based avatars
- No generic placeholder names (John Doe, Jane Smith)
- No fake round numbers in demo data
- No Unsplash — use picsum.photos or SVG if needed
- No circular spinners
- No 3-column equal card layouts

---

## Error Handling

### Three layers

1. **API client**: `ApiError` class with status code and parsed body
2. **Route level**: Next.js `error.tsx` per route segment
3. **Component level**: TanStack Query `isError` for inline errors

### Status code behavior

| Status | Behavior |
|--------|----------|
| 400 | Field-level inline errors on forms |
| 401 | Redirect to `/login`, clear session |
| 403 | "You don't have permission" with role context |
| 404 | Clean empty state |
| 500 | "Something went wrong" with retry. No stack traces |

---

## Testing Strategy (Slice 1)

| Layer | Tool | Scope |
|-------|------|-------|
| Component unit | Vitest + React Testing Library | Forms, filters, navigation state |
| API client | Vitest | Request construction, error parsing, token attachment |
| E2E integration | Playwright | Auth flow, tenant CRUD happy path, role-based access |

Test files co-located: `*.test.tsx` next to component. Playwright tests in `tests/e2e/`.

---

## Risks & Rollback

| Risk | Mitigation |
|------|------------|
| OIDC flow mismatch between NextAuth and Valinor | Test auth flow in isolation first. Valinor has dev mode with bypassed OIDC |
| CORS between dashboard and API | Configure Valinor to allow dashboard origin. Fail-fast on first API call |
| shadcn/ui breaking changes | Components are copied in, not imported. Pin versions in generation |
| Scope creep into other views | Strict slice boundary: only Overview + Tenants in Slice 1 |

### Rollback

Dashboard is a separate process with no Go code changes. Rollback is: stop the dashboard process. Valinor API is unaffected.

---

## Acceptance Criteria (Slice 1)

1. `npm run build` succeeds with zero TypeScript errors
2. Platform admin can authenticate via OIDC and see the overview dashboard
3. Platform admin can list, view, and create tenants
4. Tenant admin can authenticate and see their tenant-scoped overview
5. Unauthorized routes return to login or show 403
6. All data sections have skeleton loading states
7. Empty states render when no data exists
8. Error boundaries catch and display API failures gracefully
9. Vitest unit tests pass for API client, forms, and navigation
10. Playwright E2E passes for auth flow and tenant CRUD
11. Mobile layout collapses to single column without horizontal scroll
