# Slice 7: Channels Management UI — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.
> **Frontend skills:** Before writing any component code, invoke `vercel-react-best-practices`, `design-taste-frontend`, `next-best-practices`.

**Goal:** Build the `/channels` dashboard page with tabbed management of channel links, provider credentials, and the outbox delivery queue — completing Phase 9.

**Architecture:** Server component page wrapping a client `ChannelsView` with 3 tab panels. Each tab has its own query hook, table/card component, and CRUD operations. Follows established patterns from agents, users, and audit views.

**Tech Stack:** Next.js 16 (App Router), TypeScript, Tailwind CSS v4, TanStack Query v5, @phosphor-icons/react, Vitest + RTL

**Design doc:** `docs/plans/2026-02-26-slice7-channels-dashboard-design.md`

**Run all commands from:** `dashboard/` directory

---

### Task 1: Add Types

**Files:**
- Modify: `dashboard/src/lib/types.ts`

**Step 1: Add channel types after the existing ChannelLink interface**

Add these types after the existing `ChannelLink` interface (around line 93):

```typescript
export interface ChannelOutbox {
  id: string
  tenant_id: string
  channel_message_id: string
  provider: "slack" | "whatsapp" | "telegram"
  recipient_id: string
  payload: Record<string, unknown>
  status: "pending" | "sending" | "sent" | "dead"
  attempt_count: number
  max_attempts: number
  next_attempt_at: string
  last_error: string | null
  locked_at: string | null
  sent_at: string | null
  created_at: string
  updated_at: string
}

export interface ProviderCredentialResponse {
  provider: "slack" | "whatsapp" | "telegram"
  api_base_url: string
  api_version: string
  phone_number_id: string
  has_access_token: boolean
  has_signing_secret: boolean
  has_secret_token: boolean
  updated_at: string
}

export interface CreateChannelLinkRequest {
  user_id: string
  platform: "slack" | "whatsapp" | "telegram"
  platform_user_id: string
}

export interface UpsertProviderCredentialRequest {
  access_token?: string
  signing_secret?: string
  secret_token?: string
  api_base_url?: string
  api_version?: string
  phone_number_id?: string
}
```

**Step 2: Verify build**

Run: `cd dashboard && npx tsc --noEmit`
Expected: no errors

**Step 3: Commit**

```bash
git add dashboard/src/lib/types.ts
git commit -m "feat(dashboard): add ChannelOutbox, ProviderCredential, and request types"
```

---

### Task 2: Create Query Hooks + Tests

**Files:**
- Create: `dashboard/src/lib/queries/channels.ts`
- Create: `dashboard/src/lib/queries/channels.test.ts`

**Step 1: Write the failing tests**

Create `dashboard/src/lib/queries/channels.test.ts`:

```typescript
import { describe, it, expect, vi } from "vitest"

vi.mock("@/lib/api-client", () => ({
  apiClient: vi.fn(),
}))

describe("channel query functions", () => {
  it("fetchChannelLinks calls correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce([])

    const { fetchChannelLinks } = await import("./channels")
    await fetchChannelLinks("test-token")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/channels/links",
      "test-token",
      undefined,
    )
  })

  it("fetchOutbox calls correct endpoint with status filter", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce([])

    const { fetchOutbox } = await import("./channels")
    await fetchOutbox("test-token", "dead")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/channels/outbox",
      "test-token",
      { params: { status: "dead", limit: "100" } },
    )
  })

  it("fetchProviderCredential calls correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ provider: "slack", has_access_token: true })

    const { fetchProviderCredential } = await import("./channels")
    await fetchProviderCredential("test-token", "slack")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/channels/providers/slack/credentials",
      "test-token",
      undefined,
    )
  })

  it("createChannelLink posts to correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ id: "link-1" })

    const { createChannelLink } = await import("./channels")
    await createChannelLink("test-token", {
      user_id: "u-1",
      platform: "slack",
      platform_user_id: "U12345",
    })

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/channels/links",
      "test-token",
      {
        method: "POST",
        body: JSON.stringify({
          user_id: "u-1",
          platform: "slack",
          platform_user_id: "U12345",
        }),
      },
    )
  })

  it("deleteChannelLink calls correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce(undefined)

    const { deleteChannelLink } = await import("./channels")
    await deleteChannelLink("test-token", "link-1")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/channels/links/link-1",
      "test-token",
      { method: "DELETE" },
    )
  })

  it("requeueOutboxJob posts to correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ status: "requeued" })

    const { requeueOutboxJob } = await import("./channels")
    await requeueOutboxJob("test-token", "job-1")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/channels/outbox/job-1/requeue",
      "test-token",
      { method: "POST" },
    )
  })

  it("upsertProviderCredential puts to correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ provider: "slack" })

    const { upsertProviderCredential } = await import("./channels")
    await upsertProviderCredential("test-token", "slack", {
      access_token: "xoxb-test",
      signing_secret: "secret",
    })

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/channels/providers/slack/credentials",
      "test-token",
      {
        method: "PUT",
        body: JSON.stringify({
          access_token: "xoxb-test",
          signing_secret: "secret",
        }),
      },
    )
  })

  it("deleteProviderCredential calls correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce(undefined)

    const { deleteProviderCredential } = await import("./channels")
    await deleteProviderCredential("test-token", "whatsapp")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/channels/providers/whatsapp/credentials",
      "test-token",
      { method: "DELETE" },
    )
  })
})
```

**Step 2: Run tests to verify they fail**

Run: `cd dashboard && npx vitest run src/lib/queries/channels.test.ts`
Expected: FAIL — module not found

**Step 3: Create the query hooks**

Create `dashboard/src/lib/queries/channels.ts`:

```typescript
"use client"

import { useQuery, useMutation, useQueryClient, keepPreviousData } from "@tanstack/react-query"
import { useSession } from "next-auth/react"
import { apiClient } from "@/lib/api-client"
import type {
  ChannelLink,
  ChannelOutbox,
  ProviderCredentialResponse,
  CreateChannelLinkRequest,
  UpsertProviderCredentialRequest,
} from "@/lib/types"

export const channelKeys = {
  all: ["channels"] as const,
  links: () => [...channelKeys.all, "links"] as const,
  outbox: (status?: string) => [...channelKeys.all, "outbox", status ?? "all"] as const,
  provider: (name: string) => [...channelKeys.all, "provider", name] as const,
}

// --- Fetch functions ---

export async function fetchChannelLinks(accessToken: string): Promise<ChannelLink[]> {
  return apiClient<ChannelLink[]>("/api/v1/channels/links", accessToken, undefined)
}

export async function fetchOutbox(
  accessToken: string,
  status?: string,
): Promise<ChannelOutbox[]> {
  const params: Record<string, string> = { limit: "100" }
  if (status && status !== "all") {
    params.status = status
  }
  return apiClient<ChannelOutbox[]>("/api/v1/channels/outbox", accessToken, { params })
}

export async function fetchProviderCredential(
  accessToken: string,
  provider: string,
): Promise<ProviderCredentialResponse> {
  return apiClient<ProviderCredentialResponse>(
    `/api/v1/channels/providers/${provider}/credentials`,
    accessToken,
    undefined,
  )
}

// --- Mutation functions ---

export async function createChannelLink(
  accessToken: string,
  data: CreateChannelLinkRequest,
): Promise<ChannelLink> {
  return apiClient<ChannelLink>("/api/v1/channels/links", accessToken, {
    method: "POST",
    body: JSON.stringify(data),
  })
}

export async function deleteChannelLink(accessToken: string, id: string): Promise<void> {
  return apiClient<void>(`/api/v1/channels/links/${id}`, accessToken, {
    method: "DELETE",
  })
}

export async function requeueOutboxJob(accessToken: string, id: string): Promise<void> {
  return apiClient<void>(`/api/v1/channels/outbox/${id}/requeue`, accessToken, {
    method: "POST",
  })
}

export async function upsertProviderCredential(
  accessToken: string,
  provider: string,
  data: UpsertProviderCredentialRequest,
): Promise<ProviderCredentialResponse> {
  return apiClient<ProviderCredentialResponse>(
    `/api/v1/channels/providers/${provider}/credentials`,
    accessToken,
    { method: "PUT", body: JSON.stringify(data) },
  )
}

export async function deleteProviderCredential(
  accessToken: string,
  provider: string,
): Promise<void> {
  return apiClient<void>(
    `/api/v1/channels/providers/${provider}/credentials`,
    accessToken,
    { method: "DELETE" },
  )
}

// --- Query hooks ---

export function useChannelLinksQuery() {
  const { data: session } = useSession()
  return useQuery({
    queryKey: channelKeys.links(),
    queryFn: () => fetchChannelLinks(session!.accessToken),
    enabled: !!session?.accessToken,
    staleTime: 30_000,
  })
}

export function useOutboxQuery(status?: string) {
  const { data: session } = useSession()
  return useQuery({
    queryKey: channelKeys.outbox(status),
    queryFn: () => fetchOutbox(session!.accessToken, status),
    enabled: !!session?.accessToken,
    refetchInterval: status === "pending" || status === "sending" ? 10_000 : undefined,
    placeholderData: keepPreviousData,
  })
}

export function useProviderCredentialQuery(provider: string) {
  const { data: session } = useSession()
  return useQuery({
    queryKey: channelKeys.provider(provider),
    queryFn: () => fetchProviderCredential(session!.accessToken, provider),
    enabled: !!session?.accessToken,
    retry: false,
  })
}

// --- Mutation hooks ---

export function useCreateChannelLinkMutation() {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: CreateChannelLinkRequest) =>
      createChannelLink(session!.accessToken, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: channelKeys.links() })
    },
  })
}

export function useDeleteChannelLinkMutation() {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => deleteChannelLink(session!.accessToken, id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: channelKeys.links() })
    },
  })
}

export function useRequeueOutboxMutation() {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => requeueOutboxJob(session!.accessToken, id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: channelKeys.all })
    },
  })
}

export function useUpsertProviderCredentialMutation(provider: string) {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: UpsertProviderCredentialRequest) =>
      upsertProviderCredential(session!.accessToken, provider, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: channelKeys.provider(provider) })
    },
  })
}

export function useDeleteProviderCredentialMutation(provider: string) {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: () => deleteProviderCredential(session!.accessToken, provider),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: channelKeys.provider(provider) })
    },
  })
}
```

**Step 4: Run tests**

Run: `cd dashboard && npx vitest run src/lib/queries/channels.test.ts`
Expected: PASS (8 tests)

**Step 5: Commit**

```bash
git add dashboard/src/lib/queries/channels.ts dashboard/src/lib/queries/channels.test.ts
git commit -m "feat(dashboard): add channel query hooks and tests"
```

---

### Task 3: Create Links Tab Component

**Files:**
- Create: `dashboard/src/components/channels/links-tab.tsx`

**Step 1: Create the component**

This component renders the links table with filters, create dialog, and revoke action. Follow the agent-grid.tsx pattern for filters/loading/empty/error states. Use a simple `useState`-controlled dialog for create (no separate route).

Include:
- Platform filter dropdown (all/slack/whatsapp/telegram)
- State filter dropdown (all/verified/pending_verification/revoked)
- Table with columns: Platform, Platform User ID, User ID, State (pill), Created, Actions
- Create button opens inline form/dialog
- Revoke button with confirmation (`window.confirm`)
- Platform icons from `@phosphor-icons/react`: `SlackLogo`, `WhatsappLogo`, `TelegramLogo`

State pill colors: verified=emerald, pending_verification=amber, revoked=zinc

**Step 2: Verify build**

Run: `cd dashboard && npx tsc --noEmit`

**Step 3: Commit**

```bash
git add dashboard/src/components/channels/links-tab.tsx
git commit -m "feat(dashboard): add channel links tab with CRUD"
```

---

### Task 4: Create Providers Tab Component

**Files:**
- Create: `dashboard/src/components/channels/providers-tab.tsx`

**Step 1: Create the component**

Renders 3 provider cards (Slack, WhatsApp, Telegram) in a responsive grid. Each card shows:
- Provider name + icon
- Status indicators (has_access_token, has_signing_secret, has_secret_token) with Check/Minus icons
- Metadata fields (api_base_url, api_version, phone_number_id)
- Last updated
- Edit button → opens a modal/dialog with credential input fields
- Delete button with confirmation

The edit modal shows empty password-type inputs with placeholder "Enter new value to update". Fields are conditional per provider:
- Slack: access_token, signing_secret
- WhatsApp: access_token, signing_secret, phone_number_id, api_base_url, api_version
- Telegram: access_token, secret_token

Use `useProviderCredentialQuery` for each provider. Handle 404 gracefully (provider not configured yet — show "Not configured" state with setup button).

**Step 2: Verify build**

Run: `cd dashboard && npx tsc --noEmit`

**Step 3: Commit**

```bash
git add dashboard/src/components/channels/providers-tab.tsx
git commit -m "feat(dashboard): add provider credentials tab with edit/delete"
```

---

### Task 5: Create Outbox Tab Component

**Files:**
- Create: `dashboard/src/components/channels/outbox-tab.tsx`

**Step 1: Create the component**

Renders status tabs (All/Pending/Sending/Sent/Dead) with a table below. Follow the audit-log pattern for tab-based filtering.

- Status tabs change the `status` param passed to `useOutboxQuery`
- Table columns: Provider (badge), Recipient (mono, truncated), Status (pill), Attempts ("3/5"), Next Attempt (formatTimeAgo), Last Error (truncated, title attr), Actions
- Requeue button visible only on dead jobs
- Provider filter dropdown (client-side)
- Polling enabled for pending/sending tabs

Status pill colors: pending=amber, sending=blue, sent=emerald, dead=rose

**Step 2: Verify build**

Run: `cd dashboard && npx tsc --noEmit`

**Step 3: Commit**

```bash
git add dashboard/src/components/channels/outbox-tab.tsx
git commit -m "feat(dashboard): add outbox tab with status tabs and requeue"
```

---

### Task 6: Create ChannelsView and Page

**Files:**
- Create: `dashboard/src/components/channels/channels-view.tsx`
- Create: `dashboard/src/app/(dashboard)/channels/page.tsx`

**Step 1: Create the ChannelsView client component**

A tabbed container that renders LinksTab, ProvidersTab, or OutboxTab based on active tab state. Use simple `useState` for tab selection with styled tab buttons.

```typescript
"use client"

import { useState } from "react"
import { LinksTab } from "./links-tab"
import { ProvidersTab } from "./providers-tab"
import { OutboxTab } from "./outbox-tab"

const TABS = [
  { id: "links", label: "Links" },
  { id: "providers", label: "Providers" },
  { id: "outbox", label: "Outbox" },
] as const

type TabId = typeof TABS[number]["id"]

export function ChannelsView() {
  const [activeTab, setActiveTab] = useState<TabId>("links")

  return (
    <div className="space-y-6">
      <div className="flex gap-1 border-b border-zinc-200">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-2 text-sm font-medium transition-colors ${
              activeTab === tab.id
                ? "border-b-2 border-zinc-900 text-zinc-900"
                : "text-zinc-500 hover:text-zinc-700"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>
      {activeTab === "links" && <LinksTab />}
      {activeTab === "providers" && <ProvidersTab />}
      {activeTab === "outbox" && <OutboxTab />}
    </div>
  )
}
```

**Step 2: Create the page server component**

Create `dashboard/src/app/(dashboard)/channels/page.tsx`:

```typescript
import { auth } from "@/lib/auth"
import { hasPermission } from "@/lib/permissions"
import { ChannelsView } from "@/components/channels/channels-view"
import { ChatCircle } from "@phosphor-icons/react/dist/ssr"

export default async function ChannelsPage() {
  const session = await auth()
  const canRead = hasPermission(
    session?.user?.isPlatformAdmin ?? false,
    session?.user?.roles ?? [],
    "channels:links:read",
  )

  if (!canRead) {
    return (
      <div className="py-12 text-center">
        <p className="text-sm font-medium text-zinc-900">Access denied</p>
        <p className="mt-1 text-sm text-zinc-500">You do not have permission to manage channels.</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <ChatCircle size={24} className="text-zinc-400" />
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">Channels</h1>
          <p className="mt-1 text-sm text-zinc-500">Manage platform links, provider credentials, and delivery queue.</p>
        </div>
      </div>
      <ChannelsView />
    </div>
  )
}
```

**Step 3: Verify build**

Run: `cd dashboard && npm run build`
Expected: success

**Step 4: Commit**

```bash
git add dashboard/src/components/channels/channels-view.tsx dashboard/src/app/\(dashboard\)/channels/page.tsx
git commit -m "feat(dashboard): add /channels page with tabbed ChannelsView"
```

---

### Task 7: Add Component Tests

**Files:**
- Create: `dashboard/src/components/channels/channels-view.test.tsx`

**Step 1: Write tests**

Test the ChannelsView component and each tab's basic states (loading, error, empty, data). Mock the query hooks. Test tab switching.

Cover:
- Tab switching renders correct tab content
- Links tab: loading skeleton, error with retry, empty state, populated table
- Providers tab: renders 3 provider cards
- Outbox tab: loading skeleton, empty state, data with requeue button on dead jobs

**Step 2: Run tests**

Run: `cd dashboard && npx vitest run src/components/channels/`
Expected: PASS

**Step 3: Commit**

```bash
git add dashboard/src/components/channels/channels-view.test.tsx
git commit -m "test(dashboard): add channels component tests"
```

---

### Task 8: Final Verification

**Step 1: Run all dashboard tests**

Run: `cd dashboard && npx vitest run`
Expected: ALL PASS

**Step 2: Build**

Run: `cd dashboard && npm run build`
Expected: success with zero errors

**Step 3: Type check**

Run: `cd dashboard && npx tsc --noEmit`
Expected: no errors

**Step 4: Open PR**

```bash
git push origin feature/slice7-channels-dashboard
gh pr create --title "feat(dashboard): add channels management page with links, providers, and outbox tabs" --body "$(cat <<'EOF'
## Summary
- Add `/channels` page with 3 tabs: Links, Providers, Outbox
- Links tab: list/create/revoke user-platform identity mappings
- Providers tab: view/edit/delete per-provider credentials (Slack, WhatsApp, Telegram)
- Outbox tab: view delivery queue by status with requeue for dead jobs
- Completes Phase 9 admin dashboard (7/7 slices)

## Test Plan
- [x] Query hook tests for all fetch and mutation functions
- [x] Component tests for tab switching, loading/error/empty states
- [x] Full test suite passes
- [x] Build succeeds with zero TypeScript errors
EOF
)"
```

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
