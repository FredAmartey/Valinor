# Phase 9, Slice 7: Channels Management UI — Design Document

## Goal

Build the `/channels` dashboard page with tabbed management of channel links, provider credentials, and the outbox delivery queue. This is the final slice of Phase 9, completing the admin dashboard.

## Delivery

Single PR. All backend APIs exist — this is purely frontend.

---

## Page & Layout

- Route: `/channels`
- Server component: permission check with `channels:links:read`
- Client component: `<ChannelsView />` with 3 tabs

| Tab | Content | Read Permission | Write Permission |
|-----|---------|-----------------|------------------|
| Links | User-platform identity table | `channels:links:read` | `channels:links:write` |
| Providers | Per-provider credential cards | `channels:providers:read` | `channels:providers:write` |
| Outbox | Delivery queue table | `channels:outbox:read` | `channels:outbox:write` |

---

## Tab 1: Links

### Table

| Column | Width | Content |
|--------|-------|---------|
| Platform | `100px` | Icon + name badge (Slack/WhatsApp/Telegram) |
| Platform User ID | `1fr` | Monospace, truncated |
| Valinor User | `1fr` | Truncated user_id |
| State | `140px` | Pill: verified=emerald, pending=amber, revoked=zinc |
| Created | `120px` | `formatTimeAgo` |
| Actions | `80px` | Revoke button (disabled if already revoked) |

### Filters

- Platform: all / slack / whatsapp / telegram
- State: all / verified / pending_verification / revoked

### Create Link Dialog

Modal with fields:
- User ID (text input)
- Platform (dropdown: slack / whatsapp / telegram)
- Platform User ID (text input)

POST to `POST /api/v1/channels/links`.

### Revoke

DELETE to `DELETE /api/v1/channels/links/{id}` with confirmation.

---

## Tab 2: Providers

### Layout

3 cards in a responsive grid (`grid-cols-1 md:grid-cols-3`), one per provider.

### Card Content

- Provider name + icon (SlackLogo, WhatsappLogo, TelegramLogo from Phosphor)
- Status indicators with green check or grey dash:
  - Access Token
  - Signing Secret (Slack, WhatsApp)
  - Secret Token (Telegram)
- Metadata: API base URL, API version, phone number ID (WhatsApp only)
- Last updated timestamp
- Actions: Edit button, Delete button (with confirmation)

### Edit Credential Modal

Conditional fields per provider:
- **Slack:** access_token, signing_secret
- **WhatsApp:** access_token, signing_secret, phone_number_id, api_base_url, api_version
- **Telegram:** access_token, secret_token

PUT to `PUT /api/v1/channels/providers/{provider}/credentials`.

Existing secret values are never shown (API returns `has_*` booleans only). Form shows empty inputs with placeholder "Enter new value to update".

### Delete Credential

DELETE to `DELETE /api/v1/channels/providers/{provider}/credentials` with confirmation dialog.

---

## Tab 3: Outbox

### Status Tabs

Horizontal tab bar: All | Pending | Sending | Sent | Dead

### Table

| Column | Width | Content |
|--------|-------|---------|
| Provider | `100px` | Badge |
| Recipient | `1fr` | Monospace, truncated |
| Status | `100px` | Pill: pending=amber, sending=blue, sent=emerald, dead=rose |
| Attempts | `80px` | "3/5" format |
| Next Attempt | `120px` | `formatTimeAgo`, or dash if sent/dead |
| Last Error | `1fr` | Truncated, full value on hover via title attr |
| Actions | `80px` | Requeue button (dead jobs only) |

### Filters

- Status tab (maps to `?status=` API param)
- Provider dropdown (client-side filter)

### Polling

`refetchInterval: 10_000` for pending/sending status tabs.

### Requeue

POST to `POST /api/v1/channels/outbox/{id}/requeue` on dead jobs. Invalidates outbox query cache on success.

---

## Types

Add to `dashboard/src/lib/types.ts`:

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

## Query Hook

New `dashboard/src/lib/queries/channels.ts`:
- Factory keys: `channelKeys.all`, `.links()`, `.outbox(status)`, `.provider(name)`
- Fetch functions for all 3 areas
- Mutation hooks: createLink, deleteLink, requeueOutbox, upsertCredential, deleteCredential
- Cache invalidation on mutations

## States

All 3 tabs: skeleton loading, error with retry, empty with CTA, populated with data.

## Tests

- Query hook tests (verify endpoint construction)
- Component tests per tab (loading, empty, data, interactions)

---

## Acceptance Criteria

1. `/channels` page renders with 3 tabs
2. Links tab lists links with platform/state filters and create/revoke actions
3. Providers tab shows 3 provider cards with status indicators and edit/delete
4. Outbox tab lists jobs with status tabs and requeue on dead jobs
5. All CRUD operations work through the API
6. Loading/empty/error states on every tab
7. Permission gating on page and action buttons
8. `npm run build` succeeds with zero TypeScript errors
9. Vitest tests pass for query hooks and components

## Risks & Rollback

| Risk | Mitigation |
|------|------------|
| Provider credential form exposes no existing values | By design — API never returns secrets. UX clearly indicates "enter new value" |
| Outbox can be large | Status tab filters hit the API with `?status=`, limit defaults to 100 |

Rollback: revert dashboard PR. No backend changes.
