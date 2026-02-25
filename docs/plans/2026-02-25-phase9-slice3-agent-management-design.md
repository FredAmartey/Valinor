# Phase 9 Slice 3: Agent Management — Design Document

## Goal

Add Agent Management view to the admin dashboard, enabling tenant admins to view agent status with live health updates, configure tool allowlists, provision new agents, and destroy existing ones.

## Scope

### In scope

- Agent card grid with live-updating status indicators (10s polling)
- Status filter (all/running/unhealthy/provisioning)
- Agent detail page with config, tool allowlist, health info
- Inline configure flow (JSON config + tool allowlist editor)
- Destroy agent with confirmation dialog
- Provision agent form (user, department, config)
- TanStack Query hooks for agents (shared, replacing overview's local definition)
- Skeleton loading states, empty states
- Vitest tests for query hooks, status badge, provision form, config editor

### Out of scope

- Live console / streaming agent responses (future slice)
- Agent log viewing
- VM-level metrics (CPU, memory)

## No Go API Changes

All required endpoints already exist:

| Endpoint | Method | Permission |
|----------|--------|------------|
| `/api/v1/agents` | GET, POST | `agents:read`, `agents:write` |
| `/api/v1/agents/{id}` | GET | `agents:read` |
| `/api/v1/agents/{id}` | DELETE | `agents:write` |
| `/api/v1/agents/{id}/configure` | POST | `agents:write` |

---

## Agent List (`/agents`)

Card grid instead of table — agents are operational entities with richer visual state.

- Grid layout: `grid-cols-1 md:grid-cols-2 xl:grid-cols-3`
- Each card shows: status dot (color), agent ID (truncated monospace), assigned user, department, VM driver, last health check, created date
- Status dot colors with subtle animation:
  - `running` → emerald with pulse animation (CSS `animate-pulse`, isolated)
  - `provisioning` / `warm` → amber
  - `unhealthy` → rose
  - `destroying` / `destroyed` → zinc-400
- Live polling: TanStack Query `refetchInterval: 10_000` (10s)
- Filter bar: status dropdown (all/running/unhealthy/provisioning), search by user or ID
- "Provision agent" button top-right
- Card click → agent detail
- Empty state: "No agents running. Provision your first agent to get started."

---

## Agent Detail (`/agents/[id]`)

- Header: Agent ID (monospace, truncated with full ID tooltip), status badge, created date
- Health strip: last health check timestamp, consecutive failures count, VM driver type. Auto-refreshes every 10s
- Info section: assigned user (link), department (link), vsock CID (monospace), VM ID (monospace)
- Config section: current config as formatted JSON in `pre` block with Geist Mono
- Tool Allowlist section: tools as pills. Empty → "No tool restrictions"
- Actions:
  - "Configure" button → toggles inline editor
  - "Destroy" button → confirmation dialog, calls DELETE, redirects to list

### Configure Flow (inline)

- Toggle between view and edit mode
- Edit mode: JSON textarea for config, comma-separated text input for tool allowlist
- Submit calls `POST /api/v1/agents/{id}/configure`
- Success: cache invalidation refreshes detail
- Error: inline message (e.g., "Config violates runtime policy")

---

## Provision Agent (`/agents/new`)

- Form: user (optional dropdown from tenant users), department (optional dropdown), config (optional JSON textarea)
- Non-admin users auto-fill their own user ID
- On success → redirect to agent detail
- Same form patterns as previous slices

---

## Data Layer

### Agent Query Hooks (`lib/queries/agents.ts`)

Shared file replacing the local `agentKeys` in `platform-overview.tsx`:

- `agentKeys` factory: `all`, `list()`, `detail(id)`
- `fetchAgents(accessToken)`, `fetchAgent(accessToken, id)`
- `useAgentsQuery(statusFilter?)` — `refetchInterval: 10_000`
- `useAgentQuery(id)` — `refetchInterval: 10_000`
- `useProvisionAgentMutation()`
- `useDestroyAgentMutation()`
- `useConfigureAgentMutation(id)`

Update `platform-overview.tsx` to import from shared hooks.

### New Types

```typescript
interface ProvisionAgentRequest {
  user_id?: string
  department_id?: string
  config?: Record<string, unknown>
}

interface ConfigureAgentRequest {
  config: Record<string, unknown>
  tool_allowlist: string[]
}
```

---

## Testing

| Layer | What |
|-------|------|
| Agent query functions (Vitest) | Correct endpoints, methods, body shapes |
| Agent status badge (Vitest + RTL) | Correct colors per status |
| Provision form (Vitest + RTL) | Renders fields, submit behavior |
| Config editor (Vitest + RTL) | JSON textarea, tool allowlist input |

---

## Acceptance Criteria

1. Tenant admin can view agent card grid with live-updating status indicators
2. Status filter works (all/running/unhealthy/provisioning)
3. Tenant admin can view agent detail with config, tools, health info
4. Tenant admin can configure agent inline (config + tool allowlist)
5. Tenant admin can destroy an agent with confirmation
6. Tenant admin can provision a new agent
7. All views have skeleton loading states and empty states
8. `npm run build` succeeds, `npx vitest run` passes

---

## Risks & Rollback

| Risk | Mitigation |
|------|------------|
| 10s polling causes excessive API load | TanStack Query deduplicates. Can increase interval if needed |
| JSON config editing error-prone | Validate JSON client-side before submit. Show parse errors inline |
| Destroy is irreversible | Confirmation dialog with agent ID displayed |

Rollback: Remove new route files. No Go changes to revert.
