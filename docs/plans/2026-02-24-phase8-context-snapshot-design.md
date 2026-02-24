# Phase 8 Context Snapshot Persistence Design

## Goal

Replace the `/api/v1/agents/{id}/context` no-op with a real persistent per-user context snapshot and project that snapshot into agent execution requests.

## Decision

Chosen approach: **Snapshot** (single latest context value per tenant + agent + user).

## Why Snapshot

- Fast lookup at dispatch time (single row read).
- Idempotent updates and simple overwrite semantics.
- Lower storage and indexing cost than append-only timeline.
- Matches current product requirement: carry forward latest known user context.

## Architecture

1. Add `agent_context_snapshots` tenant-scoped table with RLS.
2. Add DB-backed user-context store in proxy package.
3. Update `HandleContext` to validate and persist `context` string for caller identity.
4. At message dispatch (`HandleMessage`, `HandleStream`), fetch snapshot and prepend a system message to `messages` payload before sending to agent.
5. Keep fail-closed write path and fail-open read path:
   - if context write fails, return error
   - if context read fails during dispatch, continue without snapshot (with warning log)

## Data Model

Table: `agent_context_snapshots`

- `tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE`
- `agent_id UUID NOT NULL REFERENCES agent_instances(id) ON DELETE CASCADE`
- `user_id TEXT NOT NULL`
- `context TEXT NOT NULL`
- `created_at TIMESTAMPTZ NOT NULL DEFAULT now()`
- `updated_at TIMESTAMPTZ NOT NULL DEFAULT now()`
- Primary key: `(tenant_id, agent_id, user_id)`

RLS policy:
- enforce `tenant_id = current_setting('app.current_tenant_id', true)::UUID` for select/insert/update/delete.

## API Behavior

### `POST /api/v1/agents/{id}/context`

Request body:

```json
{"context":"..."}
```

Behavior:
- validates tenant ownership of agent
- validates authenticated identity + non-empty `context`
- upserts snapshot row
- returns `200 {"status":"applied"}`

### Dispatch projection

For `/api/v1/agents/{id}/message` and `/api/v1/agents/{id}/stream`:
- if snapshot exists for `(tenant, agent, user)`, prepend system message:
  - role: `system`
  - content: `Persisted user context:\n<snapshot>`
- preserve existing role/content compatibility fields.

## Security Notes

- Snapshot storage remains tenant-isolated via RLS.
- Cross-tenant platform-admin access continues to attribute operations to target agent tenant.
- Projection is per authenticated user only; no cross-user context leakage.

## Out Of Scope

- Append-only context timelines.
- Agent-side memory synchronization semantics.
- Context conflict resolution/versioning.

## Verification

- `go test ./internal/proxy -run 'TestHandleContext|TestHandleMessage_InjectsPersistedContext|TestHandleStream_InjectsPersistedContext' -v`
- `go test ./internal/platform/database -run TestRLS_TenantIsolation -v`
- `go test ./... -count=1`
