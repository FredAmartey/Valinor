# Phase 8 Channel Outbox Design (Provider-Agnostic, V1)

## Goal

Add a provider-agnostic outbound delivery reliability layer so channel execution outcomes can be delivered asynchronously and safely, without coupling execution success to immediate provider availability.

This design covers the first production-safe outbox slice after channel execution-path merge.

## Scope

### In Scope

- New tenant-scoped `channel_outbox` persistence model with RLS isolation.
- Outbox enqueue on successful channel execution (`executed`) only.
- Fail-closed behavior when enqueue fails: request returns `500` and message status is persisted as `dispatch_failed`.
- In-process outbox dispatcher worker in `valinor`.
- Provider adapter interface with stub/no-op implementation (no real provider API call yet).
- Retry and dead-letter handling in same table.

### Out of Scope (Deferred)

- Real WhatsApp/Slack/Telegram outbound API calls.
- User-facing delivery for denied/error execution outcomes (`denied_*`, `dispatch_failed`).
- Outbox admin/read/requeue HTTP endpoints.
- External queue system or separate worker binary.

## Product Intent

This is the infrastructure layer that makes channel responses dependable under transient provider/network issues.

Expected product impact:

- Successful executions are eventually delivered, not dropped on temporary failure.
- Ops can inspect whether delivery is `pending`, `sent`, or `dead`.
- Multi-provider delivery can be added via adapters without reworking execution logic.

## Key Decisions

1. **Provider-agnostic outbox first** rather than provider-specific direct send.
2. **Enqueue only `executed` replies in V1** to keep policy/UX messaging out of infra slice.
3. **In-process dispatcher worker** in `valinor` for fastest operational adoption.
4. **Fail-closed on enqueue failure**: return `500` and persist `dispatch_failed`.
5. **Retry policy**: max 5 attempts with light backoff + jitter.
6. **Dead-letter persistence** in same table (`status=dead`, `last_error`).
7. **No external outbox API in V1**.

## Architecture

### Current

`ingress (verify/idempotency/link) -> execution (RBAC/sentinel/agent dispatch)`

### Target V1

`ingress -> execution -> enqueue outbox job -> async worker claims/sends/retries`

Execution remains synchronous through agent dispatch. Provider delivery becomes asynchronous and retriable.

## Data Model

Add table: `channel_outbox`

- `id UUID PRIMARY KEY DEFAULT gen_random_uuid()`
- `tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE`
- `channel_message_id UUID NOT NULL REFERENCES channel_messages(id) ON DELETE CASCADE`
- `provider TEXT NOT NULL`
- `recipient_id TEXT NOT NULL`
- `payload JSONB NOT NULL`
- `status TEXT NOT NULL` (`pending|sending|sent|dead`)
- `attempt_count INT NOT NULL DEFAULT 0`
- `max_attempts INT NOT NULL DEFAULT 5`
- `next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now()`
- `last_error TEXT`
- `locked_at TIMESTAMPTZ`
- `sent_at TIMESTAMPTZ`
- `created_at TIMESTAMPTZ NOT NULL DEFAULT now()`
- `updated_at TIMESTAMPTZ NOT NULL DEFAULT now()`

### Constraints and Indexes

- Check constraint on `status` values.
- Index `(tenant_id, status, next_attempt_at)`.
- Partial index for active work (`status IN ('pending','sending')`).
- Index on `channel_message_id`.

### Isolation

- Enable RLS.
- Tenant policy aligned with existing channel tables:
  - `tenant_id = current_setting('app.current_tenant_id', true)::UUID`

## Outbox State Machine

1. **`pending` -> `sending`** when worker claims a job (`FOR UPDATE SKIP LOCKED`).
2. **`sending` -> `sent`** on adapter success (`sent_at` set).
3. **`sending` -> `pending`** on failure when attempts remain:
   - increment `attempt_count`
   - compute `next_attempt_at` using light backoff + jitter
   - set `last_error`
4. **`sending` -> `dead`** when max attempts reached:
   - set `last_error`

### Crash Recovery

Worker periodically reclaims stale `sending` rows (`locked_at` older than threshold) back to `pending`.

## Execution Integration

- Extend channel execution result shape to include response content for outbound payload construction.
- On `executed`:
  - write outbox row with normalized payload.
- On enqueue failure:
  - treat as dispatch failure path for channel message status persistence.
  - return `500` to upstream webhook caller (fail-closed).

`accepted` remains initial ingress reservation state only and is not re-persisted by terminal status update logic.

## Dispatcher Worker

New in-process loop started from `cmd/valinor/main.go` when channel ingress is enabled.

Responsibilities:

- Poll due jobs (`status=pending`, `next_attempt_at <= now()`).
- Claim jobs safely (`SKIP LOCKED`).
- Invoke provider adapter.
- Persist success/retry/dead transition atomically per job.
- Emit logs/audit metadata for send and failure outcomes.

## Provider Adapter Abstraction (V1)

Define outbound sender interface in channels domain:

- Input: provider, recipient, normalized payload, correlation metadata.
- Output: success/error.

V1 implementation:

- Stub/no-op adapter for wiring and deterministic tests.
- No real provider network call.

## Configuration

Add channel outbox worker config defaults:

- `channels.outbox.enabled` (default true when channels ingress enabled)
- `channels.outbox.poll_interval_seconds`
- `channels.outbox.claim_batch_size`
- `channels.outbox.lock_timeout_seconds`
- `channels.outbox.max_attempts` (default 5)
- `channels.outbox.base_retry_seconds` (base retry interval)
- jitter bounds

Environment variable overrides follow existing `VALINOR_...` mapping.

## Observability

- Structured logs on claim/send/retry/dead transitions.
- Structured error logging on enqueue failure and dead-letter transitions.
- Preserve `correlation_id` and `channel_message_id` across outbox rows/logs.

## Testing Strategy

### Unit Tests

- Retry schedule calculation (bounded backoff + jitter behavior).
- State transitions: pending->sending->sent/retry/dead.
- Worker claim/reclaim semantics.
- Adapter error propagation.

### Integration Tests

- Tenant isolation for outbox table under RLS.
- Concurrent workers do not double-claim same row.
- Enqueue failure path forces `dispatch_failed` status and `500` response.

### Regression Tests

- Existing channels ingress/execution tests remain green.
- Full `go test ./...` remains green.

## Risks and Mitigations

1. **Retry storms during provider outage**
   - Mitigation: light backoff + jitter; bounded max attempts.
2. **Rows stuck in `sending` after crashes**
   - Mitigation: stale-lock reclaim sweep.
3. **Policy coupling too early (denial messaging)**
   - Mitigation: V1 sends only `executed` responses.
4. **Operational blind spots**
   - Mitigation: structured logs + persisted dead-letter state.

## Rollout Plan

1. Deploy schema + worker disabled.
2. Enable outbox worker in staging with stub adapter.
3. Verify enqueue/transition/dead-letter behavior and logs.
4. Follow-up PR: real provider adapter (WhatsApp first) using same outbox contract.

## Verification Commands

- `go test ./internal/channels -v`
- `go test ./cmd/valinor -v`
- `go test ./...`
