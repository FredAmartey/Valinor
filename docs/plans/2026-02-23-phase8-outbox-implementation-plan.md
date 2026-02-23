# Phase 8 Provider-Agnostic Outbox Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a tenant-isolated provider-agnostic outbox with in-process retries so executed channel responses are delivered reliably.

**Architecture:** Persist outbound jobs in a new `channel_outbox` table, enqueue only successful `executed` responses, and run an in-process dispatcher loop that claims jobs, attempts provider send through an adapter interface, retries with bounded backoff+jitter, then dead-letters after max attempts. Keep fail-closed behavior: if enqueue fails, return `500` and persist `dispatch_failed`.

**Tech Stack:** Go, PostgreSQL, pgx, existing RLS tenant model, Testcontainers integration tests.

---

### Task 1: Add Outbox Schema and RLS

**Files:**
- Create: `migrations/000011_channel_outbox.up.sql`
- Create: `migrations/000011_channel_outbox.down.sql`
- Modify: `internal/platform/database/rls_test.go`

**Step 1: Write the failing test**

Add `channel_outbox` to the RLS table list in `TestRLS_TenantIsolation`.

```go
tables := []string{
    "users",
    // ...
    "channel_messages",
    "channel_outbox",
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/platform/database -run TestRLS_TenantIsolation -v`
Expected: FAIL with relation/table missing for `channel_outbox`.

**Step 3: Write minimal implementation**

Create migration with:
- `channel_outbox` table
- `status` check constraint (`pending|sending|sent|dead`)
- RLS policy using `app.current_tenant_id`
- indexes on `(tenant_id, status, next_attempt_at)`, partial active-work index, `channel_message_id`

Down migration drops policy/table/indexes.

**Step 4: Run test to verify it passes**

Run: `go test ./internal/platform/database -run TestRLS_TenantIsolation -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add migrations/000011_channel_outbox.* internal/platform/database/rls_test.go
git commit -m "feat(channels): add tenant-isolated channel outbox schema"
```

### Task 2: Add Outbox Domain Types and Store Enqueue/Claim

**Files:**
- Modify: `internal/channels/channels.go`
- Modify: `internal/channels/store.go`
- Modify: `internal/channels/store_test.go`

**Step 1: Write the failing test**

Add `TestOutboxStore_EnqueueAndClaim` in `store_test.go`.

```go
func TestOutboxStore_EnqueueAndClaim(t *testing.T) {
    // enqueue one job, claim due jobs, assert one claimed with status "sending"
}
```

Include assertions for:
- tenant scoping
- `attempt_count == 0`
- status transition `pending -> sending`

**Step 2: Run test to verify it fails**

Run: `go test ./internal/channels -run TestOutboxStore_EnqueueAndClaim -v`
Expected: FAIL with undefined outbox methods/types.

**Step 3: Write minimal implementation**

Add outbox domain model/constants/errors in `channels.go`:
- `OutboxStatusPending`, `OutboxStatusSending`, `OutboxStatusSent`, `OutboxStatusDead`
- `ErrOutboxNotFound`, validation errors as needed.

Add store methods in `store.go`:
- `EnqueueOutbound(...)`
- `ClaimPendingOutbox(...)` using `FOR UPDATE SKIP LOCKED`

**Step 4: Run test to verify it passes**

Run: `go test ./internal/channels -run TestOutboxStore_EnqueueAndClaim -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add internal/channels/channels.go internal/channels/store.go internal/channels/store_test.go
git commit -m "feat(channels): add outbox enqueue and claim store APIs"
```

### Task 3: Add Retry, Dead-Letter, and Stale-Lock Recovery Store Operations

**Files:**
- Modify: `internal/channels/store.go`
- Modify: `internal/channels/store_test.go`

**Step 1: Write the failing tests**

Add tests:
- `TestOutboxStore_MarkSent`
- `TestOutboxStore_MarkRetry`
- `TestOutboxStore_MarkDead`
- `TestOutboxStore_RecoverStaleSending`

```go
require.NoError(t, store.MarkOutboxRetry(ctx, q, outboxID, nextAttempt, "provider timeout"))
```

Assert correct transitions and metadata (`attempt_count`, `next_attempt_at`, `last_error`, `sent_at`).

**Step 2: Run tests to verify failures**

Run: `go test ./internal/channels -run TestOutboxStore_ -v`
Expected: FAIL with missing methods/fields.

**Step 3: Write minimal implementation**

Implement in `store.go`:
- `MarkOutboxSent`
- `MarkOutboxRetry`
- `MarkOutboxDead`
- `RecoverStaleSending`

All methods tenant-scoped via current tenant setting.

**Step 4: Run tests to verify pass**

Run: `go test ./internal/channels -run TestOutboxStore_ -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add internal/channels/store.go internal/channels/store_test.go
git commit -m "feat(channels): add outbox retry, dead-letter, and recovery transitions"
```

### Task 4: Extend Execution Result and Enqueue in Handler (Fail-Closed)

**Files:**
- Modify: `internal/channels/execution.go`
- Modify: `internal/channels/handler.go`
- Modify: `internal/channels/handler_test.go`
- Modify: `cmd/valinor/channels_execution.go`
- Modify: `cmd/valinor/channels_execution_test.go`

**Step 1: Write the failing tests**

Add tests:
- `TestHandleWebhook_ExecutedEnqueuesOutbox`
- `TestHandleWebhook_EnqueueFailureReturns500AndDispatchFailed`

```go
h.enqueueOutbound = func(...) error { return errors.New("enqueue failed") }
require.Equal(t, http.StatusInternalServerError, w.Code)
```

Update executor tests to assert response content is carried in `ExecutionResult`.

**Step 2: Run tests to verify failures**

Run: `go test ./internal/channels ./cmd/valinor -run 'Outbox|Execution' -v`
Expected: FAIL with missing enqueue hook/response field.

**Step 3: Write minimal implementation**

- Add `ResponseContent string` to `ExecutionResult`.
- Populate it from `dispatchChannelMessageToAgent` success path.
- Add handler outbox enqueue hook.
- Enqueue only when decision is `executed`.
- On enqueue error: set decision/status to `dispatch_failed`, log, return `500`.

**Step 4: Run tests to verify pass**

Run: `go test ./internal/channels ./cmd/valinor -run 'Outbox|Execution' -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add internal/channels/execution.go internal/channels/handler.go internal/channels/handler_test.go cmd/valinor/channels_execution.go cmd/valinor/channels_execution_test.go
git commit -m "feat(channels): enqueue executed responses and fail closed on outbox errors"
```

### Task 5: Add Dispatcher + Adapter Stub + Retry Schedule

**Files:**
- Create: `internal/channels/outbox_dispatcher.go`
- Create: `internal/channels/outbox_dispatcher_test.go`

**Step 1: Write the failing tests**

Add tests:
- `TestOutboxDispatcher_SendsPendingJob`
- `TestOutboxDispatcher_RetriesWithBoundedBackoff`
- `TestOutboxDispatcher_DeadLettersAfterMaxAttempts`
- `TestOutboxDispatcher_RecoversStaleSendingBeforeClaim`

```go
assert.WithinDuration(t, expectedMin, nextAttempt, 5*time.Second)
```

**Step 2: Run tests to verify failures**

Run: `go test ./internal/channels -run TestOutboxDispatcher -v`
Expected: FAIL (missing dispatcher types/functions).

**Step 3: Write minimal implementation**

Implement dispatcher with:
- claim loop
- adapter interface (`Send(ctx, job)`)
- light backoff + jitter helper
- retry/dead transitions via store methods

Use deterministic jitter source in tests.

**Step 4: Run tests to verify pass**

Run: `go test ./internal/channels -run TestOutboxDispatcher -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add internal/channels/outbox_dispatcher.go internal/channels/outbox_dispatcher_test.go
git commit -m "feat(channels): add provider-agnostic outbox dispatcher with retries"
```

### Task 6: Wire Dispatcher in `valinor` and Add Config Defaults

**Files:**
- Modify: `internal/platform/config/config.go`
- Modify: `internal/platform/config/config_test.go`
- Create: `cmd/valinor/channels_outbox_worker.go`
- Modify: `cmd/valinor/main.go`
- Modify: `cmd/valinor/main_test.go`

**Step 1: Write the failing tests**

Add config tests:
- `TestLoad_ChannelsOutboxDefaults`
- `TestLoad_ChannelsOutboxEnvOverrides`

Add main wiring test:
- ensure worker build/start path is non-nil when channels enabled.

**Step 2: Run tests to verify failures**

Run: `go test ./internal/platform/config ./cmd/valinor -run 'Outbox|BuildChannelHandler' -v`
Expected: FAIL due missing config fields/worker wiring.

**Step 3: Write minimal implementation**

- Add `ChannelsOutboxConfig` defaults and env mapping.
- Implement worker bootstrap helper in `channels_outbox_worker.go`.
- Start worker in `main.go` with graceful shutdown and bounded poll settings.

**Step 4: Run tests to verify pass**

Run: `go test ./internal/platform/config ./cmd/valinor -run 'Outbox|BuildChannelHandler' -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add internal/platform/config/config.go internal/platform/config/config_test.go cmd/valinor/channels_outbox_worker.go cmd/valinor/main.go cmd/valinor/main_test.go
git commit -m "feat(valinor): wire in-process channel outbox worker"
```

### Task 7: Final Integration Coverage and Full Verification

**Files:**
- Modify: `internal/channels/integration_test.go`
- Optional modify: `docs/plans/2026-02-23-phase8-outbox-design.md` (only if implementation diverges)

**Step 1: Write final failing integration test**

Add `TestOutbox_MultiTenantIsolationAndSingleClaim` that:
- seeds two tenants
- enqueues jobs in both
- claims with one tenant context
- verifies no cross-tenant visibility and no double-claim.

**Step 2: Run targeted test to verify fail**

Run: `go test ./internal/channels -run TestOutbox_MultiTenantIsolationAndSingleClaim -v`
Expected: FAIL before final adjustments.

**Step 3: Implement minimal fixes**

Adjust SQL/locking/recovery edge cases to satisfy integration assertions.

**Step 4: Run complete verification**

Run:
- `go test ./internal/channels -v`
- `go test ./cmd/valinor -v`
- `go test ./internal/platform/database -run TestRLS_TenantIsolation -v`
- `go test ./...`
Expected: all PASS.

**Step 5: Commit**

```bash
git add internal/channels/integration_test.go internal/channels/*.go cmd/valinor/*.go internal/platform/config/*.go internal/platform/database/rls_test.go migrations/000011_channel_outbox.*
git commit -m "test(channels): add outbox integration coverage and finalize reliability path"
```

### Task 8: PR Hygiene and Review Loop

**Files:**
- No code changes expected unless review finds issues.

**Step 1: Push branch and open PR**

```bash
git push -u origin codex/phase8-outbox
gh pr create --base master --head codex/phase8-outbox --title "feat: add provider-agnostic channel outbox reliability layer" --body-file /tmp/pr_body.md
```

**Step 2: Request review and process feedback**

Use: `@requesting-code-review` then `@receiving-code-review`.

**Step 3: Re-run verification before merge**

Run: `go test ./...`
Expected: PASS before asking for merge.

**Step 4: Commit follow-up fixes**

Use focused commits per review cluster.

---

## Execution Notes

- Use `@test-driven-development` sequencing in each coding task.
- Use `@systematic-debugging` for any failing test not explained by current step.
- Use `@verification-before-completion` before merge request.
- Keep commits small and scoped to one task.
- Do not expose outbox API endpoints in this plan (YAGNI for V1).
