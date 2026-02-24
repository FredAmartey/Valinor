# Phase 8 Proxy Frame-ID Multiplexing Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Make concurrent requests to the same agent connection safe by routing responses via `Frame.ID`.

**Architecture:** Extend `internal/proxy.AgentConn` with a single recv loop and in-flight waiter map, then migrate caller paths (`proxy` HTTP handlers and channel execution dispatch) to request-scoped receive routing. Preserve existing protocol behavior while removing cross-request response races.

**Tech Stack:** Go, net.Conn, context cancellation, testify tests, existing proxy frame protocol.

---

### Task 1: Add Multiplexed Request Primitive in AgentConn

**Files:**
- Modify: `internal/proxy/conn.go`
- Test: `internal/proxy/conn_test.go`

**Step 1: Write failing tests for concurrent routing and waiter cleanup**

Add tests:
- concurrent requests with distinct frame IDs receive matching responses even when responses are interleaved.
- timeout/cancel unregisters pending waiter.
- recv loop failure fails pending requests.

**Step 2: Run tests to verify RED**

Run: `go test ./internal/proxy -run 'TestAgentConn_(RequestRoutesByFrameID_Concurrent|RequestTimeoutUnregistersWaiter|RequestFailsWhenRecvLoopDies)' -v`
Expected: FAIL with missing `Request` behavior.

**Step 3: Implement minimal multiplexing in conn**

Implement in `AgentConn`:
- `pending map[string]chan Frame`
- recv loop lifecycle (`startRecvLoop`, `failPending`)
- `Request(ctx, frame) (Frame, error)` with registration + send + wait + unregister
- internal helper `recvFrame` to decode length-prefixed frame

Keep send path serialized with existing write mutex.

**Step 4: Run focused tests to verify GREEN**

Run: `go test ./internal/proxy -run 'TestAgentConn_(RequestRoutesByFrameID_Concurrent|RequestTimeoutUnregistersWaiter|RequestFailsWhenRecvLoopDies)' -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add internal/proxy/conn.go internal/proxy/conn_test.go
git commit -m "feat(proxy): add frame-id request multiplexing"
```

### Task 2: Migrate Proxy HTTP Handler Paths to Request API

**Files:**
- Modify: `internal/proxy/handler.go`
- Test: `internal/proxy/handler_test.go`

**Step 1: Write failing/updated tests for request API integration**

Update tests that expect message/context handling to receive frames so they validate behavior through request-scoped routing (chunk aggregation, context ack/error, tool blocked, session halt).

**Step 2: Run targeted tests to verify RED**

Run: `go test ./internal/proxy -run 'TestHandle(Message|Stream|Context)' -v`
Expected: FAIL until handler is migrated.

**Step 3: Implement handler migration**

In message/stream/context handlers:
- Replace direct `Recv` loops keyed by timing with `conn.Request(ctx, frame)` loop semantics.
- For streaming/message: continue requesting until done/error while preserving existing response shape.
- Preserve existing audit and error mapping.

**Step 4: Run targeted tests to verify GREEN**

Run: `go test ./internal/proxy -run 'TestHandle(Message|Stream|Context)' -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add internal/proxy/handler.go internal/proxy/handler_test.go
git commit -m "refactor(proxy): route handler replies by frame id"
```

### Task 3: Migrate Channel Execution Dispatch Path

**Files:**
- Modify: `cmd/valinor/channels_execution.go`
- Test: `cmd/valinor/channels_execution_test.go`

**Step 1: Add/adjust failing tests**

Add or update tests for `dispatchChannelMessageToAgent` path to assert response handling remains correct using request-scoped routing.

**Step 2: Run targeted tests to verify RED**

Run: `go test ./cmd/valinor -run 'Test(ChannelExecutor|DispatchChannelMessageToAgent)' -v`
Expected: FAIL until migrated.

**Step 3: Implement migration to conn.Request**

Update dispatch loop:
- Use `conn.Request(sendCtx, frame)` for each receive cycle tied to `reqID`.
- Keep chunk aggregation and existing error translations unchanged.

**Step 4: Run targeted tests to verify GREEN**

Run: `go test ./cmd/valinor -run 'Test(ChannelExecutor|DispatchChannelMessageToAgent)' -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add cmd/valinor/channels_execution.go cmd/valinor/channels_execution_test.go
git commit -m "refactor(channels): use frame-id multiplexed dispatch path"
```

### Task 4: Update Plan Docs and Full Verification

**Files:**
- Modify: `docs/plans/2026-02-23-phase8-channels-execution-path.md`
- Optional modify: `docs/plans/2026-02-24-phase8-proxy-frame-multiplexing-design.md` (if implementation diverges)

**Step 1: Update deferred note now that multiplexing is implemented**

Remove or revise deferred item in execution path doc that says frame-ID multiplexing is deferred.

**Step 2: Run full verification suite**

Run:
- `go test ./internal/proxy -v`
- `go test ./cmd/valinor -v`
- `go test ./...`

Expected: PASS.

**Step 3: Commit**

```bash
git add docs/plans/2026-02-23-phase8-channels-execution-path.md docs/plans/2026-02-24-phase8-proxy-frame-multiplexing-design.md
git commit -m "docs(channels): mark frame-id multiplexing complete"
```

### Task 5: Open PR

**Files:**
- No code changes; PR metadata only.

**Step 1: Push branch**

Run:
- `git push -u origin codex/phase8-proxy-frame-multiplexing`

**Step 2: Open PR with summary and verification evidence**

Run:
- `gh pr create --base master --head codex/phase8-proxy-frame-multiplexing --title "feat: add frame-id multiplexing for shared proxy connections" --body-file /tmp/pr_body.md`

**Step 3: Wait for CI and request review**

- Wait until checks are green.
- Run requesting-code-review workflow before merge.
- Address/challenge findings, then ask user before merge.
