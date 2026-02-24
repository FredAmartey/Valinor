# Phase 8 Proxy Frame-ID Multiplexing Design

## Goal

Eliminate response misrouting when multiple requests are in flight to the same agent connection by implementing frame-ID multiplexing on shared proxy connections.

## Problem

Current `internal/proxy` behavior shares one connection per agent but uses direct `Send` + `Recv` loops at call sites. With concurrent callers on the same agent, one caller can consume another caller's response frames, creating nondeterministic failures and potential cross-request leakage.

## Decision

Implement full frame-ID multiplexing now (instead of per-agent serialization).

## Scope

### In Scope

- Add request routing primitives to `internal/proxy/conn.go` keyed by `Frame.ID`.
- Add a single background receive loop per connection.
- Expose a `Request(ctx, frame)` API that safely handles concurrent callers.
- Update proxy handlers and channel execution path to use the new request API.
- Add concurrency and lifecycle tests for request isolation, timeout cleanup, and connection failure behavior.

### Out of Scope

- Protocol redesign or new frame types.
- Multi-connection pooling per agent.
- Prioritization/queue scheduling policies.

## Architecture

### Connection internals

Enhance `AgentConn` with:

- `pending map[string]chan Frame` for in-flight requests.
- `loopErr error` and `closed bool` state.
- `recvLoop` goroutine started lazily on first request.

Flow:

1. `Request` validates non-empty frame ID.
2. `Request` registers a response channel under the frame ID.
3. `Request` sends the frame.
4. `recvLoop` continuously reads frames and routes by `reply.ID`.
5. Matching waiter receives frame and continues its protocol-specific loop.
6. On context cancel/timeout, waiter is unregistered.
7. On recv transport error, all pending waiters are failed and connection becomes unusable.

### Pool integration

Keep one connection per agent in `internal/proxy/pool.go`. Existing dial/reuse semantics stay intact.

### Caller integration

- `internal/proxy/handler.go`: replace direct `Recv` usage with `Request` loops keyed by request ID.
- `cmd/valinor/channels_execution.go`: same change in `dispatchChannelMessageToAgent`.

## Error Handling

- Unmatched frames (empty/unknown ID) are ignored and logged at debug level.
- Send failure unregisters waiter and returns error.
- Loop failure returns request error and triggers pool removal by caller paths already doing failover.
- Timeout/cancel affects only that request unless the underlying conn dies.

## Testing Strategy

1. `internal/proxy/conn_test.go`
   - Concurrent request routing correctness across interleaved frames.
   - Timeout unregister behavior (no waiter leaks).
   - Connection close propagates errors to all pending requests.
2. Regression tests for handler/channel execution compile and behavior with new API.
3. Full package verification:
   - `go test ./internal/proxy -v`
   - `go test ./cmd/valinor -v`
   - `go test ./...`

## Risks and Mitigations

1. Goroutine leaks in receive loop
   - Mitigation: explicit close path + tests asserting pending map drains.
2. Deadlocks around pending map and IO
   - Mitigation: never hold pending lock during network reads/writes; keep lock scope minimal.
3. Behavioral drift in handlers
   - Mitigation: preserve existing response-type handling and keep tests covering chunk/error/tool_blocked/session_halt paths.

## Product Outcome

Channel and proxy requests can safely execute concurrently against the same agent instance without cross-request response corruption, reducing intermittent failures and improving high-load behavior.
