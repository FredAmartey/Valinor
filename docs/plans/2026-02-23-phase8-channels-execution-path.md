# Phase 8 Channels Execution Path

## Goal

Implement the first production-safe execution path after ingress acceptance:

`channels ingress (verified + idempotent) -> linked user identity -> RBAC check -> sentinel scan -> tenant agent dispatch`

## Scope In This PR

- Add post-ingress executor hook in `internal/channels/handler.go`.
- Parse provider message text for Slack, WhatsApp, and Telegram in `internal/channels/parser.go`.
- Add execution outcomes for channel flow:
  - `executed`
  - `denied_rbac`
  - `denied_no_agent`
  - `denied_sentinel`
  - `dispatch_failed`
- Add `cmd/valinor/channels_execution.go`:
  - linked user identity lookup from auth store
  - RBAC authorization for `channels:messages:write`
  - running-agent selection with department preference
  - sentinel enforcement before dispatch
  - proxy frame dispatch to selected agent
  - channel execution audit events
- Wire executor into server bootstrap in `cmd/valinor/main.go`.
- Add tests for channel handler execution hook and executor decisions.

## Deferred

- External queue system or separate worker binary.
- Product/policy copy tuning for denied/error fallback response text.

## Verification

- `go test ./internal/channels -v`
- `go test ./cmd/valinor -v`
- `go test ./...`
