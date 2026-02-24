# Phase 8 OpenClaw Runtime Policy Enforcement Design

## Goal

Enforce OpenClaw runtime security defaults from Valinor infrastructure so operator config cannot silently weaken baseline isolation.

## Context

OpenClaw's security model is trusted-operator, with documented dangerous defaults/tradeoffs when sandbox is disabled or workspace boundaries are relaxed. Valinor must enforce production-safe defaults in the control plane.

## Recommended Approach

Apply fail-closed runtime policy normalization in orchestrator configure path:
- Endpoint: `POST /api/v1/agents/{id}/configure`
- Before persisting/pushing config:
  - inject required secure defaults when unset
  - reject explicitly insecure overrides

This keeps enforcement centralized and independent from UI/operator behavior.

## Enforced Policy (P0)

- `agents.defaults.sandbox.mode`
  - reject insecure: `off`, `main`, empty
  - default to: `non-main` when unset
- `tools.exec.workspaceOnly`
  - reject `false`
  - default to `true` when unset
- `tools.exec.applyPatch.workspaceOnly`
  - reject `false`
  - default to `true` when unset
- `gateway.bind`
  - reject non-loopback values
  - default to `loopback` when unset

## Scope

In scope:
- Add runtime policy enforcer helper in `internal/orchestrator`
- Wire helper into `HandleConfigure`
- Add unit tests for policy behavior
- Add integration tests validating configure response/rejection
- Update hardening checklist progress

Out of scope:
- Guest image/node runtime version pinning
- Persistent per-user context implementation
- Network egress policy changes

## Verification

- `go test ./internal/orchestrator -run 'TestEnforceOpenClawRuntimePolicy|TestHandler_Configure' -v`
- `go test ./... -count=1`
