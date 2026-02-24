# Phase 8 OpenClaw Runtime Hardening Design

## Goal

Translate OpenClaw's security model into concrete Valinor infrastructure controls so production behavior is secure-by-default.

## Context

OpenClaw documents a single-trust-boundary model. For Valinor, that means OpenClaw is an execution engine inside our isolation boundary, not the boundary itself.

## Security Decisions

1. Loopback-only OpenClaw endpoint in guest
- Valinor agent must reject non-loopback OpenClaw URLs by default.
- Break-glass remote endpoint support may exist but must be explicit and unsafe-by-name.

2. Runtime policy enforcement owned by infrastructure
- Required defaults for OpenClaw runtime in guest images:
  - sandbox enabled (not host-main mode)
  - `tools.exec.workspaceOnly=true`
  - `tools.applyPatch.workspaceOnly=true`
  - gateway bind local-only

3. Writable workspace isolation
- Firecracker rootfs remains read-only.
- Add per-user writable workspace/data mounts with quotas as next hardening batch.

4. Context continuity as security and product primitive
- `/agents/{id}/context` must not be no-op.
- Implement persistent per-user context in control plane; project it into execution at dispatch time.

## Scope (This Batch)

P0 scope in this PR:
- Add startup/runtime guard in `valinor-agent` that rejects non-loopback OpenClaw URLs by default.
- Add tests covering loopback and remote endpoint behavior.
- Add explicit P0/P1 checklist doc to track hardening progress.

Out of scope for this PR:
- OpenClaw runtime sandbox/workspace policy plumbing through orchestrator config push.
- Per-user persistent context store + sync path implementation.
- Firecracker per-user writable workspace disk wiring.

## P0/P1 Checklist

P0 (must complete before production):
- [x] Loopback-only OpenClaw URL guard in `valinor-agent`.
- [ ] Enforce OpenClaw sandbox/workspace policy defaults in runtime config path.
- [ ] Implement real persistent per-user context path (`/agents/{id}/context` no longer no-op).
- [ ] Pin and verify guest runtime versions (OpenClaw + Node) in image build pipeline.

P1 (next hardening wave):
- [ ] Add per-user writable workspace/data drive mount with quotas.
- [ ] Add explicit outbound-only network policy for guest runtime and no inbound gateway exposure.
- [ ] Add CI/security checks asserting runtime policy invariants.

## Verification

- `go test ./cmd/valinor-agent -run 'OpenClaw|ValidateOpenClawURL' -v`
- `go test ./... -count=1`
