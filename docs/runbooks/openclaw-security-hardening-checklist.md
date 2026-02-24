# OpenClaw Security Hardening Checklist

This checklist maps OpenClaw's security posture to Valinor production controls.

## P0 (Required Before Production)

- [x] Enforce loopback-only OpenClaw endpoint defaults in `valinor-agent`.
- [x] Enforce OpenClaw runtime policy defaults from infrastructure:
  - sandbox enabled (not host/main mode)
  - `tools.exec.workspaceOnly=true`
  - `tools.exec.applyPatch.workspaceOnly=true`
  - gateway bind local-only
- [x] Replace `/api/v1/agents/{id}/context` no-op behavior with real persistent per-user context path.
- [x] Pin and verify guest runtime versions (OpenClaw + Node) in image build pipeline.

## P1 (Next Hardening Wave)

- [x] Add per-user writable workspace/data mount with quotas in Firecracker.
  Implemented now: per-VM quota data drives plus user-affine agent provisioning/reuse (`agent_instances.user_id`) and user-scoped channel routing.
- [x] Add explicit guest network policy (outbound-only, no inbound gateway exposure).
  Implemented now: fail-closed preflight policy (`outbound_only` requires jailer + `netns_path` + `network.tap_device`) and explicit guest NIC programming (`/network-interfaces/eth0`).
- [x] Add CI checks that fail on policy regressions.

## Verification Commands

```bash
# endpoint guard + bridge behavior
go test ./cmd/valinor-agent -run 'OpenClaw|ValidateOpenClawURL' -v

# full regression
go test ./... -count=1
```
