# OpenClaw Security Hardening Checklist

This checklist maps OpenClaw's security posture to Heimdall production controls. All items apply to **both product tiers** (Teams: Docker containers, Enterprise: Firecracker microVMs) unless noted.

## P0 (Required Before Production)

- [x] Enforce loopback-only OpenClaw endpoint defaults in `heimdall-agent`. *(Both tiers)*
- [x] Enforce OpenClaw runtime policy defaults from infrastructure: *(Both tiers)*
  - sandbox enabled (not host/main mode)
  - `tools.exec.workspaceOnly=true`
  - `tools.exec.applyPatch.workspaceOnly=true`
  - gateway bind local-only
- [x] Replace `/api/v1/agents/{id}/context` no-op behavior with real persistent per-user context path. *(Both tiers)*
- [x] Pin and verify guest runtime versions (OpenClaw + Node) in image build pipeline. *(Firecracker: rootfs build; Docker: Dockerfile.agent)*

## P1 (Next Hardening Wave)

- [x] Add per-user writable workspace/data mount with quotas. *(Firecracker: per-VM quota data drives; Docker: volume mounts with storage limits)*
  Implemented (Firecracker): per-VM quota data drives plus user-affine agent provisioning/reuse (`agent_instances.user_id`) and user-scoped channel routing.
  Docker: personal memory volume mounted read-write per user, department/tenant/shared volumes mounted read-only.
- [x] Add explicit guest network policy (outbound-only, no inbound gateway exposure).
  Firecracker: fail-closed preflight policy (`outbound_only` requires jailer + `netns_path` + `network.tap_device`) and explicit guest NIC programming (`/network-interfaces/eth0`).
  Docker: per-tenant internal Docker network (`Internal: true`), no external access by default.
- [x] Add CI checks that fail on policy regressions. *(Both tiers)*

## P2 (Hierarchical Memory Hardening)

- [ ] Enforce read-only mounts for department/tenant/shared memory volumes. *(Both tiers)*
- [ ] Validate `heimdall_publish_memory` MCP tool permissions in control plane before writing to shared layers. *(Both tiers)*
- [ ] Add per-volume mutex to prevent concurrent write corruption. *(Both tiers)*
- [ ] Knowledge base grant audit trail — log all grant changes. *(Both tiers)*

## Verification Commands

```bash
# endpoint guard + bridge behavior
go test ./cmd/heimdall-agent -run 'OpenClaw|ValidateOpenClawURL' -v

# runtime policy enforcement
go test ./internal/orchestrator -run 'TestEnforceOpenClawRuntimePolicy' -v

# Docker driver integration (requires Docker daemon)
go test ./internal/orchestrator -run 'TestDockerDriver' -v

# full regression
go test ./... -count=1
```
