# Docker Teams Tier Setup Runbook

> **Scope:** This runbook applies to the **Teams tier** (Docker containers). For the **Enterprise tier** (Firecracker microVMs), see [firecracker-build-test.md](firecracker-build-test.md).

## Prerequisites

- Docker Engine 24+ installed and running
- Go 1.25+ (for building valinor-agent)
- Node.js 22+ and npm (for OpenClaw, bundled in container image)

Verify Docker:

```bash
docker info --format '{{.ServerVersion}}'
```

## 1) Build the Agent Container Image

From the Valinor repo root:

```bash
docker build -f Dockerfile.agent -t valinor/agent:dev .
```

This multi-stage build:
1. Compiles `valinor-agent` from Go source
2. Installs OpenClaw (version-pinned) on Node.js 22
3. Copies hardened OpenClaw config (`configs/openclaw-guest.json`)
4. Sets `valinor-agent` as the entrypoint

## 2) Quick Smoke Test

```bash
# Start agent container (without OpenClaw spawning, for basic validation)
docker run --rm -d --name valinor-agent-test \
  -p 19100:9100 \
  valinor/agent:dev --skip-openclaw-spawn

# Verify it starts
sleep 2 && docker logs valinor-agent-test

# Expected output:
# valinor-agent starting transport=tcp port=9100 ...
# agent listening port=9100

# Cleanup
docker stop valinor-agent-test
```

## 3) Configure Valinor for Docker Driver

In `config.yaml`:

```yaml
orchestrator:
  driver: "docker"
  warm_pool_size: 2
  health_interval_secs: 10
  reconcile_interval_secs: 30
  max_consecutive_failures: 3
  docker:
    image: "valinor/agent:dev"
    network_mode: "per-tenant"    # "none" | "per-tenant" | "bridge"
    default_cpus: 1
    default_memory_mb: 512
    memory_base_path: "/var/lib/valinor/memory"
    workspace_quota_mb: 1024

proxy:
  transport: "tcp"
  tcp_base_port: 9100
```

## 4) Start Valinor

```bash
go run ./cmd/valinor --config config.yaml
```

Expected log output:
```
orchestrator started driver=docker warm_pool=2
```

The orchestrator will pre-start 2 warm containers from the configured image.

## 5) Verify Agent Provisioning

```bash
# Provision an agent (requires auth token)
curl -X POST http://localhost:8080/api/v1/agents \
  -H "Authorization: Bearer dev" \
  -H "Content-Type: application/json" \
  -d '{"config": {}}'

# List running containers
docker ps --filter "label=valinor.agent"
```

## 6) Per-Tenant Network Isolation

When `network_mode: "per-tenant"`, Valinor creates isolated Docker networks:

```bash
# List Valinor networks
docker network ls --filter "label=valinor.agent"

# Inspect a tenant network
docker network inspect valinor-net-<tenant-id>
```

Each tenant's containers are on a separate internal bridge network. Cross-tenant traffic is impossible at the network level.

## 7) Memory Volume Layout

With `memory_base_path: "/var/lib/valinor/memory"`, agent containers get bind mounts:

```
/var/lib/valinor/memory/<vm-id>/personal/  → /memory/personal  (read-write)
```

Department, tenant, and shared memory volumes are mounted read-only once knowledge base management is configured.

## 8) Verification Checklist

```bash
# Unit tests (no Docker required)
go test ./internal/orchestrator -run TestMockDriver -v
go test ./cmd/valinor -run TestSelectVMDriver_Docker -v

# Integration tests (Docker required)
go test ./internal/orchestrator -run TestDockerDriver -v

# End-to-end test (Docker + built image required)
go test ./internal/orchestrator -run TestDockerDriver_E2E -v -timeout 120s

# Full regression
go test ./... -count=1 -short
```

## 9) Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `Cannot connect to Docker daemon` | Docker not running | `sudo systemctl start docker` |
| `image not found` | Agent image not built | `docker build -f Dockerfile.agent -t valinor/agent:dev .` |
| `port already in use` | Port conflict | Check `proxy.tcp_base_port` in config, ensure no collisions |
| `container unhealthy` | OpenClaw not starting | Check container logs: `docker logs valinor-<vm-id>` |
| `network already exists` | Stale tenant network | `docker network prune` (safe: only removes unused networks) |
