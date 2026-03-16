# Dual-Tier OpenClaw Integration with Hierarchical Memory

**Date:** 2026-03-02
**Status:** Approved

## Goal

Integrate OpenClaw as the agent runtime inside Heimdall's isolation boundary, with two product tiers (Teams: Docker, Enterprise: Firecracker) and a hierarchical memory model that enforces multi-tenant, multi-department, and per-user isolation with controlled sharing.

## Context

Heimdall is an enterprise AI agent control plane. OpenClaw is an open-source AI agent runtime (247k GitHub stars) with a single-trust-boundary model. Heimdall wraps OpenClaw in secure infrastructure so companies can deploy isolated agent workforces.

The existing codebase already has:
- `VMDriver` interface with Firecracker and Mock implementations
- `heimdall-agent` in-guest sidecar (`cmd/heimdall-agent/`) with OpenClaw HTTP proxy, tool allowlist enforcement, canary token detection, MCP connector integration
- Proxy module with TCP/vsock transport abstraction
- Runtime policy enforcement for OpenClaw config
- Loopback-only security guard for OpenClaw URLs

## Product Tiers

| | **Teams** | **Enterprise** |
|---|---|---|
| Runtime | Docker containers | Firecracker microVMs |
| Isolation | Container namespace + network | Separate kernel per agent |
| Deployment | Any Docker host, K8s, VPS | Bare-metal / KVM instances |
| Cold start | ~2-5s | ~125ms |
| Shared features | RBAC, audit, Sentinel, channels, hierarchical memory, MCP connectors |

Both tiers use the same `VMDriver` interface. Config selects the driver.

## Architecture

```
                    Heimdall Control Plane (Go)
                    ┌──────────────────────────────┐
                    │  Auth · RBAC · Sentinel       │
                    │  Proxy · Audit · Channels     │
                    │  Memory Manager · MCP Registry │
                    └──────────┬───────────────────┘
                               │
              ┌────────────────┼────────────────┐
              │ TCPTransport   │                 │ VsockTransport
              ▼                │                 ▼
    ┌─────────────────┐       │      ┌─────────────────────┐
    │ Docker Container │       │      │ Firecracker MicroVM  │
    │ (Teams tier)     │       │      │ (Enterprise tier)    │
    │                  │       │      │                      │
    │ heimdall-agent    │       │      │ heimdall-agent        │
    │   ↕ HTTP :8081   │       │      │   ↕ HTTP :8081       │
    │ OpenClaw Gateway │       │      │ OpenClaw Gateway     │
    │                  │       │      │                      │
    │ /memory/personal │       │      │ /memory/personal     │
    │ /memory/dept     │       │      │ /memory/dept         │
    │ /memory/tenant   │       │      │ /memory/tenant       │
    │ /memory/shared   │       │      │ /memory/shared       │
    └─────────────────┘       │      └─────────────────────┘
                               │
                    Same protocol, same sidecar,
                    same tool enforcement
```

### End-to-End Message Flow

```
Client → POST /agents/:id/message
  → Auth middleware (JWT validation, tenant resolution)
  → RBAC middleware (permission check)
  → Sentinel scan (prompt injection detection)
  → Proxy: inject dynamic context (recent alerts, conversation summaries)
  → Proxy: dial agent via TCP (Docker) or vsock (Firecracker)
  → heimdall-agent: validate, forward to OpenClaw at localhost:8081
  → OpenClaw: process message, read memory from /memory/*, call MCP tools
  → heimdall-agent: enforce tool allowlist, check canary tokens, relay chunks
  → Proxy: stream response back to client via SSE
```

## Docker VMDriver

New `DockerDriver` in `internal/orchestrator/` implementing the existing `VMDriver` interface.

```go
type DockerDriver struct {
    client       *docker.Client
    image        string           // "heimdall/agent:latest"
    stateDir     string           // persist container metadata for recovery
    memoryBase   string           // base path for memory volumes
}
```

### VMSpec Mapping

| VMSpec field | Docker equivalent |
|---|---|
| `VCPUs` | `--cpus` |
| `MemoryMB` | `--memory` |
| `VsockCID` | Mapped to TCP port (`basePort + CID`) |
| `DataDriveQuotaMB` | Volume with `--storage-opt size=` |
| `VMID` | Container name |

### Key Behaviors

- `Start`: creates per-tenant Docker network (if not exists), runs container with isolated network, CPU/memory limits, memory volume mounts, heimdall-agent as entrypoint, published TCP port
- `Stop`: `docker stop` with grace period, then `docker rm`
- `IsHealthy`: `docker inspect` for container status + TCP ping to heimdall-agent
- `Cleanup`: remove container + orphaned volumes
- Warm pool: pre-started containers with no tenant (claimed atomically on provision, same as Firecracker)

### Tenant Network Isolation

Each tenant gets a dedicated Docker network:

```
Tenant A network (heimdall-net-<tenant-a-id>)
├── agent-a1 (container, port 9100)
├── agent-a2 (container, port 9101)

Tenant B network (heimdall-net-<tenant-b-id>)
├── agent-b1 (container, port 9200)

Control plane connects to all networks to reach agents.
```

Containers within a tenant network can only reach each other (if needed) and the control plane. Cross-tenant traffic is impossible at the network level.

## Container Image

Single Dockerfile producing the agent container:

```dockerfile
# Stage 1: Build heimdall-agent
FROM golang:1.25 AS agent-builder
COPY . /src
RUN cd /src && go build -o /heimdall-agent ./cmd/heimdall-agent

# Stage 2: OpenClaw runtime
FROM node:22-slim
RUN npm install -g openclaw@<pinned-version>
COPY --from=agent-builder /heimdall-agent /usr/local/bin/heimdall-agent
COPY configs/openclaw-guest.json /etc/openclaw/openclaw.json

ENTRYPOINT ["/usr/local/bin/heimdall-agent", \
  "--transport", "tcp", \
  "--openclaw-url", "http://localhost:8081"]
```

### Startup Sequence

1. `heimdall-agent` starts as PID 1
2. heimdall-agent spawns `openclaw gateway` as a child process on port 8081
3. heimdall-agent listens on its TCP port for control plane connections
4. Control plane pushes config (tool allowlist, connectors, canary tokens)
5. Agent sends initial heartbeat — ready for messages

### OpenClaw Guest Config (`openclaw-guest.json`)

```json
{
  "gateway": {
    "bind": "127.0.0.1",
    "port": 8081
  },
  "agents": {
    "defaults": {
      "sandbox": { "mode": "non-main" }
    }
  },
  "tools": {
    "exec": {
      "workspaceOnly": true,
      "applyPatch": { "workspaceOnly": true }
    }
  },
  "memory": {
    "paths": [
      "/memory/personal",
      "/memory/department",
      "/memory/tenant",
      "/memory/shared"
    ]
  }
}
```

Version pinning: OpenClaw version pinned in Dockerfile, Node.js pinned via base image tag, heimdall-agent built from same monorepo commit. CI builds and tags image on every merge to master.

## Four-Layer Isolation Model

```
Layer 0: Platform       │ Heimdall control plane (manages all tenants)
Layer 1: Tenant         │ Hard wall — separate containers/VMs, separate Docker
                        │ networks, PostgreSQL RLS by tenant_id
Layer 2: Department     │ Separate agent instances per user, scoped memory
                        │ volumes per department
Layer 3: User           │ Personal agent instance, personal read-write memory
```

### Execution Isolation

- Every user gets their own agent instance (container or VM)
- No two users share an OpenClaw process
- Department and tenant boundaries enforced by control plane (RBAC) and network isolation (separate Docker networks per tenant)

### Data Isolation

- PostgreSQL RLS gates all data by `tenant_id`
- Container filesystems are independent
- Memory volumes scoped per layer (see below)

## Hierarchical Memory Model

### Volume Mounts Per Agent

```
/memory/personal/     → read-write  (per-user named volume)
/memory/department/   → read-only   (per-department named volume)
/memory/tenant/       → read-only   (per-tenant named volume)
/memory/shared/       → read-only   (admin-granted cross-dept knowledge)
```

OpenClaw reads all four paths natively as local Markdown files.

### Access Rules

| Layer | Visibility | Writability |
|---|---|---|
| Personal | Only the owning user's agent | Read-write |
| Department | All agents in that department | Read-only (write via MCP tool) |
| Tenant | All agents in that tenant | Read-only (write via MCP tool) |
| Shared (admin grants) | Agents in granted departments/roles/users | Read-only (write via MCP tool) |

### Default Hierarchy (zero config)

- User agents automatically see: personal + own department + own tenant memory
- No cross-department visibility by default
- Admin overrides allow selective cross-department sharing

### Admin-Controlled Overrides

Tenant admins can create named "knowledge bases" and grant access to specific departments, roles, or users. Example:

```
Chelsea tenant admin creates:
  "Transfer Targets" knowledge base → grants to: Scouting dept, Director role
  "Negotiation Playbook" → grants to: Front Office dept only
```

The Director's agent mounts: personal + Front Office dept + tenant + Transfer Targets (override).
Scout A's agent mounts: personal + Scouting dept + tenant + Transfer Targets (default from dept).

### Publishing to Shared Memory

Agents publish to shared memory via a Heimdall-provided MCP tool: `heimdall_publish_memory`.

Flow:
1. Agent calls `heimdall_publish_memory(layer="department", content="...")` via MCP
2. heimdall-agent forwards to control plane
3. Control plane validates: does this user have write permission to this layer?
4. Control plane acquires mutex for the target volume
5. Control plane writes content to the appropriate shared volume
6. All agents with read access see the update on next file read

### Dynamic Context Injection

At message dispatch time, Heimdall prepends small dynamic context to the message:
- Recent conversation summaries
- Dynamic alerts ("budget updated to £180M")
- RAG-retrieved relevant chunks (when knowledge bases grow large)

This uses the existing `/agents/{id}/context` snapshot system. Adds ~5ms latency, negligible compared to LLM inference time. Reserved for ephemeral/query-specific information to minimize context window consumption.

## Database Changes

### New Tables

```sql
CREATE TABLE knowledge_bases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    layer TEXT NOT NULL CHECK (layer IN ('tenant', 'department')),
    source_department_id UUID REFERENCES departments(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE knowledge_base_grants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    knowledge_base_id UUID NOT NULL REFERENCES knowledge_bases(id) ON DELETE CASCADE,
    grant_type TEXT NOT NULL CHECK (grant_type IN ('department', 'role', 'user')),
    grant_target_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

Both tables have RLS policies scoped to `tenant_id`.

No changes to `agent_instances` — `tenant_id`, `department_id`, `user_id` already exist.

## Built-In MCP Connectors

Two Heimdall-provided MCP tools available to every agent:

### `heimdall_publish_memory`

Writes a memory entry to a shared layer (department or tenant). Validates permissions in the control plane. Handles concurrency with per-volume mutex.

```json
{
  "name": "heimdall_publish_memory",
  "parameters": {
    "layer": "department | tenant",
    "title": "string",
    "content": "string (Markdown)"
  }
}
```

### `heimdall_query_memory`

Searches across accessible memory layers. Returns relevant chunks. Used for RAG-style retrieval when knowledge bases grow large.

```json
{
  "name": "heimdall_query_memory",
  "parameters": {
    "query": "string",
    "layers": ["personal", "department", "tenant", "shared"],
    "limit": 10
  }
}
```

## Firecracker Tier (Parallel Track)

Same architecture, different packaging:
- Rootfs image instead of Docker image (same binaries: heimdall-agent + OpenClaw + Node.js)
- Vsock transport instead of TCP
- Memory volumes as virtio block devices instead of Docker volumes
- Per-user writable workspace disk mount with quotas
- Version pinning in CI image build pipeline

Remaining P0 work:
- [ ] Build rootfs with Node.js 22 + OpenClaw + heimdall-agent
- [ ] Init system starts heimdall-agent → spawns OpenClaw gateway
- [ ] Pin and verify runtime versions in CI
- [ ] Per-user writable workspace disk mount with quotas

## Configuration

```yaml
Orchestrator:
  Driver: "docker"  # or "firecracker"
  WarmPoolSize: 2
  HealthIntervalSecs: 10
  ReconcileIntervalSecs: 30
  MaxConsecutiveFailures: 3
  Docker:
    Image: "heimdall/agent:latest"
    NetworkMode: "per-tenant"  # "none" | "per-tenant" | "bridge"
    DefaultCPUs: 1
    DefaultMemoryMB: 512
    WorkspaceQuotaMB: 1024
    MemoryBasePath: "/var/lib/heimdall/memory"
  Firecracker:
    Workspace:
      Enabled: true
      QuotaMB: 1024
```

## Security Summary

| Threat | Mitigation |
|---|---|
| Cross-tenant data access | Separate containers/VMs + Docker networks + PostgreSQL RLS |
| Cross-department memory leak | Read-only volume mounts, write-only via MCP tool with permission checks |
| Agent escape (container) | Upgrade to Firecracker tier; Teams tier relies on container + network isolation |
| Prompt injection | Sentinel scan before message reaches agent |
| Tool abuse | Tool allowlist in heimdall-agent, runtime policy enforcement |
| Canary token exfiltration | Canary detection in agent responses and tool results |
| OpenClaw misconfiguration | Infrastructure-enforced config (loopback-only, sandbox enabled, workspace-only) |

## Decisions Log

| Decision | Choice | Reasoning |
|---|---|---|
| Two tiers vs one | Two (Docker + Firecracker) | Teams need easy deployment; enterprises need hardware isolation. VMDriver interface already abstracts this. |
| Container model | Single container (heimdall-agent + OpenClaw) | Mirrors Firecracker model. Simplest to operate. One Dockerfile. |
| Memory sharing | Hierarchical with admin overrides | Zero-config defaults from org hierarchy + flexibility for cross-dept sharing. |
| Shared memory writability | Read-only mounts + write via MCP tool | Prevents concurrent write conflicts. Control plane handles concurrency. |
| Dynamic context | Injection at message time | Handles ephemeral data without filesystem overhead. ~5ms added latency. |

## Verification

- `go test ./internal/orchestrator -run 'TestDockerDriver' -v`
- `go test ./cmd/heimdall-agent -run 'TestOpenClaw' -v`
- `docker build -f Dockerfile.agent -t heimdall/agent:test .`
- Integration: start agent container, send message via proxy, verify response + memory isolation
