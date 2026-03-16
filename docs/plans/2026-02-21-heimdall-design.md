# Heimdall: Enterprise AI Agent Control Plane

## Context

OpenClaw is a popular open-source AI agent runtime (247k+ GitHub stars) designed as a single-user tool. It stores data as local Markdown files, has no permission system, no multi-tenancy, and its trust model assumes a single operator. Enterprises need AI agents but cannot safely deploy OpenClaw without: tenant isolation, RBAC, audit logging, prompt injection defense, and secure tool execution.

**Heimdall** is a horizontal infrastructure platform — a secure control plane that orchestrates isolated OpenClaw instances per tenant. It enables startups and enterprises across any sector to deploy AI agent workforces safely. Heimdall is to AI agents what Stripe is to payments: the infrastructure layer that handles security, isolation, and compliance so clients can focus on their product.

**Two product tiers** serve different isolation needs:

| | **Teams** | **Enterprise** |
|---|---|---|
| Runtime | Docker containers | Firecracker microVMs |
| Isolation | Container namespace + per-tenant Docker network | Separate kernel per agent (KVM) |
| Deployment | Any Docker host, Kubernetes, VPS | Bare-metal / KVM-capable instances (Linux only) |
| Cold start | ~2-5s | ~125ms |

Both tiers share the same control plane, dashboard, RBAC, audit, Sentinel, channels, and MCP connectors. The `VMDriver` interface abstracts the runtime — configuration selects the driver at startup.

**Product positioning:** Heimdall serves platform builders (e.g., "Marcelo AI" for football, "Harvey AI" for legal). These clients build domain-specific products with their own web/desktop UIs. Heimdall provides the secure agent infrastructure underneath. End users never see Heimdall — they interact through the client's product and messaging apps.

---

## Architecture: Modular Monolith (Go)

Single Go binary with 9 internal modules separated by Go interfaces. Deploys as one binary for simplicity; modules can be extracted into separate services when scaling demands it (proxy first at ~50 tenants, orchestrator at ~200).

### Module Overview

| Module | Responsibility | Hot Path? |
|--------|---------------|-----------|
| `auth` | OAuth2/OIDC verification, JWT validation/creation, identity resolution | Yes |
| `rbac` | Role resolution, hybrid policy evaluation (RBAC + resource policies), caching | Yes |
| `tenant` | Tenant/org/department CRUD, user management, hierarchy | No |
| `orchestrator` | Agent runtime lifecycle (Docker or Firecracker), warm pool, health checks | No (background) |
| `proxy` | Route requests to agent via TCP (Docker) or vsock (Firecracker), WebSocket relay | Yes |
| `audit` | Async event pipeline via buffered Go channels, batch DB writes | No (async) |
| `lifecycle` | OpenClaw start/stop/restart, config injection, in-guest agent protocol | No |
| `channels` | Messaging platform webhooks, identity linking, message relay through RBAC | Yes |
| `connectors` | MCP server registration, credential management, connection brokering | No |

### Request Flow

```
Client API / WhatsApp / Telegram / Slack
         |
    [Heimdall API Gateway]
         |
    [Auth Middleware] — validate JWT / resolve identity from platform user ID
         |
    [RBAC Middleware] — role check + resource policy check
         |
    [Input Sentinel] — prompt injection scan (pattern + LLM classifier)
         |
    [Proxy] — route to agent via TCP (Docker) or vsock (Firecracker)
         |
    [Docker Container / Firecracker MicroVM]
      [Heimdall Agent] — tool allow-list enforcement, health reporting
        [OpenClaw] — processes message, calls MCP tools
           |
      [Tool Call Validator] — deterministic RBAC check on every tool call
           |
      [MCP Server] — client's registered API (e.g., Marcelo AI's scouting API)
         |
    Response flows back through the same pipeline
```

### Project Structure

```
heimdall/
  cmd/heimdall/main.go              # composition root, DI wiring
  internal/
    platform/                       # shared infrastructure
      config/                       # env/YAML config loading
      database/                     # PostgreSQL connection, migrations
      middleware/                    # auth, RBAC, logging, request ID
      server/                       # HTTP server setup, graceful shutdown
      telemetry/                    # metrics, tracing, structured logging
      errors/                       # domain error types
      events/                       # in-process event bus (extractable to NATS later)
    auth/
      auth.go                       # Service interface
      handler.go                    # HTTP handlers (login, callback, refresh)
      oidc.go                       # OIDC provider integration
      token.go                      # JWT creation/validation
      store.go                      # DB operations
    rbac/
      rbac.go                       # PolicyEngine interface
      evaluator.go                  # policy evaluation logic
      cache.go                      # decision cache
      store.go                      # roles, permissions, policies DB ops
      middleware.go                 # authorization middleware
    tenant/
      tenant.go                     # TenantService interface
      handler.go                    # HTTP handlers
      store.go                      # DB operations
    orchestrator/
      orchestrator.go               # VMOrchestrator interface
      manager.go                    # Firecracker VM lifecycle
      pool.go                       # warm pool management
      health.go                     # health check loop
      store.go                      # VM state DB ops
    proxy/
      proxy.go                      # AgentProxy interface
      router.go                     # tenant-to-VM routing table
      handler.go                    # WebSocket/HTTP proxy handlers
      vsock.go                      # vsock connection management
    audit/
      audit.go                      # AuditLogger interface
      pipeline.go                   # buffered channel + worker pool
      store.go                      # DB operations
      handler.go                    # audit query HTTP handlers
    lifecycle/
      lifecycle.go                  # LifecycleController interface
      commands.go                   # start, stop, restart, health, update
      agent.go                      # in-guest agent protocol definition
    channels/
      channels.go                   # ChannelService interface
      whatsapp.go                   # WhatsApp webhook handler
      telegram.go                   # Telegram webhook handler
      resolver.go                   # platform user ID → Heimdall identity
      store.go                      # channel_links DB operations
    connectors/
      connectors.go                 # ConnectorService interface
      registry.go                   # MCP server registration
      broker.go                     # connection brokering + credential injection
      store.go                      # connector configs DB ops
  heimdall-agent/                    # separate binary for inside MicroVMs
    main.go                         # in-guest sidecar agent
    allowlist.go                    # tool allow-list enforcement
    sentinel.go                     # tool call validation
    health.go                       # heartbeat reporting
  api/
    openapi/                        # OpenAPI 3.0 spec
  migrations/                       # PostgreSQL migrations (golang-migrate)
  deploy/
    docker/                         # Dockerfiles
    systemd/                        # systemd unit files (on-prem)
    terraform/                      # AWS infrastructure
  dashboard/                        # Next.js admin dashboard (separate build)
    src/
      app/                          # App Router pages
      components/                   # shadcn/ui components
      lib/                          # API client, auth helpers
```

---

## Data Model (PostgreSQL)

### Tenants & Organization

```sql
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',  -- active, suspended, archived
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE departments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    name TEXT NOT NULL,
    parent_id UUID REFERENCES departments(id),  -- hierarchical
    created_at TIMESTAMPTZ DEFAULT now()
);
```

### Users & Identity

```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    email TEXT NOT NULL,
    display_name TEXT,
    oidc_subject TEXT,
    oidc_issuer TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE user_departments (
    user_id UUID NOT NULL REFERENCES users(id),
    department_id UUID NOT NULL REFERENCES departments(id),
    PRIMARY KEY (user_id, department_id)
);
```

### RBAC (Hybrid: Roles + Resource Policies)

```sql
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    name TEXT NOT NULL,
    permissions JSONB NOT NULL,  -- ["agents:read","agents:write","users:manage"]
    is_system BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES users(id),
    role_id UUID NOT NULL REFERENCES roles(id),
    scope_type TEXT NOT NULL,   -- "org" or "department"
    scope_id UUID NOT NULL,     -- tenant_id or department_id
    PRIMARY KEY (user_id, role_id, scope_type, scope_id)
);

CREATE TABLE resource_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    subject_type TEXT NOT NULL,  -- "user" or "role"
    subject_id UUID NOT NULL,
    action TEXT NOT NULL,         -- "read", "write", "execute"
    resource_type TEXT NOT NULL,  -- "agent", "document", "memory", "mcp_tool"
    resource_id UUID,             -- NULL = all of type
    effect TEXT NOT NULL,         -- "allow" or "deny"
    conditions JSONB,
    created_at TIMESTAMPTZ DEFAULT now()
);
```

### Agents & VMs

```sql
CREATE TABLE agent_instances (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    department_id UUID REFERENCES departments(id),
    vm_id TEXT,
    status TEXT NOT NULL DEFAULT 'provisioning',
    config JSONB NOT NULL,
    vsock_cid INTEGER,
    tool_allowlist JSONB DEFAULT '[]',
    created_at TIMESTAMPTZ DEFAULT now(),
    last_health_check TIMESTAMPTZ
);
```

### Channels

```sql
CREATE TABLE channel_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    platform TEXT NOT NULL,           -- "whatsapp", "telegram", "slack"
    platform_user_id TEXT NOT NULL,   -- phone number, telegram ID, etc.
    verified BOOLEAN DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT now(),
    UNIQUE(platform, platform_user_id)
);
```

### Connectors

```sql
CREATE TABLE connectors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id),
    name TEXT NOT NULL,
    connector_type TEXT NOT NULL DEFAULT 'mcp',
    endpoint TEXT NOT NULL,
    auth_config JSONB NOT NULL,       -- encrypted credentials
    resources JSONB DEFAULT '[]',
    tools JSONB DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ DEFAULT now()
);
```

### Audit

```sql
CREATE TABLE audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    user_id UUID,
    action TEXT NOT NULL,
    resource_type TEXT,
    resource_id UUID,
    metadata JSONB,
    source TEXT NOT NULL,  -- "api", "whatsapp", "telegram", "system"
    created_at TIMESTAMPTZ DEFAULT now()
) PARTITION BY RANGE (created_at);
```

### Knowledge Bases

```sql
CREATE TABLE knowledge_bases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
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

### Row-Level Security

All tables with `tenant_id` get RLS:
```sql
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON users
    USING (tenant_id = current_setting('app.current_tenant_id')::UUID);
-- Applied to: users, departments, roles, user_roles, resource_policies,
--             agent_instances, channel_links, connectors, audit_events,
--             knowledge_bases, knowledge_base_grants (via FK join)
```

---

## Security Architecture: 5 Layers of Defense

### Layer 1: Tenant Isolation (Docker Containers or Firecracker MicroVMs)
- **Teams tier (Docker):** Each agent runs in a dedicated container on a per-tenant isolated Docker network. Containers have no egress by default. Resource limits via cgroups.
- **Enterprise tier (Firecracker):** Each agent gets a dedicated MicroVM with its own Linux kernel. Hardware-level isolation via KVM (same technology as AWS Lambda).
- Both tiers: no shared filesystem, no shared database connections, no shared API keys. Prompt injection blast radius contained to single agent's isolation unit.

### Layer 2: RBAC Enforcement (Control Plane)
- Every request passes through RBAC middleware before reaching any module
- Deny-by-default: no explicit allow = denied
- Roles scoped per department: user can be `dept_head` in Scouting but `read_only` in First Team
- Resource policies for exceptions (e.g., temporary cross-department access for a transfer deal)

### Layer 3: In-Guest Tool Restriction (Heimdall Agent)
- Small Go binary inside each container/MicroVM alongside OpenClaw
- Maintains tool allow-list configured from control plane
- Blocks unauthorized tool calls before they execute
- Network egress disabled by default; only allowlisted external APIs reachable

### Layer 4: Audit Trail (Detection & Response)
- Async buffered channel pipeline (nanoseconds added to hot path)
- Captures: who, what, when, from where, what resource, allow/deny decision
- Append-only (no UPDATE/DELETE permissions for app role)
- Time-partitioned for efficient querying and retention

### Layer 5: Active Prompt Injection Defense
- **Input Sentinel**: Pattern matching + secondary LLM classifier scans every message before it reaches OpenClaw. Suspicious messages quarantined and admin alerted.
- **Tool Call Validator**: Deterministic (non-LLM) validation of every tool call against RBAC policies at the parameter level. Even if injection tricks OpenClaw into making a call, the validator blocks it.
- **Canary Tokens**: Hidden strings in system prompts and tool responses. If they appear in agent output, the session is halted immediately (indicates model hijacking).
- **Behavioral Baselines**: Track normal tool usage patterns per role. Anomalies (scout querying 500 records in 5 minutes) trigger alerts.

---

## Agent Runtime Orchestration

Both tiers share the same lifecycle, warm pool, and health check patterns via the `VMDriver` interface.

### Lifecycle
```
[Warm Pool] → claim → [Provisioning] → config inject → [Running] → health fail → [Replacing]
```

### Warm Pool
- Pre-started agents (containers or MicroVMs) ready for tenant config
- Background reconciliation loop maintains N warm agents (configurable, default: 2)
- Claim time: ~200ms (warm) vs ~2-5s cold start (Docker) or ~125ms (Firecracker)

### VMDriver Interface
```go
type VMDriver interface {
    Start(ctx context.Context, spec VMSpec) (VMHandle, error)
    Stop(ctx context.Context, id string) error
    IsHealthy(ctx context.Context, id string) (bool, error)
    Cleanup(ctx context.Context, id string) error
}
```
Implementations: `DockerDriver` (Teams), `FirecrackerDriver` (Enterprise), `MockDriver` (tests).

### Teams Tier: Docker Containers
- Container image: `heimdall-agent` (Go binary) + OpenClaw Gateway (Node.js) in one container
- Per-tenant Docker networks (internal bridge, no external access)
- TCP transport: control plane connects to agent via `127.0.0.1:<basePort + CID>`
- Resource limits via Docker cgroups (`--cpus`, `--memory`)
- Hierarchical memory volumes mounted per container (see Memory section)

### Enterprise Tier: Firecracker MicroVMs
- Minimal Linux rootfs: heimdall-agent binary + OpenClaw runtime (Node.js) + locked-down filesystem (read-only root, writable `/data` per user)
- virtio-vsock: direct socket between host and guest (no TCP/IP networking), each VM gets unique Context ID (CID)
- Lower latency than network, no firewall rules needed
- Hardware-level isolation: separate kernel per agent

### Health Checks
- Heimdall Agent heartbeats every 10 seconds (over TCP for Docker, vsock for Firecracker)
- 3 missed heartbeats → mark unhealthy → replace with new warm agent
- Old agent destroyed, resources reclaimed

### Resource Limits
- CPU: configurable (default: 1 vCPU)
- Memory: configurable (default: 512MB)
- Disk: per-user workspace volume with configurable quota
- Network: disabled by default (Docker: internal-only network; Firecracker: outbound-only via iptables)

## Hierarchical Memory Model

Heimdall enforces four-layer memory isolation with hierarchical read-up and admin-controlled overrides.

### Volume Mounts Per Agent

```
/memory/personal/     → read-write  (per-user)
/memory/department/   → read-only   (per-department)
/memory/tenant/       → read-only   (per-tenant)
/memory/shared/       → read-only   (admin-granted cross-dept knowledge)
```

OpenClaw reads all four paths natively as local Markdown files.

### Access Rules

| Layer | Visibility | Writability |
|---|---|---|
| Personal | Only the owning user's agent | Read-write |
| Department | All agents in that department | Read-only (write via MCP tool) |
| Tenant | All agents in that tenant | Read-only (write via MCP tool) |
| Shared (admin grants) | Granted departments/roles/users | Read-only (write via MCP tool) |

### Default Hierarchy (zero config)
- Agents automatically see: personal + own department + own tenant memory
- No cross-department visibility by default
- Admin overrides allow selective cross-department sharing via knowledge base grants

### Publishing to Shared Memory
Agents publish via the built-in `heimdall_publish_memory` MCP tool. The control plane validates permissions, handles concurrency, and writes to the appropriate shared volume.

### Dynamic Context Injection
At message dispatch time, Heimdall prepends small dynamic context (recent alerts, conversation summaries) via the existing context snapshot system. ~5ms added latency.

---

## Client Integration (MCP Connectors)

Clients register MCP servers with Heimdall to bridge their platform with agents:

```
POST /api/v1/connectors
{
  "name": "marcelo-scouting",
  "type": "mcp",
  "endpoint": "https://api.marcelo.ai/mcp/scouting",
  "auth": { "type": "oauth2", ... },
  "tools": ["search_players", "get_report", "update_report", "move_pipeline"]
}
```

### Context Synchronization
- **Push (client → Heimdall):** Client pushes context updates when users take actions in the web app (`POST /api/v1/agents/:id/context`). Agent memory stays current.
- **Pull (agent → client via MCP):** Agent queries client data on demand via registered MCP tools. Source of truth is the client's database.

### RBAC on MCP Tools
Tool allow-lists map to registered MCP tools per role. RBAC applies at both the tool level and parameter level.

### Memory Isolation & Sharing Model
Heimdall enforces four explicit memory scopes. Every memory write must target one scope, and reads are limited by tenant + role + scope policy.

| Scope | Owner | Visibility | Typical Use |
|------|-------|------------|-------------|
| Session | Agent session | Single conversation/request | Scratch reasoning and temporary state |
| User | Individual user | That user only | Personal notes, private drafts |
| Department | Department | Members with department access | Scout reports, team-specific insights |
| Tenant (Org) | Tenant | Org-level authorized users | Shared strategy context, approved playbooks |

Rules:
- No cross-tenant reads/writes at any scope.
- Department scope cannot be read outside department membership unless explicit org-admin override.
- User scope cannot be read by peers by default; elevation requires explicit policy + audit.
- Scope precedence on retrieval: `session -> user -> department -> tenant`, with explicit conflict metadata.
- Retention and deletion are scope-aware; audit trail remains append-only.

---

## API Surface

### Auth
- `GET /auth/login` — Initiate OIDC flow
- `GET /auth/callback` — OIDC callback, issue JWT
- `POST /auth/token/refresh` — Refresh tokens

### Tenants
- `POST /api/v1/tenants` — Create tenant
- `GET /api/v1/tenants/:id` — Get tenant
- `PUT /api/v1/tenants/:id` — Update settings

### Users
- `POST /api/v1/users` — Create user
- `PUT /api/v1/users/:id/roles` — Assign roles
- `POST /api/v1/users/:id/channels` — Link messaging identity

### Departments
- `POST /api/v1/departments` — Create department
- `PUT /api/v1/departments/:id/users` — Manage membership

### Agents
- `POST /api/v1/agents` — Provision agent (spins up MicroVM)
- `GET /api/v1/agents/:id` — Status/health
- `DELETE /api/v1/agents/:id` — Destroy agent + VM
- `POST /api/v1/agents/:id/configure` — Update config/tool allow-list
- `POST /api/v1/agents/:id/message` — Send message to agent
- `WS /api/v1/agents/:id/stream` — WebSocket for streaming responses
- `POST /api/v1/agents/:id/context` — Push context update from client

### Connectors
- `POST /api/v1/connectors` — Register MCP server
- `GET /api/v1/connectors` — List connectors
- `DELETE /api/v1/connectors/:id` — Remove connector

### Channels (Webhooks)
- `POST /webhooks/whatsapp` — WhatsApp webhook
- `POST /webhooks/telegram` — Telegram webhook

**Phase 8 gates (must be implemented before channel rollout):**
- Verified identity linking flow: `platform + platform_user_id` must map to exactly one Heimdall user, with explicit verification state.
- Webhook authenticity: provider signature verification required on every inbound request.
- Message idempotency and replay defense: dedupe key per provider message ID with TTL window, reject duplicates and stale replays.
- Correlation IDs: each inbound message must propagate a stable request/audit correlation ID through auth, RBAC, sentinel, proxy, and audit.

### Audit
- `GET /api/v1/audit/events` — Query audit log

---

## Admin Dashboard (Next.js)

**Stack:** Next.js App Router + TypeScript + shadcn/ui + Tailwind + TanStack Query + NextAuth.js

**7 Views:**
1. **Overview** — Active agents, health status, recent activity, quick stats
2. **User Management** — User list, role assignment, channel linking
3. **Department Management** — Hierarchy tree, user assignment, agent config
4. **Agent Management** — Agent cards (status, health, uptime), provisioning, tool allow-list config, live console
5. **RBAC Configuration** — Role editor, resource policy builder, permission tester
6. **Audit Dashboard** — Filterable event timeline, denial log, security alerts
7. **Channels** — Connected platforms, identity linking management, message metrics

---

## Key Technical Decisions

| Decision | Choice | Reasoning |
|----------|--------|-----------|
| Architecture | Modular Monolith | 1-2 person team, single binary deployment, clean extraction path |
| Language | Go | Industry standard for control planes (K8s, Docker, Terraform), concurrency model, single binary |
| Isolation (Teams) | Docker containers | Per-tenant network isolation, cross-platform, easy deployment, ~2-5s cold start |
| Isolation (Enterprise) | Firecracker MicroVMs | Hardware-level tenant isolation, ~125ms boot, ~5MB overhead, AWS Lambda proven |
| Database | PostgreSQL + RLS | Row-level security for defense in depth, JSONB for flexibility, battle-tested |
| Auth | OAuth2/OIDC | Enterprise SSO ready from day one |
| RBAC | Hybrid roles + resource policies | Roles for 80% of cases, resource policies for exceptions |
| Integration | MCP protocol | Emerging standard for AI agent ↔ external system communication |
| Communication | TCP (Docker) / virtio-vsock (Firecracker) | TCP for cross-platform dev; vsock for low-latency host↔guest in production |
| Memory model | Hierarchical volumes + context injection | Read-only shared layers, read-write personal, MCP tool for publishing |
| Deployment | Hybrid (SaaS + on-prem) | SaaS default on AWS, single binary + Postgres for on-prem |
| Dashboard | Next.js + shadcn/ui | Fast admin UI development, SSR, TypeScript |

---

## MVP Build Phases

| Phase | Weeks | Modules | Key Deliverable |
|-------|-------|---------|-----------------|
| **1. Foundation** | 1-2 | `platform/*` | Go project scaffold, PostgreSQL + migrations, HTTP server, structured logging, health check |
| **2. Auth + RBAC** | 3-4 | `auth`, `rbac` | OIDC login, JWT validation, role definitions, policy evaluation middleware |
| **3. Tenant + Users** | 5-6 | `tenant` | Tenant CRUD, department hierarchy, user management, role assignment |
| **4. VM Orchestrator** | 7-9 | `orchestrator` | VMDriver interface, Docker + Firecracker drivers, warm pool, provisioning, health checks |
| **5. Proxy + Lifecycle** | 10-11 | `proxy`, `lifecycle` | TCP/vsock comms, request routing, OpenClaw lifecycle, in-guest Heimdall Agent |
| **6. Security + Audit** | 12-13 | `audit`, Layer 5 | Input Sentinel, Tool Call Validator, canary tokens, async audit pipeline |
| **7. Connectors** | 14 | `connectors` | MCP server registration, connection brokering, context push/pull API |
| **8. Channels** | 15-16 | `channels` | WhatsApp webhook integration, identity linking, message relay through RBAC |
| **9. Admin Dashboard** | 17-18 | `dashboard/*` | Next.js admin UI (7 views), connected to Go API |

Phase 8 is gated by `docs/plans/2026-02-22-phase8-channels-prerequisites.md`.

### Critical Files

- `cmd/heimdall/main.go` — Composition root, all module wiring
- `internal/orchestrator/manager.go` — Agent runtime orchestration (most complex module)
- `internal/orchestrator/docker_driver.go` — Docker container lifecycle (Teams tier)
- `internal/orchestrator/firecracker_driver.go` — Firecracker VM lifecycle (Enterprise tier)
- `internal/proxy/handler.go` — Host↔agent communication (critical data path)
- `internal/rbac/evaluator.go` — Policy evaluation engine (security-critical, on hot path)
- `internal/platform/middleware/middleware.go` — Request pipeline spine
- `heimdall-agent/main.go` — In-guest sidecar (tool restriction, health reporting)
- `internal/channels/whatsapp.go` — WhatsApp webhook + identity resolution
- `internal/connectors/broker.go` — MCP connection brokering

### Key Dependencies

- `github.com/docker/docker` — Docker Engine API client (Teams tier)
- Firecracker binary + jailer (Enterprise tier, Linux only)
- `github.com/coreos/go-oidc/v3` — OIDC provider integration
- `github.com/golang-jwt/jwt/v5` — JWT handling
- `github.com/jackc/pgx/v5` — PostgreSQL driver
- `github.com/golang-migrate/migrate/v4` — DB migrations
- `go.opentelemetry.io/otel` — Observability (metrics, tracing)

---

## Verification Plan

### Phase 1 (Foundation)
- `go build ./cmd/heimdall` compiles successfully
- `./heimdall --config config.yaml` starts HTTP server on configured port
- `GET /healthz` returns 200
- PostgreSQL migrations apply cleanly
- Structured JSON logs appear on stdout

### Phase 2 (Auth + RBAC)
- OIDC login flow redirects to provider and back
- JWT issued on successful callback
- Authenticated requests pass middleware; unauthenticated return 401
- RBAC middleware denies access for unpermitted roles (403)

### Phase 3 (Tenants)
- Create tenant via API, verify in database
- Create departments with hierarchy
- Create users, assign to departments and roles
- Verify cross-tenant isolation via RLS

### Phase 4 (Orchestrator)
- Docker container (Teams) or Firecracker MicroVM (Enterprise) boots from warm pool
- Health checks report running status
- Unhealthy agent is replaced automatically
- Agent destroyed cleanly on tenant deprovisioning

### Phase 5 (Proxy + Lifecycle)
- Send message via API → receive OpenClaw response
- SSE streaming works end-to-end
- heimdall-agent spawns OpenClaw as child process
- In-guest Heimdall Agent enforces tool allow-list

### Phase 6 (Security + Audit)
- Input Sentinel blocks known injection patterns
- Tool Call Validator denies cross-department tool calls
- Canary token leak triggers session halt
- Audit events appear in database for every action
- Isolation proof suite passes for cross-tenant API, connector, and tool path negatives

### Phase 7 (Connectors)
- Register MCP server via API
- Agent can call registered MCP tools
- Context push from client appears in agent memory
- RBAC applies to MCP tool calls

### Phase 8 (Channels)
- WhatsApp webhook receives messages
- Phone number resolves to Heimdall user
- RBAC applies to messaging requests
- Agent response returns via WhatsApp
- Duplicate webhook deliveries are deduplicated (idempotency key)
- Replay attempts with reused message IDs are rejected and audited

### Phase 9 (Dashboard)
- Admin can login via OIDC
- All 7 views render with real data from Go API
- CRUD operations work for tenants, users, departments, agents
- Audit log view shows real events

### End-to-End Smoke Test
1. Admin creates tenant "Chelsea FC" with departments: Scouting, First Team
2. Admin creates Scout A (standard_user in Scouting) and DoF (org_admin)
3. Admin provisions agent for Scouting department
4. Admin registers Marcelo AI's MCP server as connector
5. Admin links Scout A's WhatsApp number
6. Scout A sends WhatsApp: "Search for centre-backs under 25 in Serie A"
7. Message flows through: channels → auth → RBAC → sentinel → proxy → agent container/VM → OpenClaw → MCP tool call → Tool Call Validator → Marcelo AI's API → response back via WhatsApp
8. Scout A sends: "What did the DoF write about the transfer budget?"
9. Tool Call Validator blocks (scout has no access to executive data)
10. Audit log shows both the allowed and denied actions
