# Phase 7: Connectors — Design Document

**Date:** 2026-02-22
**Status:** Approved

## Goal

Implement MCP connector registration, listing, deletion, and agent-side credential injection so tenants can register external MCP servers and their agents can call them directly.

## Key Decisions

| Decision | Choice | Reasoning |
|----------|--------|-----------|
| MCP routing | Direct from agent | Agent calls MCP endpoints directly; control plane injects credentials via config_update. Lower latency, simpler. |
| Credential storage | Plaintext JSONB | auth_config stored as-is. PostgreSQL disk encryption + RLS for baseline. Application-level encryption deferred. |
| Registration validation | Store only | No endpoint health-check on registration. Validation happens implicitly when agent calls MCP server. |
| Architecture | Thin CRUD layer | Handler + Store, reuses existing config_update pipeline. No broker service, no event bus. |

## Architecture

The `connectors` package is a straightforward CRUD module: handler + store. Connector configs are persisted to the existing `connectors` table (migration 000001). When an agent is configured, the orchestrator queries the tenant's connectors and includes them in the config_update frame sent to the agent via vsock. The agent-side sidecar passes connector configs to OpenClaw's MCP configuration.

No new wire protocol frames — reuses `TypeConfigUpdate` / `TypeConfigAck`.

---

## Section 1: Store & Domain Types

### Connector Type

```go
// internal/connectors/connectors.go
type Connector struct {
    ID            uuid.UUID       `json:"id"`
    TenantID      uuid.UUID       `json:"tenant_id"`
    Name          string          `json:"name"`
    ConnectorType string          `json:"connector_type"`
    Endpoint      string          `json:"endpoint"`
    AuthConfig    json.RawMessage `json:"auth_config"`
    Resources     json.RawMessage `json:"resources"`
    Tools         json.RawMessage `json:"tools"`
    Status        string          `json:"status"`
    CreatedAt     time.Time       `json:"created_at"`
}
```

### Store Operations

All operations accept `database.Querier` for RLS compatibility:

- `Create(ctx, q, tenantID, name, connectorType, endpoint, authConfig, tools, resources)` — INSERT RETURNING
- `ListByTenant(ctx, q)` — SELECT all for current tenant (RLS filters)
- `GetByID(ctx, q, id)` — SELECT by UUID
- `Delete(ctx, q, id)` — DELETE, returns `ErrNotFound` if 0 rows affected
- `ListForAgent(ctx, q)` — Returns connectors as simplified config maps for agent injection

Follows `DepartmentStore` pattern — accepts `database.Querier` to run inside `WithTenantConnection`.

---

## Section 2: HTTP Handler & Routes

### Handler

```go
type Handler struct {
    pool  *pgxpool.Pool
    store *Store
}
```

### Endpoints

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| POST | `/api/v1/tenants/{tenantID}/connectors` | `connectors:write` | Register MCP server |
| GET | `/api/v1/tenants/{tenantID}/connectors` | `connectors:read` | List tenant's connectors |
| DELETE | `/api/v1/connectors/{id}` | `connectors:write` | Remove connector |

### Request Validation

**HandleCreate:**
- `name` required, non-empty
- `endpoint` required, must be valid URL
- `connector_type` defaults to `"mcp"` if omitted
- `auth_config` defaults to `{}` if omitted
- `tools` defaults to `[]` if omitted

**HandleDelete:**
- Connector ID must be valid UUID
- Returns 404 if connector not found within tenant scope

### Auth Config in Responses

Returned as-is (plaintext JSONB). Future phase will redact secrets in API responses.

### Route Registration

```go
if deps.ConnectorHandler != nil && deps.RBAC != nil {
    protectedMux.Handle("POST /api/v1/tenants/{tenantID}/connectors", ...)
    protectedMux.Handle("GET /api/v1/tenants/{tenantID}/connectors", ...)
    protectedMux.Handle("DELETE /api/v1/connectors/{id}", ...)
}
```

### RBAC Permissions

Added to default roles:
- `org_admin`: `connectors:read`, `connectors:write`
- `dept_head`: `connectors:read`, `connectors:write`

---

## Section 3: Agent Config Integration

### Flow

1. Admin registers connector via `POST /api/v1/tenants/:id/connectors`
2. Admin configures agent via `POST /api/v1/agents/:id/configure`
3. Orchestrator handler queries tenant's connectors from store
4. config_update frame includes `connectors` field:

```json
{
  "config": { ... },
  "tool_allowlist": ["search_players", "get_report"],
  "tool_policies": { ... },
  "canary_tokens": ["..."],
  "connectors": [
    {
      "name": "marcelo-scouting",
      "type": "mcp",
      "endpoint": "https://api.marcelo.ai/mcp/scouting",
      "auth": { "type": "bearer", "token": "sk-..." },
      "tools": ["search_players", "get_report"]
    }
  ]
}
```

### Changes Required

- **`proxy/push.go`** — `PushConfig` extended with `connectors []map[string]any`
- **`orchestrator/handler.go`** — `HandleConfigure` queries connectors, includes in push
- **`cmd/valinor-agent/agent.go`** — `handleConfigUpdate` stores connector configs
- **`cmd/valinor-agent/openclaw.go`** — Writes connector configs to OpenClaw MCP config

### No Auto-Sync

Connector CRUD does not auto-push to running agents. Admin must reconfigure the agent for changes to take effect. Event-driven auto-sync deferred to a later phase.

---

## Section 4: Wiring & Testing

### DI Wiring (main.go)

```go
var connectorHandler *connectors.Handler
if pool != nil {
    connectorStore := connectors.NewStore()
    connectorHandler = connectors.NewHandler(pool, connectorStore)
}
```

`ConnectorHandler` added to `server.Dependencies`.

### Connector Resolver Interface

Orchestrator handler receives a `ConnectorResolver` interface (not the connectors package directly):

```go
type ConnectorResolver interface {
    ResolveForTenant(ctx context.Context, tenantID string) ([]map[string]any, error)
}
```

Adapter in main.go bridges `connectors.Store` to this interface.

### Audit Events

- `connector.created` — logged on successful registration
- `connector.deleted` — logged on successful deletion

Both use existing audit infrastructure (fire-and-forget via `audit.Logger`).

### Testing

- **Store tests:** CRUD operations, duplicate name handling, not-found on delete
- **Handler tests:** HTTP request/response, validation (missing name, invalid endpoint), 404 on missing connector
- **Integration test:** Register connector -> configure agent -> verify connector in config_update payload
- **RLS test:** Connector from tenant A not visible to tenant B
