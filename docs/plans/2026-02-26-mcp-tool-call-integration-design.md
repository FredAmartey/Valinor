# MCP Tool Call Integration — Design Document

## Goal

End-to-end tool execution: register an MCP server, provision an agent with its tools, send a message, OpenClaw calls a tool, valinor-agent validates and executes via MCP JSON-RPC 2.0, result returned to OpenClaw, final response back to user.

## Delivery

Single PR touching backend only (Go). No dashboard changes.

---

## Architecture

Four components:

1. **Connector injection** — wire `connectorStore.ListForAgent()` into orchestrator config push
2. **MCP JSON-RPC client** — new HTTP client in valinor-agent implementing `tools/call`
3. **Agentic tool loop** — modify OpenClaw handler to execute tools and loop until final response
4. **Audit events** — emit `tool.executed` and `tool.failed` from agent

---

## Component 1: Connector Injection at Provision/Config

### Changes

- Extend `TypeConfigUpdate` payload to include `connectors` field
- Wire `connectorStore` (via `ListForAgent()`) into orchestrator `HandleProvision` and `HandleConfigure`
- Pass connector store to orchestrator handler via dependency injection
- Agent parses and stores connectors alongside allowlist/policies

### Config Push Payload (extended)

```json
{
  "config": {},
  "tool_allowlist": ["search_players", "get_report"],
  "tool_policies": {},
  "canary_tokens": [],
  "connectors": [
    {
      "name": "marcelo-api",
      "type": "mcp",
      "endpoint": "https://api.marcelo.ai/mcp",
      "auth": {"api_key": "..."},
      "tools": ["search_players", "get_report"]
    }
  ]
}
```

### Files

- Modify: `internal/orchestrator/handler.go` — inject connectors into config push
- Modify: `internal/proxy/push.go` — add connectors param to `PushConfig`
- Modify: `cmd/valinor-agent/agent.go` — parse and store connectors from config update
- Modify: `cmd/valinor/main.go` — wire connector store into orchestrator handler

---

## Component 2: MCP JSON-RPC Client

### Protocol

MCP uses JSON-RPC 2.0 over HTTP. The agent sends:

```
POST {connector.endpoint}
Content-Type: application/json
Authorization: Bearer {connector.auth.api_key}

{
  "jsonrpc": "2.0",
  "id": "req-<uuid>",
  "method": "tools/call",
  "params": {
    "name": "search_players",
    "arguments": {"league": "Serie A"}
  }
}
```

Response:

```json
{
  "jsonrpc": "2.0",
  "id": "req-<uuid>",
  "result": {
    "content": [{"type": "text", "text": "{\"players\": [...]}"}]
  }
}
```

### Client Behavior

- Resolve which connector owns the tool by matching tool name to `connector.tools[]`
- Construct JSON-RPC 2.0 request envelope
- Apply auth from `connector.auth` (Bearer token via `api_key` field)
- Timeout: 30 seconds per tool call (configurable)
- Parse MCP response: extract text from `result.content[]` where `type == "text"`
- Handle JSON-RPC errors: `error.code`, `error.message`
- Return result text or error to caller

### Files

- Create: `cmd/valinor-agent/mcp.go` — MCP client + connector resolver

---

## Component 3: Agentic Tool Execution Loop

### Current Flow (incomplete)

```
Agent receives message → forwards to OpenClaw → gets response with tool_calls →
validates tool call → [STOPS HERE] → sends text response back
```

### New Flow

```
Agent receives message → forwards to OpenClaw → gets response →
  if tool_calls present:
    for each tool_call:
      validate (existing) → if blocked: send TypeToolBlocked, return
      execute via MCP client → get result
    build follow-up request with tool results
    send to OpenClaw again
    repeat until no more tool_calls OR max iterations (10)
  send final text response as TypeChunk
```

### OpenClaw Tool Result Format

OpenClaw expects tool results in the chat completions format:

```json
{
  "messages": [
    {"role": "user", "content": "Find Serie A players"},
    {"role": "assistant", "tool_calls": [{"id": "tc-1", "function": {"name": "search_players", "arguments": "{\"league\": \"Serie A\"}"}}]},
    {"role": "tool", "tool_call_id": "tc-1", "content": "{\"players\": [...]}"}
  ]
}
```

The agent accumulates messages across loop iterations and sends the full conversation to OpenClaw on each round.

### Safety

- Max 10 tool call iterations per message (prevents runaway loops)
- 30-second timeout per individual tool call
- 120-second total timeout for the entire message processing
- If any tool call fails, send error response back (don't silently drop)

### Files

- Modify: `cmd/valinor-agent/openclaw.go` — implement agentic loop with tool execution

---

## Component 4: Audit Events

### New Constants

```go
ActionToolExecuted = "tool.executed"
ActionToolFailed   = "tool.failed"
```

### Emission Points

From within the agent's tool execution loop:
- After successful MCP call: emit `tool.executed` with metadata `{tool_name, connector_name, duration_ms}`
- After failed MCP call: emit `tool.failed` with metadata `{tool_name, connector_name, error, duration_ms}`

The agent sends audit events via `TypeToolBlocked` frame type (already exists for blocked tools). Add new frame types `TypeToolExecuted` and `TypeToolFailed` that the proxy handler forwards to the audit logger.

### Files

- Modify: `internal/audit/audit.go` — add constants
- Modify: `internal/proxy/protocol.go` — add frame types
- Modify: `internal/proxy/handler.go` — handle new frame types, forward to audit logger
- Modify: `cmd/valinor-agent/openclaw.go` — emit frames after tool execution

---

## Testing

| Layer | Test | Type |
|-------|------|------|
| MCP client | Mock HTTP server returning JSON-RPC responses | Unit |
| MCP client | Error handling (timeout, invalid JSON-RPC, auth failure) | Unit |
| Connector resolver | Tool-to-connector mapping | Unit |
| Tool loop | Single tool call → result → final response | Unit |
| Tool loop | Multi-tool sequence (2 calls in sequence) | Unit |
| Tool loop | Max iteration limit enforcement | Unit |
| Connector injection | ListForAgent called during provision | Unit |
| Config push | Connectors included in payload | Unit |
| Existing | Tool validator tests unchanged | Regression |

---

## Acceptance Criteria

1. Registering a connector and provisioning an agent injects connector config into the agent
2. When OpenClaw returns a tool call, the agent executes it via MCP JSON-RPC
3. Tool results are fed back to OpenClaw for continued processing
4. Multi-tool sequences work (OpenClaw calls tool A, then tool B)
5. Tool calls respect the existing allowlist and parameter policies
6. Failed tool calls return errors (not silent failures)
7. Max iteration limit prevents runaway loops
8. Audit events emitted for tool execution (success and failure)
9. `go test ./...` passes
10. `go build ./...` passes

---

## Risks & Rollback

| Risk | Mitigation |
|------|------------|
| MCP server unavailable | 30s timeout per call, error returned to user |
| Runaway tool loops | Max 10 iterations, 120s total timeout |
| Auth credential exposure | Credentials in connector config, encrypted at rest in DB, passed via vsock (not network) |
| Breaking existing tool validation | Validation code unchanged, execution added after validation |

Rollback: revert Go PR. Connector registration still works, tool calls just won't execute (existing behavior).
