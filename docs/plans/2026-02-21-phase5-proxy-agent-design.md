# Phase 5: Proxy + In-Guest Agent — Design

**Date:** 2026-02-21
**Status:** Approved
**Phase:** 5 of 9 (MVP Build)

## Goal

Build the vsock communication layer, proxy module, and in-guest valinor-agent binary so that clients can send messages to agents, receive streaming responses, and push config updates to running VMs.

## Architecture Overview

```
Control Plane (existing Valinor binary)
  ├── proxy/              ← NEW: message relay + SSE streaming
  │     ├── VsockDialer   — connects to VMs via vsock CID
  │     ├── AgentConn     — per-VM connection with length-prefixed JSON protocol
  │     ├── ConnPool      — maintains open connections per agent
  │     └── Handler       — HTTP: /message, /stream (SSE), /context
  │
  └── orchestrator/       ← MODIFIED: config push delegates to proxy
        └── Handler       — HandleConfigure calls proxy.PushConfig()

In-Guest (separate binary: cmd/valinor-agent)
  └── valinor-agent       ← NEW: runs inside each MicroVM
        ├── VsockListener — accepts control plane connections on vsock port 1024
        ├── OpenClawProxy — HTTP reverse proxy to localhost:8081
        ├── AllowList     — intercepts tool calls, enforces allow-list
        └── Heartbeat     — sends heartbeat every 10s over vsock
```

### End-to-End Message Flow

```
Client → POST /agents/:id/message
  → proxy.Handler validates tenant, looks up vsock CID
  → proxy.AgentConn dials vsock CID, sends message frame
  → valinor-agent receives, forwards to OpenClaw at localhost:8081
  → OpenClaw processes, streams response chunks
  → valinor-agent relays chunks back over vsock
  → proxy.Handler streams via SSE to client
```

### Transport Abstraction

vsock is Linux-only. On macOS dev, the proxy uses a TCP mock transport (same protocol, localhost:PORT instead of vsock:CID).

```go
type Transport interface {
    Dial(ctx context.Context, cid uint32) (net.Conn, error)
    Listen(ctx context.Context, port uint32) (net.Listener, error)
}
```

Two implementations: `VsockTransport` (Linux, `AF_VSOCK`) and `TCPTransport` (dev, maps CID to localhost:PORT).

## Wire Protocol — Length-Prefixed JSON

Every message on the wire (both directions) follows the same frame format:

```
[4 bytes: payload length, big-endian uint32] [N bytes: JSON payload]
```

### Frame Envelope

```go
type Frame struct {
    Type    string          `json:"type"`
    ID      string          `json:"id"`       // request correlation ID
    Payload json.RawMessage `json:"payload"`
}
```

### Message Types (Control Plane → Agent)

| Type | Payload | Description |
|------|---------|-------------|
| `config_update` | `{config, tool_allowlist}` | Push new config |
| `message` | `{role, content}` | User message for OpenClaw |
| `context_update` | `{context}` | Push additional context |
| `ping` | `{}` | Health probe |

### Message Types (Agent → Control Plane)

| Type | Payload | Description |
|------|---------|-------------|
| `heartbeat` | `{status, uptime_secs}` | Every 10s |
| `chunk` | `{id, content, done}` | Streaming response chunk |
| `config_ack` | `{applied}` | Config update confirmation |
| `tool_blocked` | `{tool_name, reason}` | Allow-list rejection |
| `pong` | `{}` | Health probe reply |
| `error` | `{code, message}` | Error from agent/OpenClaw |

### Connection Lifecycle

1. Control plane dials `vsock:CID:1024` (port 1024 is the agent listen port)
2. Agent sends initial `heartbeat` on connect
3. Connection stays open — multiplexed by `Frame.ID` for concurrent requests
4. If connection drops, control plane redials on next request (lazy reconnect)

## Proxy Module (Control Plane)

### ConnPool

Maintains open vsock connections per agent, lazy-connects on first use:

```go
type ConnPool struct {
    transport Transport
    mu        sync.Mutex
    conns     map[string]*AgentConn // keyed by agent instance ID
}

func (p *ConnPool) Get(ctx context.Context, agentID string, cid uint32) (*AgentConn, error)
func (p *ConnPool) Remove(agentID string)
```

### AgentConn

Wraps a net.Conn with the length-prefixed JSON protocol:

```go
type AgentConn struct {
    conn   net.Conn
    mu     sync.Mutex // serializes writes
    readMu sync.Mutex // serializes reads
}

func (c *AgentConn) Send(ctx context.Context, frame Frame) error
func (c *AgentConn) Recv(ctx context.Context) (Frame, error)
func (c *AgentConn) Close() error
```

### HTTP Handlers

| Endpoint | Permission | Flow |
|----------|-----------|------|
| `POST /agents/:id/message` | `agents:write` | Validates tenant → gets conn → sends `message` frame → collects `chunk` frames until `done:true` → returns full response as JSON |
| `GET /agents/:id/stream` | `agents:write` | Same but returns SSE: each chunk becomes an SSE `data:` event |
| `POST /agents/:id/context` | `agents:write` | Sends `context_update` frame → waits for ack → returns 200 |

### SSE Format

```
event: chunk
data: {"content": "The transfer fee for...", "done": false}

event: chunk
data: {"content": " Ronaldo was €100M.", "done": true}

event: done
data: {}
```

### Config Push Integration

The existing `HandleConfigure` in orchestrator calls into proxy after DB update:

```go
if inst.Status == StatusRunning {
    proxy.PushConfig(ctx, inst.ID, inst.VsockCID, config, toolAllowlist)
}
```

Orchestrator handler owns the endpoint; proxy module handles the vsock push.

## In-Guest Valinor Agent (`cmd/valinor-agent`)

A standalone Go binary that runs inside each MicroVM.

### Startup Sequence

1. Listen on vsock port 1024 (or TCP port from flag for local dev)
2. Load initial config from `/etc/valinor/agent.json` (baked into rootfs)
3. Start heartbeat goroutine (sends `heartbeat` every 10s)
4. Accept connection from control plane
5. Read frames in a loop, dispatch by type

### Core Loop

```go
for {
    frame := conn.Recv(ctx)
    switch frame.Type {
    case "config_update":
        applyConfig(frame.Payload)
        conn.Send(configAckFrame)
    case "message":
        go handleMessage(ctx, conn, frame)
    case "context_update":
        forwardContext(frame.Payload)
    case "ping":
        conn.Send(pongFrame)
    }
}
```

### OpenClaw Proxy

- HTTP client to `localhost:8081` (OpenClaw's local API)
- On `message` frame: `POST http://localhost:8081/v1/chat/completions` with streaming
- Reads OpenClaw streaming response, wraps each chunk as a `chunk` frame, sends back over vsock
- If OpenClaw makes a tool call, agent checks `tool_allowlist` before forwarding

### Tool Allow-List Enforcement

```go
func (a *Agent) isToolAllowed(toolName string) bool {
    if len(a.toolAllowlist) == 0 {
        return true // empty list = all allowed
    }
    return slices.Contains(a.toolAllowlist, toolName)
}
```

If blocked, sends `tool_blocked` frame instead of forwarding the tool call.

### Flags

```
valinor-agent --transport vsock --port 1024
valinor-agent --transport tcp --port 9100  # local dev
```

## Error Handling

| Scenario | Behavior |
|----------|----------|
| Agent not running | Proxy returns `503 Service Unavailable` |
| Vsock connection drops mid-message | Proxy returns `502 Bad Gateway`, removes conn from pool |
| OpenClaw timeout (30s default) | Agent sends `error` frame, proxy returns `504 Gateway Timeout` |
| Tool blocked by allow-list | Agent sends `tool_blocked` frame, included in SSE stream |
| Config push to dead agent | DB updated, warning logged. Health check catches it. |
| Malformed frame | Receiving side closes connection, logs error |

## Timeouts

| Operation | Timeout |
|-----------|---------|
| Message request | 60s (configurable) |
| Config push | 5s |
| Ping/pong | 3s |
| SSE stream | No timeout (client controls disconnect) |

## Testing Strategy

| Layer | Approach |
|-------|----------|
| Wire protocol (Frame encode/decode) | Pure unit tests, no I/O |
| AgentConn (Send/Recv) | net.Pipe() — two in-memory connected sockets |
| ConnPool | TCPTransport + mock agent listener on localhost |
| Proxy Handler (HTTP) | httptest + mock ConnPool with pre-canned frames |
| valinor-agent core loop | net.Pipe() — send frames, assert responses |
| Tool allow-list | Unit tests, pure logic |
| OpenClaw proxy | httptest mock server simulating streaming responses |
| End-to-end | Integration: start valinor-agent on TCP, proxy connects, send message, receive streamed chunks |

No vsock required for any test. Everything uses TCPTransport or net.Pipe().

## Decisions Log

| Decision | Choice | Reasoning |
|----------|--------|-----------|
| Wire format | Length-prefixed JSON | Simple, debuggable, sufficient for MVP throughput |
| Client streaming | SSE | Works through proxies/CDNs, simpler than WebSocket for server→client |
| OpenClaw integration | HTTP proxy to localhost:8081 | Decoupled, testable, production-ready |
| Transport abstraction | VsockTransport / TCPTransport | Enables macOS development without vsock |
| Agent heartbeat | Over vsock, 10s interval | Replaces MockDriver.IsHealthy() with real signal |
| Config push | Orchestrator handler → proxy module | Clean separation of concerns |
