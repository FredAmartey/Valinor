# Agent Debug Console Design

## Goal

Add a WebSocket relay endpoint and a dashboard chat UI so admins can interactively test, debug, and demo agents directly from the agent detail page.

## Context

- Current agent messaging uses HTTP POST (`/message` for buffered, `/stream` for SSE)
- SSE is server→client only — client can't send follow-ups over the same connection
- No dashboard UI exists for sending messages to agents
- `tool_executed` and `tool_failed` frames are consumed for audit but never shown to clients
- The existing `AgentConn` + `ConnPool` infrastructure already supports concurrent request multiplexing by ID

## Scope

### In scope

**Backend:**
- `GET /api/v1/agents/{id}/ws` — WebSocket upgrade handler
- JWT auth at upgrade time via `access_token` query parameter
- Bidirectional relay: client JSON messages → agent frames, agent frames → client JSON messages
- Forward `tool_executed`, `tool_blocked`, `session_halt` events to the client (currently audit-only)
- Sentinel scan on every inbound message
- User context injection per existing pattern
- `nhooyr.io/websocket` dependency

**Frontend:**
- `useAgentWebSocket(agentId)` React hook — WS lifecycle, reconnect, message state
- `AgentChat` component on `/agents/[id]` detail page — message list, streaming responses, tool events, input bar
- Only shown when agent status is `running`

### Out of scope

- No chat history persistence (ephemeral debug console)
- No reconnect-and-resume (new WS = new conversation)
- No multi-agent chat (one agent per connection)
- No file upload or multimodal (text only)
- No rate limiting beyond sentinel (admin-only, RBAC-gated)

## Backend Design

### Route

`GET /api/v1/agents/{id}/ws` — registered alongside existing agent routes in `server.go`

RBAC: `agents:message` permission required (org_admin has wildcard, dept_head has it, standard_user has it, read_only does not)

### Auth at Upgrade

Browsers cannot set custom headers on WebSocket upgrade. JWT is passed as query parameter:
```
ws://localhost:8080/api/v1/agents/{id}/ws?access_token=eyJ...
```
The handler extracts the token, validates it using the existing `auth.ValidateToken` logic, checks tenant ownership and RBAC, then upgrades. If any check fails, respond with HTTP 401/403 before upgrade.

### WebSocket Protocol

**Client → Server:**
```json
{"type": "message", "content": "What players match these criteria?"}
```
Only `"message"` type is supported from client. Server ignores unknown types.

**Server → Client:**
```json
{"type": "chunk", "request_id": "uuid", "content": "Based on...", "done": false}
{"type": "chunk", "request_id": "uuid", "content": " the data", "done": true}
{"type": "tool_executed", "request_id": "uuid", "tool_name": "search_players"}
{"type": "tool_blocked", "request_id": "uuid", "tool_name": "bash", "reason": "not in allowlist"}
{"type": "error", "request_id": "uuid", "message": "agent error: timeout"}
{"type": "session_halt", "request_id": "uuid", "reason": "canary token detected"}
```

### Handler Internals

Two goroutines per WS connection:

**Read loop:**
1. Read JSON message from WS
2. Validate `type == "message"` and `content` is non-empty
3. Run sentinel scan on content
4. Inject user context from `agent_context_snapshots`
5. Build TypeMessage frame with new UUID request ID
6. Call `AgentConn.SendRequest(ctx, frame)` to get a `RequestStream`
7. Register the stream with the write loop

**Write loop:**
1. Select across all active `RequestStream` channels
2. On each frame: marshal to JSON, write to WS
3. Forward `TypeChunk`, `TypeError`, `TypeToolBlocked`, `TypeSessionHalt`, `TypeToolExecuted`, `TypeToolFailed`
4. On `TypeChunk` with `done: true` or error frames: clean up that request stream

**Connection lifecycle:**
- Server sends WS close frame on: agent status change to non-running, auth token expiry, context cancel
- Client close or network drop: both goroutines exit, request streams are cleaned up
- No automatic reconnect server-side

### Audit

Each message exchange is audit-logged as `agent.message.ws` (new action) with the same metadata as the existing HTTP handlers.

## Frontend Design

### Hook: `useAgentWebSocket`

```ts
function useAgentWebSocket(agentId: string, enabled: boolean): {
  messages: ChatMessage[]
  sendMessage: (content: string) => void
  status: "connecting" | "connected" | "disconnected" | "error"
  error: string | null
}
```

- Connects when `enabled` is true (agent is running)
- Manages message state as a local array (not TanStack Query — ephemeral)
- Handles WS lifecycle: open, message parsing, close, error
- Auto-reconnect with backoff on unexpected disconnect (max 3 attempts)

### Component: `AgentChat`

Placed on the `/agents/[id]` page, below or beside the existing agent metadata. Only rendered when `agent.status === "running"`.

**Layout:**
- Message area (scrollable, auto-scroll to bottom)
- Input bar at bottom with send button
- Connection status indicator

**Message types rendered:**
- User messages — right-aligned
- Agent response chunks — left-aligned, streams in as chunks arrive, coalesced into a single bubble
- Tool events — centered system messages (muted styling): "Calling `search_players`...", "Tool `bash` blocked: not in allowlist"
- Errors — inline error banner
- Session halt — prominent warning banner

### Types

```ts
interface ChatMessage {
  id: string
  type: "user" | "assistant" | "tool" | "error" | "halt"
  content: string
  toolName?: string
  requestId?: string
  timestamp: number
  streaming?: boolean  // true while chunks are still arriving
}
```

## Acceptance Criteria

- Admin can open `/agents/[id]` for a running agent and see the chat panel
- Admin can type a message and see the agent's response stream in real-time
- Tool execution events appear as system messages in the chat
- Blocked tools and session halts are clearly surfaced
- Sentinel blocks show an error before the message reaches the agent
- WS connection closes cleanly when navigating away or agent stops
- Read-only users cannot access the chat (RBAC `agents:message`)
- Non-running agents show a disabled state with explanation
