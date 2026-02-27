# Agent Debug Console Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a WebSocket relay endpoint and a dashboard chat UI so admins can interactively test agents from the agent detail page.

**Architecture:** New `HandleWebSocket` method on the existing `proxy.Handler` — upgrades HTTP to WS, authenticates via query-param JWT, then runs read/write goroutines bridging WS frames to the existing `AgentConn.SendRequest` infrastructure. Dashboard adds a `useAgentWebSocket` hook and `AgentChat` component to the `/agents/[id]` detail page.

**Tech Stack:** Go (`nhooyr.io/websocket`), TypeScript, React, browser WebSocket API

**Reference files:**
- Backend handler pattern: `internal/proxy/handler.go` (HandleStream is the closest analog)
- Frame protocol: `internal/proxy/protocol.go`
- Connection multiplexing: `internal/proxy/conn.go` (SendRequest/RequestStream)
- Route registration: `internal/platform/server/server.go`
- Handler construction: `cmd/valinor/main.go` (lines 241-258)
- Auth token validation: `internal/auth/token.go` (TokenService.ValidateToken)
- Agent detail page: `dashboard/src/components/agents/agent-detail.tsx`
- Agent queries: `dashboard/src/lib/queries/agents.ts`

---

### Task 1: Add `nhooyr.io/websocket` dependency

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`

**Step 1: Add the dependency**

Run: `go get nhooyr.io/websocket@latest`

**Step 2: Verify**

Run: `go build ./...`
Expected: Clean build, no errors

**Step 3: Commit**

```bash
git add go.mod go.sum
git commit -m "deps: add nhooyr.io/websocket for agent debug console"
```

---

### Task 2: WebSocket handler — test for auth rejection

**Files:**
- Create: `internal/proxy/ws_handler.go`
- Create: `internal/proxy/ws_handler_test.go`

**Step 1: Write the failing test**

```go
// internal/proxy/ws_handler_test.go
package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/valinor-ai/valinor/internal/auth"
)

// mockTokenService implements just enough for WS auth testing
type mockTokenService struct {
	identity *auth.Identity
	err      error
}

func (m *mockTokenService) ValidateToken(token string) (*auth.Identity, error) {
	return m.identity, m.err
}

func TestHandleWebSocket_RejectsNoToken(t *testing.T) {
	h := &Handler{}
	ts := &mockTokenService{err: auth.ErrTokenInvalid}
	h.tokenValidator = ts

	req := httptest.NewRequest("GET", "/api/v1/agents/agent-1/ws", nil)
	req.SetPathValue("id", "agent-1")
	rec := httptest.NewRecorder()

	h.HandleWebSocket(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandleWebSocket_RejectsExpiredToken(t *testing.T) {
	h := &Handler{}
	ts := &mockTokenService{err: auth.ErrTokenExpired}
	h.tokenValidator = ts

	req := httptest.NewRequest("GET", "/api/v1/agents/agent-1/ws?access_token=expired", nil)
	req.SetPathValue("id", "agent-1")
	rec := httptest.NewRecorder()

	h.HandleWebSocket(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandleWebSocket_RejectsRefreshToken(t *testing.T) {
	h := &Handler{}
	ts := &mockTokenService{identity: &auth.Identity{
		UserID:    "u-1",
		TenantID:  "t-1",
		TokenType: "refresh",
	}}
	h.tokenValidator = ts

	req := httptest.NewRequest("GET", "/api/v1/agents/agent-1/ws?access_token=refresh-tok", nil)
	req.SetPathValue("id", "agent-1")
	rec := httptest.NewRecorder()

	h.HandleWebSocket(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/ -run TestHandleWebSocket -v`
Expected: FAIL — `HandleWebSocket` and `tokenValidator` undefined

**Step 3: Write minimal implementation**

```go
// internal/proxy/ws_handler.go
package proxy

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

// TokenValidator validates a raw JWT string and returns the identity.
type TokenValidator interface {
	ValidateToken(token string) (*auth.Identity, error)
}

// wsClientMessage is the JSON shape clients send over the WebSocket.
type wsClientMessage struct {
	Type    string `json:"type"`
	Content string `json:"content"`
}

// wsServerMessage is the JSON shape the server sends to clients.
type wsServerMessage struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id,omitempty"`
	Content   string `json:"content,omitempty"`
	Done      bool   `json:"done,omitempty"`
	ToolName  string `json:"tool_name,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Message   string `json:"message,omitempty"`
}

// HandleWebSocket upgrades to a WebSocket connection for bidirectional
// agent messaging. Auth is performed via access_token query parameter
// since browsers cannot set headers on WebSocket upgrade.
func (h *Handler) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	agentID := r.PathValue("id")
	if agentID == "" {
		http.Error(w, `{"error":"missing agent id"}`, http.StatusBadRequest)
		return
	}

	// Auth via query parameter
	rawToken := r.URL.Query().Get("access_token")
	if rawToken == "" {
		http.Error(w, `{"error":"missing access_token"}`, http.StatusUnauthorized)
		return
	}

	identity, err := h.tokenValidator.ValidateToken(rawToken)
	if err != nil {
		if errors.Is(err, auth.ErrTokenExpired) {
			http.Error(w, `{"error":"token expired"}`, http.StatusUnauthorized)
		} else {
			http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
		}
		return
	}

	if identity.TokenType != "access" {
		http.Error(w, `{"error":"invalid token type"}`, http.StatusUnauthorized)
		return
	}

	// Look up agent and verify ownership
	inst, err := h.agents.GetByID(r.Context(), agentID)
	if err != nil {
		http.Error(w, `{"error":"agent not found"}`, http.StatusNotFound)
		return
	}

	if !identity.IsPlatformAdmin && inst.TenantID != nil && identity.TenantID != inst.TenantID.String() {
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		return
	}

	if inst.Status != "running" {
		http.Error(w, `{"error":"agent is not running"}`, http.StatusServiceUnavailable)
		return
	}

	if inst.VsockCID == nil {
		http.Error(w, `{"error":"agent has no vsock connection"}`, http.StatusServiceUnavailable)
		return
	}

	// Inject identity into context for downstream use
	ctx := auth.WithIdentity(r.Context(), identity)
	ctx = middleware.WithTenantID(ctx, identity.TenantID)

	// Upgrade to WebSocket
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: []string{"*"},
	})
	if err != nil {
		slog.Error("websocket upgrade failed", "error", err)
		return
	}
	defer conn.CloseNow()

	h.runWebSocketRelay(ctx, conn, inst, identity)
}

func (h *Handler) runWebSocketRelay(ctx context.Context, wsConn *websocket.Conn, inst *orchestrator.AgentInstance, identity *auth.Identity) {
	// Read loop: read client messages, forward to agent
	for {
		var msg wsClientMessage
		if err := wsjson.Read(ctx, wsConn, &msg); err != nil {
			// Client disconnected or context cancelled
			wsConn.Close(websocket.StatusNormalClosure, "")
			return
		}

		if msg.Type != "message" || msg.Content == "" {
			continue
		}

		// Sentinel scan
		if h.sentinel != nil {
			scanResult, scanErr := h.sentinel.Scan(ctx, SentinelInput{
				TenantID: identity.TenantID,
				UserID:   identity.UserID,
				Content:  msg.Content,
			})
			if scanErr != nil {
				wsjson.Write(ctx, wsConn, wsServerMessage{Type: "error", Message: "sentinel scan failed"})
				continue
			}
			if !scanResult.Allowed {
				wsjson.Write(ctx, wsConn, wsServerMessage{Type: "error", Message: "message blocked: " + scanResult.Reason})
				continue
			}
		}

		// Build frame
		requestID := uuid.New().String()
		agentTenantID := ""
		if inst.TenantID != nil {
			agentTenantID = inst.TenantID.String()
		}

		// Inject persisted user context
		body, _ := json.Marshal(map[string]any{
			"role":    "user",
			"content": msg.Content,
		})
		body = h.injectPersistedUserContext(ctx, body, agentTenantID, inst.ID.String())

		frame := Frame{
			Type:    TypeMessage,
			ID:      requestID,
			Payload: body,
		}

		// Send to agent
		agentConn, err := h.pool.Get(inst.ID.String(), *inst.VsockCID)
		if err != nil {
			wsjson.Write(ctx, wsConn, wsServerMessage{Type: "error", RequestID: requestID, Message: "failed to connect to agent"})
			continue
		}

		stream, err := agentConn.SendRequest(ctx, frame)
		if err != nil {
			wsjson.Write(ctx, wsConn, wsServerMessage{Type: "error", RequestID: requestID, Message: "failed to send message"})
			continue
		}

		// Audit log
		if h.audit != nil {
			uid := uuid.MustParse(identity.UserID)
			rid := inst.ID
			tid := uuid.Nil
			if inst.TenantID != nil {
				tid = *inst.TenantID
			}
			h.audit.Log(ctx, AuditEvent{
				TenantID:     tid,
				UserID:       &uid,
				Action:       "agent.message.ws",
				ResourceType: "agent",
				ResourceID:   &rid,
				Source:        "websocket",
			})
		}

		// Read response frames and forward to WS client
		h.relayAgentFrames(ctx, wsConn, stream, requestID, inst)
	}
}

func (h *Handler) relayAgentFrames(ctx context.Context, wsConn *websocket.Conn, stream *RequestStream, requestID string, inst *orchestrator.AgentInstance) {
	defer stream.Close()

	for {
		frame, err := stream.Recv(ctx)
		if err != nil {
			wsjson.Write(ctx, wsConn, wsServerMessage{Type: "error", RequestID: requestID, Message: "agent connection error"})
			return
		}

		switch frame.Type {
		case TypeChunk:
			var chunk struct {
				Content string `json:"content"`
				Done    bool   `json:"done"`
			}
			json.Unmarshal(frame.Payload, &chunk)
			wsjson.Write(ctx, wsConn, wsServerMessage{
				Type:      "chunk",
				RequestID: requestID,
				Content:   chunk.Content,
				Done:      chunk.Done,
			})
			if chunk.Done {
				return
			}

		case TypeError:
			var errPayload struct {
				Message string `json:"message"`
			}
			json.Unmarshal(frame.Payload, &errPayload)
			wsjson.Write(ctx, wsConn, wsServerMessage{
				Type:      "error",
				RequestID: requestID,
				Message:   errPayload.Message,
			})
			return

		case TypeToolExecuted:
			var tool struct {
				ToolName string `json:"tool_name"`
			}
			json.Unmarshal(frame.Payload, &tool)
			wsjson.Write(ctx, wsConn, wsServerMessage{
				Type:      "tool_executed",
				RequestID: requestID,
				ToolName:  tool.ToolName,
			})
			// Don't return — more frames may follow

		case TypeToolFailed:
			var tool struct {
				ToolName string `json:"tool_name"`
				Reason   string `json:"reason"`
			}
			json.Unmarshal(frame.Payload, &tool)
			wsjson.Write(ctx, wsConn, wsServerMessage{
				Type:      "tool_executed",
				RequestID: requestID,
				ToolName:  tool.ToolName,
				Reason:    tool.Reason,
			})

		case TypeToolBlocked:
			var blocked struct {
				ToolName string `json:"tool_name"`
				Reason   string `json:"reason"`
			}
			json.Unmarshal(frame.Payload, &blocked)
			wsjson.Write(ctx, wsConn, wsServerMessage{
				Type:      "tool_blocked",
				RequestID: requestID,
				ToolName:  blocked.ToolName,
				Reason:    blocked.Reason,
			})

		case TypeSessionHalt:
			var halt struct {
				Reason string `json:"reason"`
			}
			json.Unmarshal(frame.Payload, &halt)
			wsjson.Write(ctx, wsConn, wsServerMessage{
				Type:      "session_halt",
				RequestID: requestID,
				Reason:    halt.Reason,
			})
			// Session halt — close WS
			wsConn.Close(websocket.StatusPolicyViolation, halt.Reason)
			return
		}
	}
}
```

Note: You need to add `tokenValidator TokenValidator` to the `Handler` struct and add `import "context"` plus the `orchestrator` import. Also need to add `middleware.WithTenantID` — check if it exists, if not add a simple context setter (same pattern as `middleware.GetTenantID` but for setting).

**Step 4: Run test to verify it passes**

Run: `go test ./internal/proxy/ -run TestHandleWebSocket -v`
Expected: 3 tests PASS

**Step 5: Commit**

```bash
git add internal/proxy/ws_handler.go internal/proxy/ws_handler_test.go
git commit -m "feat(proxy): add WebSocket handler with auth validation"
```

---

### Task 3: Wire WebSocket handler into server + main

**Files:**
- Modify: `internal/platform/server/server.go` — add WS route
- Modify: `cmd/valinor/main.go` — pass TokenService to proxy handler
- Modify: `internal/proxy/handler.go` — add `WithTokenValidator` method

**Step 1: Add `WithTokenValidator` to Handler**

In `internal/proxy/handler.go`, add to the `Handler` struct:

```go
tokenValidator TokenValidator
```

Add builder method:

```go
func (h *Handler) WithTokenValidator(tv TokenValidator) *Handler {
	h.tokenValidator = tv
	return h
}
```

**Step 2: Register the route in server.go**

Add alongside the other proxy routes:

```go
protectedMux.Handle("GET /api/v1/agents/{id}/ws", rbac("agents:message")(http.HandlerFunc(deps.ProxyHandler.HandleWebSocket)))
```

Note: The WS handler does its own auth from the query param, but the middleware chain still runs (it will see no Bearer header in dev mode with `MiddlewareWithDevMode` — this needs to be handled). Two options:

**Option A (recommended):** Register the WS route on `topMux` (public routes) and let the handler do all auth itself. This avoids the middleware chain trying to parse a non-existent Authorization header.

```go
topMux.HandleFunc("GET /api/v1/agents/{id}/ws", deps.ProxyHandler.HandleWebSocket)
```

The handler already validates the JWT, checks tenant ownership, and checks RBAC internally. This is the same pattern as the webhook ingress routes.

**Step 3: Pass TokenService in main.go**

After building `proxyHandler`, chain:

```go
proxyHandler = proxy.NewHandler(...).WithUserContextStore(userContextStore).WithTokenValidator(tokenSvc)
```

**Step 4: Verify**

Run: `go build ./cmd/valinor`
Expected: Clean build

Run: `go test ./internal/proxy/ -v`
Expected: All tests pass

**Step 5: Commit**

```bash
git add internal/proxy/handler.go internal/platform/server/server.go cmd/valinor/main.go
git commit -m "feat(proxy): wire WebSocket handler into server routes"
```

---

### Task 4: Add `middleware.WithTenantID` helper

**Files:**
- Modify: `internal/platform/middleware/tenant.go` (or wherever `GetTenantID` is)

**Step 1: Check if `WithTenantID` exists**

Run: `grep -rn "WithTenantID" internal/platform/middleware/`

If it exists, skip this task. If not:

**Step 2: Add the setter**

```go
func WithTenantID(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantIDKey{}, tenantID)
}
```

This uses the same `tenantIDKey{}` that `GetTenantID` reads from.

**Step 3: Verify**

Run: `go build ./...`
Expected: Clean build

**Step 4: Commit**

```bash
git add internal/platform/middleware/
git commit -m "feat(middleware): add WithTenantID context setter"
```

---

### Task 5: RBAC check inside WS handler

**Files:**
- Modify: `internal/proxy/ws_handler.go`
- Modify: `internal/proxy/ws_handler_test.go`

**Step 1: Write the failing test**

```go
func TestHandleWebSocket_RejectsInsufficientRBAC(t *testing.T) {
	h := &Handler{}
	h.tokenValidator = &mockTokenService{identity: &auth.Identity{
		UserID:    "u-1",
		TenantID:  "t-1",
		TokenType: "access",
		Roles:     []string{"read_only"},
	}}
	h.agents = &mockAgentLookup{agent: &orchestrator.AgentInstance{
		ID:       uuid.MustParse("00000000-0000-0000-0000-000000000001"),
		TenantID: uuidPtr(uuid.MustParse("00000000-0000-0000-0000-000000000002")),
		Status:   "running",
		VsockCID: uint32Ptr(100),
	}}
	// read_only role has no "agents:message" permission

	req := httptest.NewRequest("GET", "/api/v1/agents/00000000-0000-0000-0000-000000000001/ws?access_token=valid", nil)
	req.SetPathValue("id", "00000000-0000-0000-0000-000000000001")
	rec := httptest.NewRecorder()

	h.HandleWebSocket(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}
```

You'll need `mockAgentLookup` and helper functions — add them to the test file.

**Step 2: Implement RBAC check**

Add to `HandleWebSocket`, after identity validation and before agent lookup:

```go
// Check RBAC — agents:message required
if !identity.IsPlatformAdmin {
	hasPermission := false
	for _, role := range identity.Roles {
		if role == "org_admin" || role == "dept_head" || role == "standard_user" {
			hasPermission = true
			break
		}
	}
	if !hasPermission {
		http.Error(w, `{"error":"insufficient permissions"}`, http.StatusForbidden)
		return
	}
}
```

Note: This is a simplified RBAC check that mirrors the server-side RBAC but runs inline. The real `rbac.Evaluator` is not available inside the handler (it's middleware). Since we registered the WS route on `topMux`, we need this inline check. The roles that have `agents:message` are: `org_admin` (wildcard), `dept_head`, `standard_user`. `read_only` does not.

Actually — look at `server.go`. The existing proxy routes use `rbac("agents:write")` not `agents:message`. Check permissions.ts too — `standard_user` has `agents:message` but the HTTP routes require `agents:write`. The WS handler should use the same permission the HTTP message/stream handlers use. Verify and match.

**Step 3: Run tests**

Run: `go test ./internal/proxy/ -run TestHandleWebSocket -v`
Expected: All pass including the new RBAC test

**Step 4: Commit**

```bash
git add internal/proxy/ws_handler.go internal/proxy/ws_handler_test.go
git commit -m "feat(proxy): add RBAC check to WebSocket handler"
```

---

### Task 6: Dashboard — add ChatMessage types

**Files:**
- Modify: `dashboard/src/lib/types.ts`

**Step 1: Add the types**

```ts
// WebSocket chat types for agent debug console
export interface ChatMessage {
  id: string
  type: "user" | "assistant" | "tool" | "error" | "halt"
  content: string
  toolName?: string
  reason?: string
  requestId?: string
  timestamp: number
  streaming?: boolean
}

export interface WsServerMessage {
  type: "chunk" | "tool_executed" | "tool_blocked" | "error" | "session_halt"
  request_id?: string
  content?: string
  done?: boolean
  tool_name?: string
  reason?: string
  message?: string
}
```

**Step 2: Verify**

Run: `cd dashboard && npx tsc --noEmit`
Expected: No errors

**Step 3: Commit**

```bash
git add dashboard/src/lib/types.ts
git commit -m "feat(dashboard): add ChatMessage and WsServerMessage types"
```

---

### Task 7: Dashboard — `useAgentWebSocket` hook

**Files:**
- Create: `dashboard/src/hooks/use-agent-websocket.ts`
- Create: `dashboard/src/hooks/use-agent-websocket.test.ts`

**Step 1: Write the hook**

```ts
"use client"

import { useState, useEffect, useRef, useCallback } from "react"
import { useSession } from "next-auth/react"
import type { ChatMessage, WsServerMessage } from "@/lib/types"

type WsStatus = "connecting" | "connected" | "disconnected" | "error"

const WS_BASE_URL = (process.env.NEXT_PUBLIC_VALINOR_API_URL ?? "http://localhost:8080")
  .replace(/^http/, "ws")

const MAX_RECONNECT_ATTEMPTS = 3
const RECONNECT_BASE_DELAY = 1000

export function useAgentWebSocket(agentId: string, enabled: boolean) {
  const { data: session } = useSession()
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [status, setStatus] = useState<WsStatus>("disconnected")
  const [error, setError] = useState<string | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectAttempts = useRef(0)
  const reconnectTimer = useRef<ReturnType<typeof setTimeout>>()

  const connect = useCallback(() => {
    if (!session?.accessToken || !enabled) return

    const url = `${WS_BASE_URL}/api/v1/agents/${agentId}/ws?access_token=${session.accessToken}`
    const ws = new WebSocket(url)
    wsRef.current = ws
    setStatus("connecting")
    setError(null)

    ws.onopen = () => {
      setStatus("connected")
      reconnectAttempts.current = 0
    }

    ws.onmessage = (event) => {
      const msg: WsServerMessage = JSON.parse(event.data)
      setMessages((prev) => {
        switch (msg.type) {
          case "chunk": {
            if (msg.done) {
              // Mark the streaming message as done
              return prev.map((m) =>
                m.requestId === msg.request_id && m.type === "assistant"
                  ? { ...m, content: m.content + (msg.content ?? ""), streaming: false }
                  : m,
              )
            }
            // Append to existing streaming message or create new one
            const existing = prev.find(
              (m) => m.requestId === msg.request_id && m.type === "assistant" && m.streaming,
            )
            if (existing) {
              return prev.map((m) =>
                m === existing ? { ...m, content: m.content + (msg.content ?? "") } : m,
              )
            }
            return [
              ...prev,
              {
                id: crypto.randomUUID(),
                type: "assistant",
                content: msg.content ?? "",
                requestId: msg.request_id,
                timestamp: Date.now(),
                streaming: true,
              },
            ]
          }

          case "tool_executed":
            return [
              ...prev,
              {
                id: crypto.randomUUID(),
                type: "tool",
                content: `Called \`${msg.tool_name}\``,
                toolName: msg.tool_name,
                requestId: msg.request_id,
                timestamp: Date.now(),
              },
            ]

          case "tool_blocked":
            return [
              ...prev,
              {
                id: crypto.randomUUID(),
                type: "tool",
                content: `Tool \`${msg.tool_name}\` blocked: ${msg.reason}`,
                toolName: msg.tool_name,
                reason: msg.reason,
                requestId: msg.request_id,
                timestamp: Date.now(),
              },
            ]

          case "error":
            return [
              ...prev,
              {
                id: crypto.randomUUID(),
                type: "error",
                content: msg.message ?? "Unknown error",
                requestId: msg.request_id,
                timestamp: Date.now(),
              },
            ]

          case "session_halt":
            return [
              ...prev,
              {
                id: crypto.randomUUID(),
                type: "halt",
                content: `Session halted: ${msg.reason}`,
                reason: msg.reason,
                requestId: msg.request_id,
                timestamp: Date.now(),
              },
            ]

          default:
            return prev
        }
      })
    }

    ws.onerror = () => {
      setError("WebSocket connection error")
      setStatus("error")
    }

    ws.onclose = (event) => {
      wsRef.current = null
      if (event.code === 1000 || event.code === 1001) {
        setStatus("disconnected")
        return
      }
      // Unexpected close — attempt reconnect
      if (reconnectAttempts.current < MAX_RECONNECT_ATTEMPTS) {
        const delay = RECONNECT_BASE_DELAY * Math.pow(2, reconnectAttempts.current)
        reconnectAttempts.current++
        setStatus("connecting")
        reconnectTimer.current = setTimeout(connect, delay)
      } else {
        setStatus("error")
        setError("Connection lost. Refresh to retry.")
      }
    }
  }, [agentId, enabled, session?.accessToken])

  useEffect(() => {
    connect()
    return () => {
      clearTimeout(reconnectTimer.current)
      wsRef.current?.close(1000, "component unmounted")
      wsRef.current = null
    }
  }, [connect])

  const sendMessage = useCallback(
    (content: string) => {
      if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) return
      setMessages((prev) => [
        ...prev,
        {
          id: crypto.randomUUID(),
          type: "user",
          content,
          timestamp: Date.now(),
        },
      ])
      wsRef.current.send(JSON.stringify({ type: "message", content }))
    },
    [],
  )

  return { messages, sendMessage, status, error }
}
```

**Step 2: Write a basic test**

```ts
// dashboard/src/hooks/use-agent-websocket.test.ts
import { describe, it, expect } from "vitest"

describe("useAgentWebSocket", () => {
  it("exports the hook", async () => {
    const mod = await import("./use-agent-websocket")
    expect(typeof mod.useAgentWebSocket).toBe("function")
  })
})
```

**Step 3: Verify**

Run: `cd dashboard && npx tsc --noEmit && npx vitest run src/hooks/use-agent-websocket.test.ts`
Expected: Types clean, test passes

**Step 4: Commit**

```bash
git add dashboard/src/hooks/use-agent-websocket.ts dashboard/src/hooks/use-agent-websocket.test.ts
git commit -m "feat(dashboard): add useAgentWebSocket hook"
```

---

### Task 8: Dashboard — `AgentChat` component

**Files:**
- Create: `dashboard/src/components/agents/agent-chat.tsx`

**Step 1: Write the component**

```tsx
"use client"

import { useState, useRef, useEffect } from "react"
import { useAgentWebSocket } from "@/hooks/use-agent-websocket"
import { PaperPlaneRight, CircleNotch, Wrench, Warning, ShieldWarning } from "@phosphor-icons/react"
import type { ChatMessage } from "@/lib/types"

function StatusDot({ status }: { status: string }) {
  const color =
    status === "connected"
      ? "bg-emerald-500"
      : status === "connecting"
        ? "bg-amber-500 animate-pulse"
        : "bg-zinc-300"
  return <span className={`inline-block h-2 w-2 rounded-full ${color}`} />
}

function MessageBubble({ msg }: { msg: ChatMessage }) {
  if (msg.type === "user") {
    return (
      <div className="flex justify-end">
        <div className="max-w-[75%] rounded-xl rounded-br-sm bg-zinc-900 px-3 py-2 text-sm text-white">
          {msg.content}
        </div>
      </div>
    )
  }

  if (msg.type === "assistant") {
    return (
      <div className="flex justify-start">
        <div className="max-w-[75%] rounded-xl rounded-bl-sm bg-zinc-100 px-3 py-2 text-sm text-zinc-900">
          {msg.content}
          {msg.streaming && (
            <span className="ml-1 inline-block h-3 w-1 animate-pulse bg-zinc-400 rounded-full" />
          )}
        </div>
      </div>
    )
  }

  if (msg.type === "tool") {
    return (
      <div className="flex justify-center">
        <div className="flex items-center gap-1.5 rounded-full bg-zinc-50 border border-zinc-200 px-3 py-1 text-xs text-zinc-500">
          <Wrench size={12} />
          {msg.content}
        </div>
      </div>
    )
  }

  if (msg.type === "error") {
    return (
      <div className="flex justify-center">
        <div className="flex items-center gap-1.5 rounded-lg bg-rose-50 border border-rose-200 px-3 py-1.5 text-xs text-rose-600">
          <Warning size={12} />
          {msg.content}
        </div>
      </div>
    )
  }

  if (msg.type === "halt") {
    return (
      <div className="flex justify-center">
        <div className="flex items-center gap-1.5 rounded-lg bg-amber-50 border border-amber-200 px-3 py-1.5 text-xs text-amber-700">
          <ShieldWarning size={12} />
          {msg.content}
        </div>
      </div>
    )
  }

  return null
}

export function AgentChat({ agentId, agentStatus }: { agentId: string; agentStatus: string }) {
  const enabled = agentStatus === "running"
  const { messages, sendMessage, status, error } = useAgentWebSocket(agentId, enabled)
  const [input, setInput] = useState("")
  const scrollRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" })
  }, [messages])

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    const trimmed = input.trim()
    if (!trimmed) return
    sendMessage(trimmed)
    setInput("")
  }

  if (!enabled) {
    return (
      <div className="rounded-xl border border-zinc-200 bg-zinc-50 p-6 text-center">
        <p className="text-sm text-zinc-500">Agent must be running to use the debug console.</p>
      </div>
    )
  }

  return (
    <div className="flex flex-col rounded-xl border border-zinc-200 bg-white" style={{ height: "480px" }}>
      {/* Header */}
      <div className="flex items-center justify-between border-b border-zinc-100 px-4 py-2">
        <h3 className="text-sm font-medium text-zinc-900">Debug Console</h3>
        <div className="flex items-center gap-2 text-xs text-zinc-500">
          <StatusDot status={status} />
          {status === "connecting" ? "Connecting..." : status === "connected" ? "Connected" : "Disconnected"}
        </div>
      </div>

      {/* Messages */}
      <div ref={scrollRef} className="flex-1 overflow-y-auto p-4 space-y-3">
        {messages.length === 0 && status === "connected" && (
          <p className="text-center text-sm text-zinc-400 pt-8">Send a message to test this agent.</p>
        )}
        {messages.map((msg) => (
          <MessageBubble key={msg.id} msg={msg} />
        ))}
      </div>

      {/* Error bar */}
      {error && (
        <div className="border-t border-rose-100 bg-rose-50 px-4 py-2 text-xs text-rose-600">{error}</div>
      )}

      {/* Input */}
      <form onSubmit={handleSubmit} className="flex items-center gap-2 border-t border-zinc-100 p-3">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          disabled={status !== "connected"}
          placeholder={status === "connected" ? "Type a message..." : "Connecting..."}
          className="flex-1 rounded-lg border border-zinc-200 px-3 py-2 text-sm text-zinc-900 placeholder:text-zinc-400 disabled:opacity-50"
        />
        <button
          type="submit"
          disabled={status !== "connected" || !input.trim()}
          className="rounded-lg bg-zinc-900 p-2 text-white hover:bg-zinc-800 transition-colors active:scale-[0.98] disabled:opacity-50"
        >
          {status === "connecting" ? (
            <CircleNotch size={16} className="animate-spin" />
          ) : (
            <PaperPlaneRight size={16} />
          )}
        </button>
      </form>
    </div>
  )
}
```

**Step 2: Verify**

Run: `cd dashboard && npx tsc --noEmit`
Expected: No errors

**Step 3: Commit**

```bash
git add dashboard/src/components/agents/agent-chat.tsx
git commit -m "feat(dashboard): add AgentChat debug console component"
```

---

### Task 9: Integrate AgentChat into agent detail page

**Files:**
- Modify: `dashboard/src/components/agents/agent-detail.tsx`

**Step 1: Add import and render**

Add import at the top:

```tsx
import { AgentChat } from "./agent-chat"
```

Add the chat component at the end of the return JSX, after the tool allowlist section (before the closing `</div>` of the outer div, after `</>` that closes the config/tools conditional):

```tsx
      {/* Debug Console */}
      <div>
        <h2 className="mb-3 text-sm font-medium text-zinc-900">Debug Console</h2>
        <AgentChat agentId={id} agentStatus={agent.status} />
      </div>
```

**Step 2: Verify**

Run: `cd dashboard && npx tsc --noEmit`
Expected: No errors

**Step 3: Commit**

```bash
git add dashboard/src/components/agents/agent-detail.tsx
git commit -m "feat(dashboard): integrate debug console into agent detail page"
```

---

### Task 10: Add audit label for WS messages

**Files:**
- Modify: `dashboard/src/components/audit/audit-labels.ts`

**Step 1: Add the label**

Add to `ACTION_LABELS` in the agent events section:

```ts
  "agent.message.ws": { label: "Agent Message (WS)", category: "agent" },
```

Add `"websocket"` to `SOURCES`:

```ts
  { value: "websocket", label: "WebSocket" },
```

And to `SOURCE_LABELS`:

```ts
  websocket: "WebSocket",
```

**Step 2: Verify**

Run: `cd dashboard && npx tsc --noEmit`
Expected: No errors

**Step 3: Commit**

```bash
git add dashboard/src/components/audit/audit-labels.ts
git commit -m "feat(dashboard): add WebSocket audit event labels"
```

---

### Task 11: End-to-end verification

**Step 1: Build backend**

Run: `go build ./cmd/valinor`
Expected: Clean build

**Step 2: Run Go tests**

Run: `go test ./internal/proxy/ -v`
Expected: All tests pass

**Step 3: Run dashboard tests**

Run: `cd dashboard && npx vitest run`
Expected: All tests pass

**Step 4: Manual E2E test**

1. Start backend: `go run ./cmd/valinor`
2. Start dashboard: `cd dashboard && npm run dev`
3. Login as `turgon@gondolin.fc` (org_admin)
4. Provision an agent at `/agents/new`
5. Configure the agent at `/agents/[id]`
6. Navigate to `/agents/[id]` — verify "Debug Console" section appears
7. If agent status is `running`: verify WS connects (green dot, "Connected")
8. Type a message and send — verify streaming response appears
9. If agent is not running: verify "Agent must be running" disabled state
10. Login as `maeglin@gondolin.fc` (read_only) — verify chat is not interactive (no `agents:message` permission)
11. Check `/audit` — verify `agent.message.ws` events appear with "WebSocket" source

**Step 5: Commit any fixes**

```bash
git add -A
git commit -m "fix: address issues found in debug console E2E verification"
```
