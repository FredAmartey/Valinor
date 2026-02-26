# MCP Tool Call Integration — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Wire end-to-end tool execution: connector injection at provision/config → MCP JSON-RPC 2.0 client in agent → agentic tool loop with OpenClaw → audit events for tool calls.

**Architecture:** Extend config push payload to include connectors from the DB. Add an MCP client in the valinor-agent that implements `tools/call` over JSON-RPC 2.0. Modify the OpenClaw handler to loop: execute allowed tool calls via MCP, feed results back to OpenClaw, repeat until final text response.

**Tech Stack:** Go 1.25, net/http, JSON-RPC 2.0, pgx/v5

**Design doc:** `docs/plans/2026-02-26-mcp-tool-call-integration-design.md`

**Run all commands from:** repo root directory

---

### Task 1: Add Audit Constants for Tool Execution

**Files:**
- Modify: `internal/audit/audit.go`

**Step 1: Add constants after the existing CRUD action block**

```go
ActionToolExecuted = "tool.executed"
ActionToolFailed   = "tool.failed"
```

Add these to the CRUD actions `const` block in `internal/audit/audit.go`.

**Step 2: Verify**

Run: `go build ./internal/audit/...`
Expected: success

**Step 3: Commit**

```bash
git add internal/audit/audit.go
git commit -m "feat(audit): add tool.executed and tool.failed action constants"
```

---

### Task 2: Add Tool Execution Frame Types to Protocol

**Files:**
- Modify: `internal/proxy/protocol.go`

**Step 1: Add new frame types for tool execution events**

Add to the Agent → Control Plane constants block (after `TypeError`):

```go
TypeToolExecuted = "tool_executed"
TypeToolFailed   = "tool_failed"
```

These are informational frames the agent sends to the control plane for audit logging (fire-and-forget, no ack needed).

**Step 2: Verify**

Run: `go build ./internal/proxy/...`
Expected: success

**Step 3: Commit**

```bash
git add internal/proxy/protocol.go
git commit -m "feat(proxy): add tool_executed and tool_failed frame types"
```

---

### Task 3: Extend Config Push to Include Connectors

**Files:**
- Modify: `internal/proxy/push.go`
- Modify: `internal/orchestrator/handler.go`
- Modify: `cmd/valinor/main.go`

**Step 1: Add connectors parameter to PushConfig**

In `internal/proxy/push.go`, add `connectors []map[string]any` parameter to `PushConfig` function signature and include it in the payload struct:

Change the function signature from:
```go
func PushConfig(ctx context.Context, pool *ConnPool, agentID string, cid uint32,
	config map[string]any, toolAllowlist []string,
	toolPolicies map[string]any, canaryTokens []string,
	timeout time.Duration) error {
```
To:
```go
func PushConfig(ctx context.Context, pool *ConnPool, agentID string, cid uint32,
	config map[string]any, toolAllowlist []string,
	toolPolicies map[string]any, canaryTokens []string,
	connectors []map[string]any,
	timeout time.Duration) error {
```

Add `Connectors` field to the payload struct:
```go
payload := struct {
    Config        map[string]any   `json:"config"`
    ToolAllowlist []string         `json:"tool_allowlist"`
    ToolPolicies  map[string]any   `json:"tool_policies,omitempty"`
    CanaryTokens  []string         `json:"canary_tokens,omitempty"`
    Connectors    []map[string]any `json:"connectors,omitempty"`
}{
    Config:        config,
    ToolAllowlist: toolAllowlist,
    ToolPolicies:  toolPolicies,
    CanaryTokens:  canaryTokens,
    Connectors:    connectors,
}
```

**Step 2: Update ConfigPusher interface in orchestrator**

In `internal/orchestrator/handler.go`, the `ConfigPusher` interface (line 17-19) needs the connectors parameter:

```go
type ConfigPusher interface {
    PushConfig(ctx context.Context, agentID string, cid uint32, config map[string]any, toolAllowlist []string, toolPolicies map[string]any, canaryTokens []string, connectors []map[string]any) error
}
```

**Step 3: Update the configPusherAdapter in main.go**

In `cmd/valinor/main.go`, the `configPusherAdapter` struct's `PushConfig` method needs to accept and pass through the connectors parameter:

```go
func (a *configPusherAdapter) PushConfig(ctx context.Context, agentID string, cid uint32, config map[string]any, toolAllowlist []string, toolPolicies map[string]any, canaryTokens []string, connectors []map[string]any) error {
    return proxy.PushConfig(ctx, a.pool, agentID, cid, config, toolAllowlist, toolPolicies, canaryTokens, connectors, a.timeout)
}
```

**Step 4: Update HandleConfigure to load and pass connectors**

In `internal/orchestrator/handler.go`, add a `connectorStore` field to Handler (alongside `manager`, `configPusher`, `auditLog`):

Add to Handler struct:
```go
type Handler struct {
    manager        *Manager
    configPusher   ConfigPusher
    auditLog       audit.Logger
    connectorStore ConnectorLister
}
```

Define the interface:
```go
// ConnectorLister loads active connectors for agent config injection.
type ConnectorLister interface {
    ListForAgent(ctx context.Context, q database.Querier) ([]connectors.AgentConnectorConfig, error)
}
```

Update `NewHandler`:
```go
func NewHandler(manager *Manager, pusher ConfigPusher, auditLog audit.Logger, connectorLister ConnectorLister) *Handler {
    return &Handler{manager: manager, configPusher: pusher, auditLog: auditLog, connectorStore: connectorLister}
}
```

In `HandleConfigure`, after the config push line (currently passes `nil, nil` for toolPolicies and canaryTokens), load connectors and pass them:

```go
// Load active connectors for this tenant
var agentConnectors []map[string]any
if h.connectorStore != nil && pool != nil {
    tenantID := middleware.GetTenantID(r.Context())
    _ = database.WithTenantConnection(r.Context(), pool, tenantID, func(ctx context.Context, q database.Querier) error {
        configs, listErr := h.connectorStore.ListForAgent(ctx, q)
        if listErr != nil {
            slog.Warn("failed to load connectors for agent", "error", listErr)
            return nil
        }
        for _, c := range configs {
            agentConnectors = append(agentConnectors, map[string]any{
                "name":     c.Name,
                "type":     c.Type,
                "endpoint": c.Endpoint,
                "auth":     c.Auth,
                "tools":    c.Tools,
            })
        }
        return nil
    })
}

if h.configPusher != nil && inst.Status == StatusRunning && inst.VsockCID != nil {
    if pushErr := h.configPusher.PushConfig(r.Context(), id, *inst.VsockCID, req.Config, req.ToolAllowlist, nil, nil, agentConnectors); pushErr != nil {
        slog.Warn("config push to agent failed", "id", id, "error", pushErr)
    }
}
```

Note: The handler needs access to the DB pool for `WithTenantConnection`. Add it as a field or pass via DI. Check how existing handlers handle this (DepartmentHandler has `pool *pgxpool.Pool`).

**Step 5: Wire connector store in main.go**

In `cmd/valinor/main.go`, update the orchestrator handler construction:

```go
agentHandler = orchestrator.NewHandler(orchManager, pusher, auditLogger, connectors.NewStore())
```

Also pass the pool to the handler (add pool field if needed).

**Step 6: Verify**

Run: `go build ./...`
Expected: success (may require fixing call sites that pass old parameter count)

**Step 7: Commit**

```bash
git add internal/proxy/push.go internal/orchestrator/handler.go cmd/valinor/main.go
git commit -m "feat(orchestrator): inject connectors into agent config push"
```

---

### Task 4: Agent Parses Connectors from Config Update

**Files:**
- Modify: `cmd/valinor-agent/agent.go`

**Step 1: Add connectors field to Agent struct**

Add to the Agent struct:
```go
type AgentConnector struct {
    Name     string          `json:"name"`
    Type     string          `json:"type"`
    Endpoint string          `json:"endpoint"`
    Auth     json.RawMessage `json:"auth"`
    Tools    []string        `json:"tools"`
}
```

Add `connectors []AgentConnector` field to Agent struct (protected by existing `mu`).

**Step 2: Parse connectors in handleConfigUpdate**

Extend the config payload struct:
```go
var payload struct {
    Config        map[string]any        `json:"config"`
    ToolAllowlist []string              `json:"tool_allowlist"`
    ToolPolicies  map[string]ToolPolicy `json:"tool_policies"`
    CanaryTokens  []string              `json:"canary_tokens"`
    Connectors    []AgentConnector      `json:"connectors"`
}
```

After lock, store connectors:
```go
a.connectors = payload.Connectors
```

Update log line:
```go
slog.Info("config updated", "tools", len(payload.ToolAllowlist), "connectors", len(payload.Connectors))
```

**Step 3: Verify**

Run: `go build ./cmd/valinor-agent/...`
Expected: success

**Step 4: Commit**

```bash
git add cmd/valinor-agent/agent.go
git commit -m "feat(agent): parse and store connectors from config update"
```

---

### Task 5: MCP JSON-RPC Client

**Files:**
- Create: `cmd/valinor-agent/mcp.go`
- Create: `cmd/valinor-agent/mcp_test.go`

**Step 1: Write the failing test**

Create `cmd/valinor-agent/mcp_test.go`:

```go
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMCPClient_CallTool(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "Bearer test-key", r.Header.Get("Authorization"))

		var req jsonRPCRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		assert.Equal(t, "2.0", req.JSONRPC)
		assert.Equal(t, "tools/call", req.Method)

		var params toolCallParams
		require.NoError(t, json.Unmarshal(req.Params, &params))
		assert.Equal(t, "search_players", params.Name)

		resp := jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: &toolCallResult{
				Content: []contentBlock{{Type: "text", Text: `{"players":["messi"]}`}},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := newMCPClient(&http.Client{})
	connector := AgentConnector{
		Name:     "test-api",
		Endpoint: server.URL,
		Auth:     json.RawMessage(`{"api_key":"test-key"}`),
		Tools:    []string{"search_players"},
	}

	result, err := client.callTool(context.Background(), connector, "search_players", `{"league":"Serie A"}`)
	require.NoError(t, err)
	assert.Contains(t, result, "messi")
}

func TestMCPClient_CallTool_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      "1",
			Error:   &jsonRPCError{Code: -32601, Message: "method not found"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := newMCPClient(&http.Client{})
	connector := AgentConnector{
		Name:     "test-api",
		Endpoint: server.URL,
		Auth:     json.RawMessage(`{}`),
		Tools:    []string{"bad_tool"},
	}

	_, err := client.callTool(context.Background(), connector, "bad_tool", `{}`)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "method not found")
}

func TestResolveConnector(t *testing.T) {
	connectors := []AgentConnector{
		{Name: "api-a", Tools: []string{"tool_1", "tool_2"}},
		{Name: "api-b", Tools: []string{"tool_3"}},
	}

	c, err := resolveConnector(connectors, "tool_3")
	require.NoError(t, err)
	assert.Equal(t, "api-b", c.Name)

	_, err = resolveConnector(connectors, "unknown")
	assert.Error(t, err)
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./cmd/valinor-agent/ -run TestMCPClient -v`
Expected: FAIL — types and functions not defined

**Step 3: Implement the MCP client**

Create `cmd/valinor-agent/mcp.go`:

```go
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/google/uuid"
)

// JSON-RPC 2.0 types for MCP tools/call

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      string          `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      string          `json:"id"`
	Result  *toolCallResult `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type toolCallResult struct {
	Content []contentBlock `json:"content"`
}

type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// mcpClient executes MCP tool calls over HTTP JSON-RPC 2.0.
type mcpClient struct {
	httpClient *http.Client
}

func newMCPClient(httpClient *http.Client) *mcpClient {
	return &mcpClient{httpClient: httpClient}
}

// callTool executes a tools/call JSON-RPC request against a connector's endpoint.
func (c *mcpClient) callTool(ctx context.Context, connector AgentConnector, toolName string, arguments string) (string, error) {
	params, err := json.Marshal(toolCallParams{
		Name:      toolName,
		Arguments: json.RawMessage(arguments),
	})
	if err != nil {
		return "", fmt.Errorf("marshaling tool call params: %w", err)
	}

	rpcReq := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      uuid.New().String(),
		Method:  "tools/call",
		Params:  params,
	}

	body, err := json.Marshal(rpcReq)
	if err != nil {
		return "", fmt.Errorf("marshaling JSON-RPC request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", connector.Endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("creating HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	// Apply auth from connector config
	var authConfig struct {
		APIKey string `json:"api_key"`
	}
	if len(connector.Auth) > 0 {
		_ = json.Unmarshal(connector.Auth, &authConfig)
	}
	if authConfig.APIKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+authConfig.APIKey)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("MCP request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", fmt.Errorf("reading MCP response: %w", err)
	}

	var rpcResp jsonRPCResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return "", fmt.Errorf("parsing MCP JSON-RPC response: %w", err)
	}

	if rpcResp.Error != nil {
		return "", fmt.Errorf("MCP error %d: %s", rpcResp.Error.Code, rpcResp.Error.Message)
	}

	if rpcResp.Result == nil {
		return "", fmt.Errorf("MCP response has no result")
	}

	// Extract text from content blocks
	var result string
	for _, block := range rpcResp.Result.Content {
		if block.Type == "text" {
			result += block.Text
		}
	}
	return result, nil
}

// resolveConnector finds which connector owns a given tool name.
func resolveConnector(connectors []AgentConnector, toolName string) (AgentConnector, error) {
	for _, c := range connectors {
		for _, t := range c.Tools {
			if t == toolName {
				return c, nil
			}
		}
	}
	return AgentConnector{}, fmt.Errorf("no connector registered for tool %q", toolName)
}
```

**Step 4: Run tests**

Run: `go test ./cmd/valinor-agent/ -run "TestMCPClient|TestResolveConnector" -v`
Expected: PASS (3 tests)

**Step 5: Commit**

```bash
git add cmd/valinor-agent/mcp.go cmd/valinor-agent/mcp_test.go
git commit -m "feat(agent): add MCP JSON-RPC 2.0 client with connector resolver"
```

---

### Task 6: Implement Agentic Tool Execution Loop

**Files:**
- Modify: `cmd/valinor-agent/openclaw.go`

This is the core change. After OpenClaw returns tool_calls and validation passes, execute each tool via MCP, build the result messages, and call OpenClaw again. Loop until no more tool calls or max iterations.

**Step 1: Add mcpClient field to Agent and initialize in NewAgent**

In `agent.go`, add to Agent struct: `mcp *mcpClient`

In `NewAgent`:
```go
return &Agent{
    cfg:        cfg,
    httpClient: &http.Client{Timeout: 30 * time.Second},
    mcp:        newMCPClient(&http.Client{Timeout: 30 * time.Second}),
}
```

**Step 2: Refactor forwardToOpenClaw into an agentic loop**

Replace the existing `forwardToOpenClaw` function. The key changes:

1. Build initial messages array from the frame payload
2. Call OpenClaw
3. If response has tool_calls:
   a. Validate each (existing)
   b. Execute each via `a.mcp.callTool()`
   c. Append assistant message (with tool_calls) + tool result messages
   d. Call OpenClaw again with full conversation
   e. Repeat (max 10 iterations)
4. If response is text only: send as TypeChunk done=true
5. Check canary tokens on every response

The `openClawResponse` struct needs to be extended to include `tool_call_id` and the full structure needed for the loop.

Key code structure:
```go
const maxToolIterations = 10

func (a *Agent) forwardToOpenClaw(ctx context.Context, conn *proxy.AgentConn, frame proxy.Frame) {
    // ... URL validation, parse initial messages (existing) ...

    for iteration := 0; iteration < maxToolIterations; iteration++ {
        // Call OpenClaw with current messages
        ocResp, err := a.callOpenClaw(ctx, messages)
        if err != nil {
            a.sendError(ctx, conn, frame.ID, "openclaw_error", err.Error())
            return
        }

        choice := ocResp.Choices[0]

        // Check canary tokens
        if found, token := a.checkCanary(choice.Message.Content); found {
            // ... send TypeSessionHalt (existing) ...
            return
        }

        // No tool calls → final response
        if len(choice.Message.ToolCalls) == 0 {
            // Send done chunk (existing)
            return
        }

        // Validate and execute tool calls
        // Append assistant message with tool_calls to messages
        // For each tool call:
        //   validate → if blocked: send TypeToolBlocked, return
        //   execute via MCP → if error: send tool error, continue or return
        //   append tool result message
        //   emit TypeToolExecuted or TypeToolFailed frame (audit)
        // Loop continues with updated messages
    }

    a.sendError(ctx, conn, frame.ID, "max_iterations", "tool call loop exceeded maximum iterations")
}
```

**Step 3: Extract callOpenClaw helper**

Factor the HTTP call to OpenClaw into a reusable method:
```go
func (a *Agent) callOpenClaw(ctx context.Context, messages []any) (*openClawResponse, error) {
    // Build request body, POST to OpenClaw, parse response
}
```

**Step 4: Emit audit frames for tool execution**

After each tool call (success or failure), send a fire-and-forget frame to the control plane:

```go
// Success
auditFrame := proxy.Frame{
    Type: proxy.TypeToolExecuted,
    ID:   frame.ID,
    Payload: marshal(map[string]any{
        "tool_name":      toolName,
        "connector_name": connector.Name,
        "duration_ms":    elapsed.Milliseconds(),
    }),
}
_ = conn.Send(ctx, auditFrame)
```

**Step 5: Verify**

Run: `go build ./cmd/valinor-agent/...`
Expected: success

Run: `go test ./cmd/valinor-agent/ -v`
Expected: ALL PASS

**Step 6: Commit**

```bash
git add cmd/valinor-agent/agent.go cmd/valinor-agent/openclaw.go
git commit -m "feat(agent): implement agentic tool execution loop with MCP"
```

---

### Task 7: Handle Tool Audit Frames in Proxy

**Files:**
- Modify: `internal/proxy/handler.go`

**Step 1: Handle TypeToolExecuted and TypeToolFailed in the message response loop**

In `HandleMessage`, the response loop currently handles `TypeChunk`, `TypeToolBlocked`, `TypeSessionHalt`, and `TypeError`. Add handling for the new types:

```go
case TypeToolExecuted:
    // Fire-and-forget audit event
    if h.auditLogger != nil {
        var meta map[string]any
        _ = json.Unmarshal(reply.Payload, &meta)
        h.auditLogger.Log(ctx, AuditEvent{
            TenantID:     tenantUUID,
            UserID:       userUUID,
            Action:       "tool.executed",
            ResourceType: "agent",
            ResourceID:   agentUUID,
            Metadata:     meta,
            Source:       "agent",
        })
    }
    continue // don't return, keep collecting frames

case TypeToolFailed:
    // Same pattern, action = "tool.failed"
    continue
```

**Step 2: Verify**

Run: `go build ./internal/proxy/...`
Expected: success

**Step 3: Commit**

```bash
git add internal/proxy/handler.go
git commit -m "feat(proxy): forward tool execution audit events to logger"
```

---

### Task 8: Integration Test — Tool Call Loop

**Files:**
- Create: `cmd/valinor-agent/openclaw_test.go`

**Step 1: Write integration test**

Test the full loop: mock OpenClaw returns a tool call → agent validates → calls mock MCP server → feeds result back → OpenClaw returns final text.

```go
func TestForwardToOpenClaw_ToolCallLoop(t *testing.T) {
    // Set up mock OpenClaw that:
    //   1st call: returns tool_calls: [{name: "search_players", args: "{}"}]
    //   2nd call: returns content: "Found 3 players"
    // Set up mock MCP server that returns tool result
    // Create agent with connectors configured
    // Call forwardToOpenClaw
    // Verify the response chunk contains "Found 3 players"
}
```

**Step 2: Run test**

Run: `go test ./cmd/valinor-agent/ -run TestForwardToOpenClaw -v`
Expected: PASS

**Step 3: Commit**

```bash
git add cmd/valinor-agent/openclaw_test.go
git commit -m "test(agent): add integration test for tool call execution loop"
```

---

### Task 9: Final Verification

**Step 1: Run full test suite**

Run: `go test ./...`
Expected: ALL PASS

**Step 2: Build all binaries**

Run: `go build ./cmd/valinor/... && go build ./cmd/valinor-agent/...`
Expected: success

**Step 3: Lint**

Run: `gofmt -d .`
Expected: no output (all formatted)

---

## Verification Commands

```bash
# Unit tests
go test ./cmd/valinor-agent/... -v
go test ./internal/proxy/... -v
go test ./internal/orchestrator/... -v
go test ./internal/audit/... -v

# Full suite
go test ./...

# Build
go build ./cmd/valinor/...
go build ./cmd/valinor-agent/...

# Lint
gofmt -d .
```
