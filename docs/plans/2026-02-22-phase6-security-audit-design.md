# Phase 6: Security + Audit — Design Document

**Date:** 2026-02-22

**Scope:** Audit pipeline, Input Sentinel, Tool Call Validator (parameter-level), Canary Tokens

**Approach:** Service Injection — components are Go services injected via DI into the places that need them. No new middleware layers; audit calls happen inside handlers and existing middleware.

---

## 1. Audit Pipeline

**Package:** `internal/audit/`

### Interface

```go
type Logger interface {
    Log(ctx context.Context, event Event)
    Close() error
}
```

`Log` is fire-and-forget — drops the event onto a buffered channel, never blocks the caller. A background worker pool drains the channel in batches (100 events or every 500ms, whichever comes first) and inserts into `audit_events` via a multi-row INSERT.

### Event Struct

```go
type Event struct {
    TenantID     uuid.UUID
    UserID       *uuid.UUID     // nullable for system events
    Action       string         // "message.sent", "tool.blocked", "config.updated"
    ResourceType string         // "agent", "user", "connector"
    ResourceID   *uuid.UUID
    Metadata     map[string]any
    Source       string         // "api", "whatsapp", "system"
}
```

### Database

Migration 000008 creates the `audit_events` table:

- Partitioned by month on `created_at`
- RLS policy for reads only (app role has INSERT but no UPDATE/DELETE)
- No FK on `tenant_id` (performance — audit is append-only)
- Nullable `user_id` for system-generated events

### Injection Points

- Proxy handlers: message sent/received
- RBAC middleware: access denied
- Agent store: provisioned/destroyed
- Sentinel: injection detected/quarantined
- Tool Call Validator: tool blocked (via proxy handler receiving TypeToolBlocked)

---

## 2. Input Sentinel

**Package:** `internal/sentinel/`

### Interface

```go
type Sentinel interface {
    Scan(ctx context.Context, input ScanInput) (ScanResult, error)
}
```

### Two-Stage Scan

1. **Pattern matcher** (microseconds): Regex checks for known injection patterns — "ignore previous instructions", "system prompt:", role injection attempts, encoded payloads. Blocks immediately on match. Patterns compiled once at startup from config file.

2. **LLM classifier** (only if patterns pass): Sends message to Claude Haiku via Anthropic Go SDK. Classification prompt returns `{"injection": bool, "confidence": float, "reason": string}`. Block if confidence > 0.85; quarantine (allow + flag) if 0.5–0.85.

### ScanResult

```go
type ScanResult struct {
    Allowed    bool
    Score      float64  // 0.0 = safe, 1.0 = definite injection
    Reason     string   // "pattern:role_injection" or "llm:high_confidence"
    Quarantine bool     // allow but flag for review
}
```

### Placement

Injected into proxy `Handler`. Called in `HandleMessage` and `HandleStream` before forwarding to agent. Non-message endpoints skip sentinel entirely.

### Failure Mode

If LLM call fails (timeout, API error), fall through to allow — pattern matcher already ran. Log the failure for ops visibility. No silent blocking on infra errors.

### Configuration

- Patterns loadable from config file
- LLM endpoint + API key from env vars
- Both stages independently toggleable

---

## 3. Tool Call Validator (Parameter-Level)

**Location:** `cmd/valinor-agent/` (enhances existing `isToolAllowed`)

### Current State

`isToolAllowed` checks tool name against a flat allow-list.

### Enhancement

Control plane pushes `tool_policies` via existing `config_update` frame:

```json
{
  "tool_allowlist": ["search_players", "get_report"],
  "tool_policies": {
    "search_players": {
      "allowed_params": ["league", "position", "age_max"],
      "denied_params": ["salary", "contract_value"],
      "max_results": 50
    }
  }
}
```

Agent validates tool name AND parsed arguments. Blocked calls send existing `TypeToolBlocked` frame with details (tool name, violated parameter, policy reason).

---

## 4. Canary Tokens

**Location:** `cmd/valinor-agent/` (in-guest detection)

### Injection

Control plane pushes canary strings via `config_update`:

```json
{
  "canary_tokens": ["CANARY-a8f3e2", "CANARY-7b1d4c"]
}
```

### Detection

After receiving each OpenClaw response chunk, agent scans content for any canary token. If found:

1. Send `TypeSessionHalt` frame: `{"reason": "canary_leak", "token": "CANARY-a8f3e2"}`
2. Drop the tainted response — never forward to client
3. Close the OpenClaw session

### Proxy-Side Handling

Proxy handler receives `TypeSessionHalt`, logs an audit event, returns 503 with generic error (no leak details exposed).

### New Wire Protocol Addition

`TypeSessionHalt = "session_halt"` added to `internal/proxy/protocol.go`.

---

## 5. Wiring & Integration

### Dependency Injection (main.go)

```go
auditLogger := audit.NewLogger(db, audit.Config{
    BufferSize:    4096,
    BatchSize:     100,
    FlushInterval: 500 * time.Millisecond,
})
defer auditLogger.Close()

sentinel := sentinel.New(sentinel.Config{
    PatternsFile:   cfg.Sentinel.PatternsFile,
    AnthropicKey:   cfg.Sentinel.AnthropicAPIKey,
    LLMEnabled:     cfg.Sentinel.LLMEnabled,
    BlockThreshold: 0.85,
})

proxyHandler := proxy.NewHandler(pool, agentStore, proxy.HandlerConfig{
    MessageTimeout: 30 * time.Second,
}, sentinel, auditLogger)
```

### Middleware Chain (Unchanged)

```
RequestID -> Logging -> Auth -> TenantContext -> RBAC -> Handler
```

Audit is NOT a middleware layer. It's a service called from inside handlers and middleware:
- RBAC middleware calls `auditLogger.Log()` on denials
- Proxy handlers call `auditLogger.Log()` on message events
- This keeps audit precise and domain-aware

### Agent Config Update Payload (Extended)

```json
{
  "config": { "model": "gpt-4o" },
  "tool_allowlist": ["search_players"],
  "tool_policies": { ... },
  "canary_tokens": ["CANARY-a8f3e2"]
}
```

Uses existing `config_update` frame. No new frame types except `TypeSessionHalt`.

### New Dependencies

- `github.com/anthropics/anthropic-sdk-go` — Claude Haiku for sentinel LLM classifier
- No other new deps

### Testing Strategy

- **Audit:** Unit test channel + batch writer with mock DB
- **Sentinel:** Unit test patterns against known injection corpus; mock Anthropic API for LLM tests
- **Tool Call Validator:** Extend existing `TestOpenClawProxy_ToolBlocked` with parameter-level cases
- **Canary Tokens:** Test with mock OpenClaw that returns canary in response
- **Integration:** End-to-end test: injection attempt -> audit event + block verified
