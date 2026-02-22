# Phase 7: Connectors Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement MCP connector CRUD (register, list, delete) with agent-side credential injection via the existing config_update pipeline.

**Architecture:** Thin CRUD layer — `internal/connectors/` package with Store + Handler. Connector configs pushed to agents via the existing `PushConfig` function. No new wire protocol frames. Agent stores connector configs alongside tool allowlists.

**Tech Stack:** Go, PostgreSQL (existing `connectors` table with RLS), `pgx/v5`, `database.Querier` + `WithTenantConnection` for tenant isolation.

---

### Task 1: Connector Domain Types

**Files:**
- Create: `internal/connectors/connectors.go`

**Step 1: Write the domain types and error sentinels**

```go
package connectors

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Connector represents a registered MCP server for a tenant.
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

var (
	ErrNotFound      = errors.New("connector not found")
	ErrNameEmpty     = errors.New("connector name is required")
	ErrEndpointEmpty = errors.New("connector endpoint is required")
)
```

**Step 2: Verify it compiles**

Run: `go build ./internal/connectors/`
Expected: SUCCESS (no output)

**Step 3: Commit**

```bash
git add internal/connectors/connectors.go
git commit -m "feat: add connector domain types and error sentinels"
```

---

### Task 2: Connector Store — Create

**Files:**
- Create: `internal/connectors/store.go`
- Create: `internal/connectors/store_test.go`

**Step 1: Write the failing test**

```go
package connectors_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/valinor-ai/valinor/internal/connectors"
)

// mockQuerier implements database.Querier for unit tests.
// It captures the SQL and args from the last call.
type mockQuerier struct {
	queryRowSQL  string
	queryRowArgs []any
	execSQL      string
	execArgs     []any
	scanValues   []any // values to return from Scan
	scanErr      error
	execTag      string // e.g. "DELETE 1"
	execErr      error
}

// We'll implement the full mock later. For now, test that Store exists.

func TestNewStore(t *testing.T) {
	store := connectors.NewStore()
	if store == nil {
		t.Fatal("NewStore returned nil")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/connectors/ -run TestNewStore -v`
Expected: FAIL — `NewStore` not defined

**Step 3: Write the Store with Create method**

```go
package connectors

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

// Store handles connector database operations.
// Methods accept database.Querier so they can run inside WithTenantConnection.
type Store struct{}

// NewStore creates a new connector store.
func NewStore() *Store {
	return &Store{}
}

// Create inserts a new connector. The tenant_id is read from the RLS session variable.
func (s *Store) Create(ctx context.Context, q database.Querier, name, connectorType, endpoint string, authConfig, tools, resources json.RawMessage) (*Connector, error) {
	if name == "" {
		return nil, ErrNameEmpty
	}
	if endpoint == "" {
		return nil, ErrEndpointEmpty
	}
	if connectorType == "" {
		connectorType = "mcp"
	}
	if authConfig == nil {
		authConfig = json.RawMessage(`{}`)
	}
	if tools == nil {
		tools = json.RawMessage(`[]`)
	}
	if resources == nil {
		resources = json.RawMessage(`[]`)
	}

	var c Connector
	err := q.QueryRow(ctx,
		`INSERT INTO connectors (tenant_id, name, connector_type, endpoint, auth_config, tools, resources)
		 VALUES (current_setting('app.current_tenant_id', true)::UUID, $1, $2, $3, $4, $5, $6)
		 RETURNING id, tenant_id, name, connector_type, endpoint, auth_config, resources, tools, status, created_at`,
		name, connectorType, endpoint, authConfig, tools, resources,
	).Scan(&c.ID, &c.TenantID, &c.Name, &c.ConnectorType, &c.Endpoint, &c.AuthConfig, &c.Resources, &c.Tools, &c.Status, &c.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("creating connector: %w", err)
	}
	return &c, nil
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/connectors/ -run TestNewStore -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/connectors/store.go internal/connectors/store_test.go
git commit -m "feat: add connector store with Create method"
```

---

### Task 3: Connector Store — List, GetByID, Delete

**Files:**
- Modify: `internal/connectors/store.go`
- Modify: `internal/connectors/store_test.go`

**Step 1: Write failing tests for validation edge cases**

Add to `store_test.go`:

```go
func TestCreateValidation(t *testing.T) {
	store := connectors.NewStore()

	t.Run("empty name returns error", func(t *testing.T) {
		_, err := store.Create(context.Background(), nil, "", "mcp", "https://example.com", nil, nil, nil)
		if err == nil {
			t.Fatal("expected error for empty name")
		}
	})

	t.Run("empty endpoint returns error", func(t *testing.T) {
		_, err := store.Create(context.Background(), nil, "test", "mcp", "", nil, nil, nil)
		if err == nil {
			t.Fatal("expected error for empty endpoint")
		}
	})
}
```

**Step 2: Run tests to verify they pass (validation is pre-DB)**

Run: `go test ./internal/connectors/ -run TestCreateValidation -v`
Expected: PASS (validation returns errors before hitting DB)

**Step 3: Add List, GetByID, Delete methods to store.go**

Append to `store.go`:

```go
// List returns all connectors visible through RLS (current tenant).
func (s *Store) List(ctx context.Context, q database.Querier) ([]Connector, error) {
	rows, err := q.Query(ctx,
		`SELECT id, tenant_id, name, connector_type, endpoint, auth_config, resources, tools, status, created_at
		 FROM connectors ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("listing connectors: %w", err)
	}
	defer rows.Close()

	var result []Connector
	for rows.Next() {
		var c Connector
		if err := rows.Scan(&c.ID, &c.TenantID, &c.Name, &c.ConnectorType, &c.Endpoint, &c.AuthConfig, &c.Resources, &c.Tools, &c.Status, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning connector: %w", err)
		}
		result = append(result, c)
	}
	return result, rows.Err()
}

// GetByID retrieves a connector by ID. RLS ensures tenant isolation.
func (s *Store) GetByID(ctx context.Context, q database.Querier, id string) (*Connector, error) {
	var c Connector
	err := q.QueryRow(ctx,
		`SELECT id, tenant_id, name, connector_type, endpoint, auth_config, resources, tools, status, created_at
		 FROM connectors WHERE id = $1`,
		id,
	).Scan(&c.ID, &c.TenantID, &c.Name, &c.ConnectorType, &c.Endpoint, &c.AuthConfig, &c.Resources, &c.Tools, &c.Status, &c.CreatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("getting connector: %w", err)
	}
	return &c, nil
}

// Delete removes a connector by ID. Returns ErrNotFound if no rows affected.
func (s *Store) Delete(ctx context.Context, q database.Querier, id string) error {
	tag, err := q.Exec(ctx, `DELETE FROM connectors WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("deleting connector: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListForAgent returns connectors as simplified config maps for agent injection.
func (s *Store) ListForAgent(ctx context.Context, q database.Querier) ([]map[string]any, error) {
	rows, err := q.Query(ctx,
		`SELECT name, connector_type, endpoint, auth_config, tools
		 FROM connectors WHERE status = 'active' ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("listing connectors for agent: %w", err)
	}
	defer rows.Close()

	var result []map[string]any
	for rows.Next() {
		var name, connType, endpoint string
		var authConfig, tools json.RawMessage
		if err := rows.Scan(&name, &connType, &endpoint, &authConfig, &tools); err != nil {
			return nil, fmt.Errorf("scanning connector for agent: %w", err)
		}
		result = append(result, map[string]any{
			"name":     name,
			"type":     connType,
			"endpoint": endpoint,
			"auth":     json.RawMessage(authConfig),
			"tools":    json.RawMessage(tools),
		})
	}
	return result, rows.Err()
}
```

**Step 4: Run all tests**

Run: `go test ./internal/connectors/ -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/connectors/store.go internal/connectors/store_test.go
git commit -m "feat: add connector store List, GetByID, Delete, ListForAgent"
```

---

### Task 4: Connector Handler — HandleCreate

**Files:**
- Create: `internal/connectors/handler.go`
- Create: `internal/connectors/handler_test.go`

**Step 1: Write the failing test**

```go
package connectors_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/valinor-ai/valinor/internal/connectors"
)

func TestHandleCreate_MissingName(t *testing.T) {
	handler := connectors.NewHandler(nil, connectors.NewStore())
	body := `{"endpoint": "https://example.com"}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/test-tenant/connectors", strings.NewReader(body))
	w := httptest.NewRecorder()

	handler.HandleCreate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/connectors/ -run TestHandleCreate_MissingName -v`
Expected: FAIL — `NewHandler` not defined

**Step 3: Write the handler with HandleCreate**

```go
package connectors

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/valinor-ai/valinor/internal/platform/database"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
)

// Handler handles connector HTTP endpoints.
type Handler struct {
	pool  *pgxpool.Pool
	store *Store
}

// NewHandler creates a new connector handler.
func NewHandler(pool *pgxpool.Pool, store *Store) *Handler {
	return &Handler{pool: pool, store: store}
}

// HandleCreate registers a new MCP connector for the tenant.
// POST /api/v1/tenants/{tenantID}/connectors
func (h *Handler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 10<<10)

	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant context required"})
		return
	}

	var req struct {
		Name          string          `json:"name"`
		ConnectorType string          `json:"connector_type"`
		Endpoint      string          `json:"endpoint"`
		AuthConfig    json.RawMessage `json:"auth_config"`
		Tools         json.RawMessage `json:"tools"`
		Resources     json.RawMessage `json:"resources"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	var connector *Connector
	err := database.WithTenantConnection(r.Context(), h.pool, tenantID, func(ctx context.Context, q database.Querier) error {
		var createErr error
		connector, createErr = h.store.Create(ctx, q, req.Name, req.ConnectorType, req.Endpoint, req.AuthConfig, req.Tools, req.Resources)
		return createErr
	})
	if err != nil {
		if err == ErrNameEmpty || err == ErrEndpointEmpty {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "connector creation failed"})
		return
	}

	writeJSON(w, http.StatusCreated, connector)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/connectors/ -run TestHandleCreate_MissingName -v`
Expected: PASS (validation catches empty name before DB, pool is nil so no DB hit)

**Step 5: Commit**

```bash
git add internal/connectors/handler.go internal/connectors/handler_test.go
git commit -m "feat: add connector handler with HandleCreate"
```

---

### Task 5: Connector Handler — HandleList and HandleDelete

**Files:**
- Modify: `internal/connectors/handler.go`
- Modify: `internal/connectors/handler_test.go`

**Step 1: Write failing tests**

Add to `handler_test.go`:

```go
func TestHandleDelete_MissingID(t *testing.T) {
	handler := connectors.NewHandler(nil, connectors.NewStore())
	req := httptest.NewRequest("DELETE", "/api/v1/connectors/", nil)
	w := httptest.NewRecorder()

	handler.HandleDelete(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/connectors/ -run TestHandleDelete -v`
Expected: FAIL — `HandleDelete` not defined

**Step 3: Add HandleList and HandleDelete**

Append to `handler.go`:

```go
// HandleList returns all connectors for the tenant.
// GET /api/v1/tenants/{tenantID}/connectors
func (h *Handler) HandleList(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant context required"})
		return
	}

	var list []Connector
	err := database.WithTenantConnection(r.Context(), h.pool, tenantID, func(ctx context.Context, q database.Querier) error {
		var listErr error
		list, listErr = h.store.List(ctx, q)
		return listErr
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "listing connectors failed"})
		return
	}

	if list == nil {
		list = []Connector{}
	}

	writeJSON(w, http.StatusOK, list)
}

// HandleDelete removes a connector.
// DELETE /api/v1/connectors/{id}
func (h *Handler) HandleDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "connector id is required"})
		return
	}

	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant context required"})
		return
	}

	err := database.WithTenantConnection(r.Context(), h.pool, tenantID, func(ctx context.Context, q database.Querier) error {
		return h.store.Delete(ctx, q, id)
	})
	if err != nil {
		if err == ErrNotFound {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "connector not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "deleting connector failed"})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
```

**Step 4: Run all tests**

Run: `go test ./internal/connectors/ -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/connectors/handler.go internal/connectors/handler_test.go
git commit -m "feat: add connector handler HandleList and HandleDelete"
```

---

### Task 6: Wire Connector Handler into Server Dependencies

**Files:**
- Modify: `internal/platform/server/server.go:14` (imports), `server.go:24-40` (Dependencies), `server.go:229-236` (route block)

**Step 1: Write a failing build check**

Run: `go build ./internal/platform/server/`
Expected: SUCCESS (no changes yet — baseline)

**Step 2: Add ConnectorHandler to Dependencies and register routes**

In `internal/platform/server/server.go`:

1. Add import: `"github.com/valinor-ai/valinor/internal/connectors"`

2. Add to `Dependencies` struct (after `AuditHandler` field, line 35):
```go
ConnectorHandler *connectors.Handler
```

3. Add route block after the audit routes block (after line 236):
```go
// Connector routes (tenant-scoped, RBAC-protected)
if deps.ConnectorHandler != nil && deps.RBAC != nil {
    protectedMux.Handle("POST /api/v1/tenants/{tenantID}/connectors",
        rbac.RequirePermission(deps.RBAC, "connectors:write", rbacOpts...)(
            http.HandlerFunc(deps.ConnectorHandler.HandleCreate),
        ),
    )
    protectedMux.Handle("GET /api/v1/tenants/{tenantID}/connectors",
        rbac.RequirePermission(deps.RBAC, "connectors:read", rbacOpts...)(
            http.HandlerFunc(deps.ConnectorHandler.HandleList),
        ),
    )
    protectedMux.Handle("DELETE /api/v1/connectors/{id}",
        rbac.RequirePermission(deps.RBAC, "connectors:write", rbacOpts...)(
            http.HandlerFunc(deps.ConnectorHandler.HandleDelete),
        ),
    )
}
```

**Step 3: Verify it compiles**

Run: `go build ./internal/platform/server/`
Expected: SUCCESS

**Step 4: Commit**

```bash
git add internal/platform/server/server.go
git commit -m "feat: wire connector handler routes into server"
```

---

### Task 7: Wire Connector Store and Handler in main.go

**Files:**
- Modify: `cmd/valinor/main.go:12-23` (imports), `main.go:119-136` (after tenant setup, RBAC section), `main.go:224-240` (Dependencies)

**Step 1: Add connector initialization to main.go**

1. Add import: `"github.com/valinor-ai/valinor/internal/connectors"`

2. After the RBAC role registration block (line 136) and before the Audit block (line 138), add:
```go
// Connectors
var connectorHandler *connectors.Handler
if pool != nil {
    connectorStore := connectors.NewStore()
    connectorHandler = connectors.NewHandler(pool, connectorStore)
}
```

3. Add `connectors:read` and `connectors:write` to `dept_head` role (modify line 126-130):
```go
rbacEngine.RegisterRole("dept_head", []string{
    "agents:read", "agents:write", "agents:message",
    "users:read", "users:write",
    "departments:read",
    "connectors:read", "connectors:write",
})
```

4. Add `ConnectorHandler` to Dependencies struct (in the `server.New()` call, after `AuditHandler`):
```go
ConnectorHandler:  connectorHandler,
```

**Step 2: Verify it compiles**

Run: `go build ./cmd/valinor/`
Expected: SUCCESS

**Step 3: Run all tests**

Run: `go test ./...`
Expected: PASS

**Step 4: Commit**

```bash
git add cmd/valinor/main.go
git commit -m "feat: wire connector store and handler in main.go DI"
```

---

### Task 8: Add ConnectorResolver Interface to Orchestrator

**Files:**
- Modify: `internal/orchestrator/handler.go:15-29` (Handler struct and constructor)

**Step 1: Add the interface and update Handler**

In `internal/orchestrator/handler.go`:

1. Add the interface (after `ConfigPusher` interface, line 18):
```go
// ConnectorResolver resolves connectors for a tenant during config push.
type ConnectorResolver interface {
	ResolveForTenant(ctx context.Context, pool any, tenantID string) ([]map[string]any, error)
}
```

2. Add field to Handler struct:
```go
type Handler struct {
    manager            *Manager
    configPusher       ConfigPusher       // optional, nil = no vsock push
    connectorResolver  ConnectorResolver  // optional, nil = no connector injection
}
```

3. Update NewHandler:
```go
func NewHandler(manager *Manager, pusher ConfigPusher, resolver ConnectorResolver) *Handler {
    return &Handler{manager: manager, configPusher: pusher, connectorResolver: resolver}
}
```

**Step 2: Fix all callers of NewHandler**

In `cmd/valinor/main.go`, the `NewHandler` call (line 199) needs the new parameter:
```go
agentHandler = orchestrator.NewHandler(orchManager, pusher, nil)
```

(We'll pass the real resolver in the next task.)

**Step 3: Verify it compiles**

Run: `go build ./...`
Expected: SUCCESS

**Step 4: Run all tests**

Run: `go test ./...`
Expected: PASS (existing orchestrator tests pass NewHandler with updated signature)

**Step 5: Commit**

```bash
git add internal/orchestrator/handler.go cmd/valinor/main.go
git commit -m "feat: add ConnectorResolver interface to orchestrator handler"
```

---

### Task 9: Extend PushConfig for Connectors

**Files:**
- Modify: `internal/proxy/push.go:13-16` (PushConfig signature)
- Modify: `internal/proxy/push.go:22-32` (payload struct)

**Step 1: Extend PushConfig signature and payload**

In `internal/proxy/push.go`:

1. Update function signature (line 13-16):
```go
func PushConfig(ctx context.Context, pool *ConnPool, agentID string, cid uint32,
	config map[string]any, toolAllowlist []string,
	toolPolicies map[string]any, canaryTokens []string,
	connectorConfigs []map[string]any,
	timeout time.Duration) error {
```

2. Update payload struct (line 22-32):
```go
payload := struct {
    Config           map[string]any   `json:"config"`
    ToolAllowlist    []string         `json:"tool_allowlist"`
    ToolPolicies     map[string]any   `json:"tool_policies,omitempty"`
    CanaryTokens     []string         `json:"canary_tokens,omitempty"`
    ConnectorConfigs []map[string]any `json:"connectors,omitempty"`
}{
    Config:           config,
    ToolAllowlist:    toolAllowlist,
    ToolPolicies:     toolPolicies,
    CanaryTokens:     canaryTokens,
    ConnectorConfigs: connectorConfigs,
}
```

**Step 2: Update ConfigPusher interface in orchestrator**

In `internal/orchestrator/handler.go`, update the ConfigPusher interface:
```go
type ConfigPusher interface {
	PushConfig(ctx context.Context, agentID string, cid uint32, config map[string]any, toolAllowlist []string, toolPolicies map[string]any, canaryTokens []string, connectorConfigs []map[string]any) error
}
```

**Step 3: Update configPusherAdapter in main.go**

In `cmd/valinor/main.go`, update the adapter method:
```go
func (a *configPusherAdapter) PushConfig(ctx context.Context, agentID string, cid uint32, config map[string]any, toolAllowlist []string, toolPolicies map[string]any, canaryTokens []string, connectorConfigs []map[string]any) error {
	return proxy.PushConfig(ctx, a.pool, agentID, cid, config, toolAllowlist, toolPolicies, canaryTokens, connectorConfigs, a.timeout)
}
```

**Step 4: Update HandleConfigure call site**

In `internal/orchestrator/handler.go` `HandleConfigure` (line 237), update the PushConfig call:
```go
if pushErr := h.configPusher.PushConfig(r.Context(), id, *inst.VsockCID, req.Config, req.ToolAllowlist, nil, nil, nil); pushErr != nil {
```

**Step 5: Verify it compiles**

Run: `go build ./...`
Expected: SUCCESS

**Step 6: Run all tests**

Run: `go test ./...`
Expected: PASS

**Step 7: Commit**

```bash
git add internal/proxy/push.go internal/orchestrator/handler.go cmd/valinor/main.go
git commit -m "feat: extend PushConfig with connector configs parameter"
```

---

### Task 10: Wire ConnectorResolver Adapter in main.go

**Files:**
- Modify: `cmd/valinor/main.go` (add connectorResolverAdapter, wire into orchestrator)

**Step 1: Add the adapter type**

After the existing adapter types at the bottom of `main.go`, add:

```go
// connectorResolverAdapter bridges connectors.Store to orchestrator.ConnectorResolver.
type connectorResolverAdapter struct {
	store *connectors.Store
}

func (a *connectorResolverAdapter) ResolveForTenant(ctx context.Context, pool any, tenantID string) ([]map[string]any, error) {
	pgxPool, ok := pool.(*pgxpool.Pool)
	if !ok {
		return nil, fmt.Errorf("invalid pool type for connector resolver")
	}
	var result []map[string]any
	err := database.WithTenantConnection(ctx, pgxPool, tenantID, func(ctx context.Context, q database.Querier) error {
		var listErr error
		result, listErr = a.store.ListForAgent(ctx, q)
		return listErr
	})
	return result, err
}
```

**Step 2: Pass the real resolver to orchestrator.NewHandler**

Update the `NewHandler` call in main.go from `nil` to the adapter:

```go
var connectorResolver orchestrator.ConnectorResolver
if pool != nil {
    connectorResolver = &connectorResolverAdapter{store: connectors.NewStore()}
}
agentHandler = orchestrator.NewHandler(orchManager, pusher, connectorResolver)
```

Note: The `connectorStore` is already created for the handler. Reuse it:

```go
var connectorHandler *connectors.Handler
var connectorStore *connectors.Store
if pool != nil {
    connectorStore = connectors.NewStore()
    connectorHandler = connectors.NewHandler(pool, connectorStore)
}
```

Then:
```go
var connectorResolver orchestrator.ConnectorResolver
if connectorStore != nil {
    connectorResolver = &connectorResolverAdapter{store: connectorStore}
}
agentHandler = orchestrator.NewHandler(orchManager, pusher, connectorResolver)
```

**Step 3: Verify it compiles**

Run: `go build ./cmd/valinor/`
Expected: SUCCESS

**Step 4: Commit**

```bash
git add cmd/valinor/main.go
git commit -m "feat: wire connector resolver adapter into orchestrator"
```

---

### Task 11: Resolve Connectors During HandleConfigure

**Files:**
- Modify: `internal/orchestrator/handler.go:174-250` (HandleConfigure method)

**Step 1: Update HandleConfigure to resolve and push connectors**

In `HandleConfigure`, after the existing `UpdateConfig` call (line 229-233) and before the push block (line 235-240):

1. Add the Handler's pool field. Update Handler struct to include pool reference. Actually — the orchestrator handler doesn't have the pool. The `ConnectorResolver.ResolveForTenant` accepts a `pool any` parameter so main.go can pass the pool type-erased. But a cleaner approach: change the interface so it doesn't need pool:

Update `ConnectorResolver` interface:
```go
type ConnectorResolver interface {
	ResolveForTenant(ctx context.Context, tenantID string) ([]map[string]any, error)
}
```

Update the adapter in main.go to close over the pool:
```go
type connectorResolverAdapter struct {
	pool  *pgxpool.Pool
	store *connectors.Store
}

func (a *connectorResolverAdapter) ResolveForTenant(ctx context.Context, tenantID string) ([]map[string]any, error) {
	var result []map[string]any
	err := database.WithTenantConnection(ctx, a.pool, tenantID, func(ctx context.Context, q database.Querier) error {
		var listErr error
		result, listErr = a.store.ListForAgent(ctx, q)
		return listErr
	})
	return result, err
}
```

2. In HandleConfigure, resolve connectors before push:

```go
// Resolve connectors for the agent's tenant
var connectorConfigs []map[string]any
if h.connectorResolver != nil && inst.TenantID != nil {
    resolved, resolveErr := h.connectorResolver.ResolveForTenant(r.Context(), *inst.TenantID)
    if resolveErr != nil {
        slog.Warn("connector resolution failed", "id", id, "error", resolveErr)
    } else {
        connectorConfigs = resolved
    }
}

// Best-effort push to running agent via vsock
if h.configPusher != nil && inst.Status == StatusRunning && inst.VsockCID != nil {
    if pushErr := h.configPusher.PushConfig(r.Context(), id, *inst.VsockCID, req.Config, req.ToolAllowlist, nil, nil, connectorConfigs); pushErr != nil {
        slog.Warn("config push to agent failed", "id", id, "error", pushErr)
    }
}
```

**Step 2: Verify it compiles**

Run: `go build ./...`
Expected: SUCCESS

**Step 3: Run all tests**

Run: `go test ./...`
Expected: PASS

**Step 4: Commit**

```bash
git add internal/orchestrator/handler.go cmd/valinor/main.go
git commit -m "feat: resolve and push connectors during agent configure"
```

---

### Task 12: Extend Agent Config Update for Connectors

**Files:**
- Modify: `cmd/valinor-agent/agent.go:24-32` (Agent struct), `agent.go:132-167` (handleConfigUpdate)

**Step 1: Add connectors field to Agent struct**

In `cmd/valinor-agent/agent.go`:

1. Add field to Agent struct (after `canaryTokens` field, line 29):
```go
connectors []map[string]any
```

2. Update `mu` comment (line 30):
```go
mu sync.RWMutex // protects toolAllowlist, toolPolicies, canaryTokens, connectors, config
```

3. Update `handleConfigUpdate` payload struct (line 133-138):
```go
var payload struct {
    Config        map[string]any        `json:"config"`
    ToolAllowlist []string              `json:"tool_allowlist"`
    ToolPolicies  map[string]ToolPolicy `json:"tool_policies"`
    CanaryTokens  []string              `json:"canary_tokens"`
    Connectors    []map[string]any      `json:"connectors"`
}
```

4. Store connectors in the lock block (line 150-155):
```go
a.mu.Lock()
a.config = payload.Config
a.toolAllowlist = payload.ToolAllowlist
a.toolPolicies = payload.ToolPolicies
a.canaryTokens = payload.CanaryTokens
a.connectors = payload.Connectors
a.mu.Unlock()
```

5. Update log line (line 157):
```go
slog.Info("config updated", "tools", len(payload.ToolAllowlist), "connectors", len(payload.Connectors))
```

**Step 2: Verify it compiles**

Run: `go build ./cmd/valinor-agent/`
Expected: SUCCESS

**Step 3: Run all tests**

Run: `go test ./...`
Expected: PASS

**Step 4: Commit**

```bash
git add cmd/valinor-agent/agent.go
git commit -m "feat: extend agent config update to store connector configs"
```

---

### Task 13: Add RBAC Permissions for Connectors

**Files:**
- Modify: `cmd/valinor/main.go:124-136` (already partially done in Task 7)

This task ensures `connectors:read` and `connectors:write` are properly registered. If already done in Task 7, verify and skip.

**Step 1: Verify RBAC registration includes connector permissions**

The `org_admin` role already has `"*"` (wildcard), so it inherits connector permissions.

For `dept_head`, ensure the registration includes:
```go
rbacEngine.RegisterRole("dept_head", []string{
    "agents:read", "agents:write", "agents:message",
    "users:read", "users:write",
    "departments:read",
    "connectors:read", "connectors:write",
})
```

**Step 2: Verify it compiles and tests pass**

Run: `go build ./... && go test ./...`
Expected: SUCCESS + PASS

**Step 3: Commit (if changes needed)**

```bash
git add cmd/valinor/main.go
git commit -m "feat: add connector RBAC permissions to dept_head role"
```

---

### Task 14: Add Audit Logging to Connector Handler

**Files:**
- Modify: `internal/connectors/handler.go` (add audit interface, log events)

**Step 1: Add audit interface to handler**

The handler needs an optional audit logger. Following the same adapter pattern as proxy handler:

1. Add to `handler.go`:
```go
// AuditLogger logs auditable connector events.
type AuditLogger interface {
	Log(ctx context.Context, event AuditEvent)
}

// AuditEvent captures a connector audit action.
type AuditEvent struct {
	TenantID     uuid.UUID
	UserID       *uuid.UUID
	Action       string
	ResourceType string
	ResourceID   *uuid.UUID
	Metadata     map[string]any
	Source       string
}
```

2. Add `audit` field to Handler:
```go
type Handler struct {
    pool  *pgxpool.Pool
    store *Store
    audit AuditLogger
}
```

3. Update NewHandler:
```go
func NewHandler(pool *pgxpool.Pool, store *Store, audit AuditLogger) *Handler {
    return &Handler{pool: pool, store: store, audit: audit}
}
```

4. Add audit calls in HandleCreate (after successful creation):
```go
if h.audit != nil {
    var userID *uuid.UUID
    if identity := auth.GetIdentity(r.Context()); identity != nil {
        if uid, parseErr := uuid.Parse(identity.UserID); parseErr == nil {
            userID = &uid
        }
    }
    var tid uuid.UUID
    if parsed, parseErr := uuid.Parse(tenantID); parseErr == nil {
        tid = parsed
    }
    h.audit.Log(r.Context(), AuditEvent{
        TenantID:     tid,
        UserID:       userID,
        Action:       "connector.created",
        ResourceType: "connector",
        ResourceID:   &connector.ID,
        Source:       "api",
    })
}
```

5. Add similar audit call in HandleDelete (after successful deletion).

**Step 2: Update NewHandler callers**

In `cmd/valinor/main.go`:
```go
connectorHandler = connectors.NewHandler(pool, connectorStore, &connectorAuditAdapter{l: auditLogger})
```

Add adapter:
```go
type connectorAuditAdapter struct {
	l audit.Logger
}

func (a *connectorAuditAdapter) Log(ctx context.Context, event connectors.AuditEvent) {
	a.l.Log(ctx, audit.Event{
		TenantID:     event.TenantID,
		UserID:       event.UserID,
		Action:       event.Action,
		ResourceType: event.ResourceType,
		ResourceID:   event.ResourceID,
		Metadata:     event.Metadata,
		Source:       event.Source,
	})
}
```

In `handler_test.go`, update `NewHandler` calls to pass `nil` for audit:
```go
handler := connectors.NewHandler(nil, connectors.NewStore(), nil)
```

**Step 3: Verify it compiles and tests pass**

Run: `go build ./... && go test ./...`
Expected: SUCCESS + PASS

**Step 4: Commit**

```bash
git add internal/connectors/handler.go internal/connectors/handler_test.go cmd/valinor/main.go
git commit -m "feat: add audit logging to connector create and delete"
```

---

### Task 15: Full Integration Test — Build and Vet

**Files:**
- No new files

**Step 1: Run full build**

Run: `go build ./...`
Expected: SUCCESS

**Step 2: Run vet**

Run: `go vet ./...`
Expected: No issues

**Step 3: Run gofmt check**

Run: `gofmt -l .`
Expected: No output (all files formatted)

**Step 4: Run all tests**

Run: `go test ./...`
Expected: All packages PASS

**Step 5: Fix any issues found, then commit**

```bash
git add -A
git commit -m "fix: address any build/vet/format issues"
```

(Skip commit if no issues found.)

---

### Task 16: Delete .gitkeep from connectors directory

**Files:**
- Delete: `internal/connectors/.gitkeep`

**Step 1: Remove the placeholder file**

```bash
rm internal/connectors/.gitkeep
```

**Step 2: Commit**

```bash
git add internal/connectors/.gitkeep
git commit -m "chore: remove .gitkeep now that connectors package has real files"
```
