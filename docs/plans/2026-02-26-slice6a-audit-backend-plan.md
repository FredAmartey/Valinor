# Slice 6a: Audit Backend — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add server-side filters to the audit events API and emit CRUD audit events from all resource handlers.

**Architecture:** Extend the existing audit handler with composable query params (action, resource_type, user_id, source, before). Add an `audit.Logger` field to each handler struct that performs writes. Emit fire-and-forget audit events after successful DB mutations.

**Tech Stack:** Go 1.25, PostgreSQL 15, pgx/v5, testify

---

### Task 1: Add CRUD Action Constants

**Files:**
- Modify: `internal/audit/audit.go:20-32`

**Step 1: Add constants**

Add after the existing channel constants block (line 32):

```go
const (
	// CRUD actions
	ActionUserCreated          = "user.created"
	ActionUserUpdated          = "user.updated"
	ActionUserSuspended        = "user.suspended"
	ActionUserReactivated      = "user.reactivated"

	ActionAgentProvisioned     = "agent.provisioned"
	ActionAgentUpdated         = "agent.updated"
	ActionAgentDestroyed       = "agent.destroyed"

	ActionTenantCreated        = "tenant.created"
	ActionTenantUpdated        = "tenant.updated"
	ActionTenantSuspended      = "tenant.suspended"

	ActionDepartmentCreated    = "department.created"
	ActionDepartmentUpdated    = "department.updated"
	ActionDepartmentDeleted    = "department.deleted"

	ActionRoleCreated          = "role.created"
	ActionRoleUpdated          = "role.updated"
	ActionRoleDeleted          = "role.deleted"

	ActionUserRoleAssigned     = "user_role.assigned"
	ActionUserRoleRevoked      = "user_role.revoked"
)
```

**Step 2: Verify compilation**

Run: `go build ./internal/audit/...`
Expected: success, no errors

**Step 3: Commit**

```bash
git add internal/audit/audit.go
git commit -m "feat(audit): add CRUD action constants"
```

---

### Task 2: Add ListEventsParams and Dynamic Query Builder

**Files:**
- Modify: `internal/audit/store.go`
- Modify: `internal/audit/store_test.go`

**Step 1: Write the failing test**

Add to `internal/audit/store_test.go`:

```go
func TestBuildListQuery_NoFilters(t *testing.T) {
	tenantID := uuid.New()
	params := ListEventsParams{
		TenantID: tenantID,
		Limit:    50,
	}
	sql, args := buildListQuery(params)
	assert.Contains(t, sql, "WHERE tenant_id = $1")
	assert.Contains(t, sql, "LIMIT $2")
	assert.Equal(t, tenantID, args[0])
	assert.Equal(t, 50, args[1])
}

func TestBuildListQuery_AllFilters(t *testing.T) {
	tenantID := uuid.New()
	userID := uuid.New()
	action := "user.created"
	resType := "user"
	source := "api"
	after := time.Date(2026, 2, 25, 0, 0, 0, 0, time.UTC)
	before := time.Date(2026, 2, 26, 0, 0, 0, 0, time.UTC)
	params := ListEventsParams{
		TenantID:     tenantID,
		Action:       &action,
		ResourceType: &resType,
		UserID:       &userID,
		Source:       &source,
		After:        &after,
		Before:       &before,
		Limit:        100,
	}
	sql, args := buildListQuery(params)
	assert.Contains(t, sql, "action = $")
	assert.Contains(t, sql, "resource_type = $")
	assert.Contains(t, sql, "user_id = $")
	assert.Contains(t, sql, "source = $")
	assert.Contains(t, sql, "created_at > $")
	assert.Contains(t, sql, "created_at < $")
	// tenant_id + 6 filters + limit = 8 args
	assert.Len(t, args, 8)
}

func TestBuildListQuery_PartialFilters(t *testing.T) {
	tenantID := uuid.New()
	action := "role.deleted"
	params := ListEventsParams{
		TenantID: tenantID,
		Action:   &action,
		Limit:    50,
	}
	sql, args := buildListQuery(params)
	assert.Contains(t, sql, "action = $2")
	assert.Contains(t, sql, "LIMIT $3")
	assert.Len(t, args, 3)
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/audit/ -run TestBuildListQuery -v`
Expected: FAIL — `ListEventsParams` and `buildListQuery` undefined

**Step 3: Implement ListEventsParams and buildListQuery**

Add to `internal/audit/store.go`:

```go
// ListEventsParams defines filters for querying audit events.
type ListEventsParams struct {
	TenantID     uuid.UUID
	Action       *string
	ResourceType *string
	UserID       *uuid.UUID
	Source       *string
	After        *time.Time
	Before       *time.Time
	Limit        int
}

// buildListQuery constructs a parameterized SELECT for audit events.
func buildListQuery(p ListEventsParams) (string, []any) {
	var conditions []string
	var args []any
	argN := 1

	conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argN))
	args = append(args, p.TenantID)
	argN++

	if p.Action != nil {
		conditions = append(conditions, fmt.Sprintf("action = $%d", argN))
		args = append(args, *p.Action)
		argN++
	}
	if p.ResourceType != nil {
		conditions = append(conditions, fmt.Sprintf("resource_type = $%d", argN))
		args = append(args, *p.ResourceType)
		argN++
	}
	if p.UserID != nil {
		conditions = append(conditions, fmt.Sprintf("user_id = $%d", argN))
		args = append(args, *p.UserID)
		argN++
	}
	if p.Source != nil {
		conditions = append(conditions, fmt.Sprintf("source = $%d", argN))
		args = append(args, *p.Source)
		argN++
	}
	if p.After != nil {
		conditions = append(conditions, fmt.Sprintf("created_at > $%d", argN))
		args = append(args, *p.After)
		argN++
	}
	if p.Before != nil {
		conditions = append(conditions, fmt.Sprintf("created_at < $%d", argN))
		args = append(args, *p.Before)
		argN++
	}

	sql := fmt.Sprintf(
		`SELECT id, tenant_id, user_id, action, resource_type, resource_id, metadata, source, created_at
		FROM audit_events
		WHERE %s
		ORDER BY created_at DESC
		LIMIT $%d`,
		strings.Join(conditions, " AND "), argN,
	)
	args = append(args, p.Limit)

	return sql, args
}
```

Add imports: `"time"`, `"github.com/google/uuid"` (if not already present).

**Step 4: Run test to verify it passes**

Run: `go test ./internal/audit/ -run TestBuildListQuery -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/audit/store.go internal/audit/store_test.go
git commit -m "feat(audit): add ListEventsParams and dynamic query builder"
```

---

### Task 3: Update Handler to Use Filters

**Files:**
- Modify: `internal/audit/handler.go:28-107`
- Modify: `internal/audit/handler_test.go`

**Step 1: Write the failing tests**

Add to `internal/audit/handler_test.go`:

```go
func TestHandleListEvents_WithActionFilter(t *testing.T) {
	h := NewHandler(nil)
	req := httptest.NewRequest("GET", "/api/v1/audit/events?action=user.created", nil)
	req = req.WithContext(middleware.WithTenantID(req.Context(), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"))
	w := httptest.NewRecorder()

	h.HandleListEvents(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"count":0`)
}

func TestHandleListEvents_WithResourceTypeFilter(t *testing.T) {
	h := NewHandler(nil)
	req := httptest.NewRequest("GET", "/api/v1/audit/events?resource_type=agent", nil)
	req = req.WithContext(middleware.WithTenantID(req.Context(), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"))
	w := httptest.NewRecorder()

	h.HandleListEvents(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"count":0`)
}

func TestHandleListEvents_WithSourceFilter(t *testing.T) {
	h := NewHandler(nil)
	req := httptest.NewRequest("GET", "/api/v1/audit/events?source=api", nil)
	req = req.WithContext(middleware.WithTenantID(req.Context(), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"))
	w := httptest.NewRecorder()

	h.HandleListEvents(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"count":0`)
}

func TestHandleListEvents_WithBeforeFilter(t *testing.T) {
	h := NewHandler(nil)
	req := httptest.NewRequest("GET", "/api/v1/audit/events?before=2026-02-26T00:00:00Z", nil)
	req = req.WithContext(middleware.WithTenantID(req.Context(), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"))
	w := httptest.NewRecorder()

	h.HandleListEvents(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"count":0`)
}

func TestHandleListEvents_WithUserIDFilter(t *testing.T) {
	h := NewHandler(nil)
	req := httptest.NewRequest("GET", "/api/v1/audit/events?user_id=a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11", nil)
	req = req.WithContext(middleware.WithTenantID(req.Context(), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"))
	w := httptest.NewRecorder()

	h.HandleListEvents(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"count":0`)
}

func TestHandleListEvents_InvalidUserIDFilter(t *testing.T) {
	h := NewHandler(nil)
	req := httptest.NewRequest("GET", "/api/v1/audit/events?user_id=not-a-uuid", nil)
	req = req.WithContext(middleware.WithTenantID(req.Context(), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"))
	w := httptest.NewRecorder()

	h.HandleListEvents(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/audit/ -run "TestHandleListEvents_With|TestHandleListEvents_Invalid" -v`
Expected: FAIL — new filter params not parsed, InvalidUserIDFilter won't return 400

**Step 3: Rewrite HandleListEvents to parse filters and use buildListQuery**

Replace `HandleListEvents` in `internal/audit/handler.go`:

```go
func (h *Handler) HandleListEvents(w http.ResponseWriter, r *http.Request) {
	tenantIDStr := middleware.GetTenantID(r.Context())
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		writeAuditJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid tenant context"})
		return
	}

	params := ListEventsParams{
		TenantID: tenantID,
		Limit:    50,
	}

	// Parse limit
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, parseErr := strconv.Atoi(raw); parseErr == nil && n > 0 && n <= 200 {
			params.Limit = n
		}
	}

	// Parse optional filters
	if v := r.URL.Query().Get("action"); v != "" {
		params.Action = &v
	}
	if v := r.URL.Query().Get("resource_type"); v != "" {
		params.ResourceType = &v
	}
	if v := r.URL.Query().Get("source"); v != "" {
		params.Source = &v
	}
	if raw := r.URL.Query().Get("user_id"); raw != "" {
		uid, parseErr := uuid.Parse(raw)
		if parseErr != nil {
			writeAuditJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid user_id"})
			return
		}
		params.UserID = &uid
	}
	if raw := r.URL.Query().Get("after"); raw != "" {
		if t, parseErr := time.Parse(time.RFC3339, raw); parseErr == nil {
			params.After = &t
		}
	}
	if raw := r.URL.Query().Get("before"); raw != "" {
		if t, parseErr := time.Parse(time.RFC3339, raw); parseErr == nil {
			params.Before = &t
		}
	}

	if h.pool == nil {
		writeAuditJSON(w, http.StatusOK, map[string]any{"events": []any{}, "count": 0})
		return
	}

	var events []map[string]any
	queryErr := database.WithTenantConnection(r.Context(), h.pool, tenantIDStr, func(ctx context.Context, q database.Querier) error {
		sql, args := buildListQuery(params)
		rows, qErr := q.Query(ctx, sql, args...)
		if qErr != nil {
			return qErr
		}
		defer rows.Close()

		for rows.Next() {
			var (
				id, tid    uuid.UUID
				uid, resID *uuid.UUID
				action     string
				resType    *string
				metadata   json.RawMessage
				source     string
				createdAt  time.Time
			)
			if scanErr := rows.Scan(&id, &tid, &uid, &action, &resType, &resID, &metadata, &source, &createdAt); scanErr != nil {
				continue
			}
			events = append(events, map[string]any{
				"id":            id,
				"tenant_id":     tid,
				"user_id":       uid,
				"action":        action,
				"resource_type": resType,
				"resource_id":   resID,
				"metadata":      metadata,
				"source":        source,
				"created_at":    createdAt,
			})
		}
		return nil
	})

	if queryErr != nil {
		writeAuditJSON(w, http.StatusInternalServerError, map[string]string{"error": "query failed"})
		return
	}

	if events == nil {
		events = []map[string]any{}
	}

	writeAuditJSON(w, http.StatusOK, map[string]any{"events": events, "count": len(events)})
}
```

**Step 4: Run all audit handler tests**

Run: `go test ./internal/audit/ -run TestHandleListEvents -v`
Expected: ALL PASS

**Step 5: Commit**

```bash
git add internal/audit/handler.go internal/audit/handler_test.go
git commit -m "feat(audit): add server-side filters to audit events API"
```

---

### Task 4: Inject audit.Logger into Tenant Handlers

This task adds the `audit.Logger` field to all four handler structs in the `tenant` package and emits audit events after successful writes. The handlers (tenant, department, user, role) share a package, so we do them together.

**Files:**
- Modify: `internal/tenant/handler.go`
- Modify: `internal/tenant/department_handler.go`
- Modify: `internal/tenant/user_handler.go`
- Modify: `internal/tenant/role_handler.go`
- Create: `internal/tenant/audit_test.go`

**Step 1: Write the failing test**

Create `internal/tenant/audit_test.go`:

```go
package tenant

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/valinor-ai/valinor/internal/audit"
)

// captureLogger is a test helper that captures audit events.
type captureLogger struct {
	mu     sync.Mutex
	events []audit.Event
}

func (l *captureLogger) Log(_ context.Context, e audit.Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
}

func (l *captureLogger) Close() error { return nil }

func (l *captureLogger) Events() []audit.Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]audit.Event{}, l.events...)
}

func TestNewHandler_AcceptsAuditLogger(t *testing.T) {
	logger := &captureLogger{}
	h := NewHandler(nil, logger)
	assert.NotNil(t, h)
}

func TestNewDepartmentHandler_AcceptsAuditLogger(t *testing.T) {
	logger := &captureLogger{}
	h := NewDepartmentHandler(nil, nil, logger)
	assert.NotNil(t, h)
}

func TestNewUserHandler_AcceptsAuditLogger(t *testing.T) {
	logger := &captureLogger{}
	h := NewUserHandler(nil, nil, nil, logger)
	assert.NotNil(t, h)
}

func TestNewRoleHandler_AcceptsAuditLogger(t *testing.T) {
	logger := &captureLogger{}
	h := NewRoleHandler(nil, nil, nil, nil, nil, logger)
	assert.NotNil(t, h)
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/tenant/ -run "TestNew.*_AcceptsAuditLogger" -v`
Expected: FAIL — constructor signatures don't accept audit.Logger

**Step 3: Add audit.Logger to all handler structs**

Modify `internal/tenant/handler.go`:
- Add import `"github.com/valinor-ai/valinor/internal/audit"`
- Add `auditLog audit.Logger` to `Handler` struct
- Update `NewHandler` to accept `audit.Logger`:
  ```go
  func NewHandler(store *Store, auditLog audit.Logger) *Handler {
      return &Handler{store: store, auditLog: auditLog}
  }
  ```

Modify `internal/tenant/department_handler.go`:
- Add import `"github.com/valinor-ai/valinor/internal/audit"`
- Add `auditLog audit.Logger` to `DepartmentHandler` struct
- Update `NewDepartmentHandler`:
  ```go
  func NewDepartmentHandler(pool *pgxpool.Pool, store *DepartmentStore, auditLog audit.Logger) *DepartmentHandler {
      return &DepartmentHandler{pool: pool, store: store, auditLog: auditLog}
  }
  ```

Modify `internal/tenant/user_handler.go`:
- Add import `"github.com/valinor-ai/valinor/internal/audit"`
- Add `auditLog audit.Logger` to `UserHandler` struct
- Update `NewUserHandler`:
  ```go
  func NewUserHandler(pool *pgxpool.Pool, store *UserStore, deptStore *DepartmentStore, auditLog audit.Logger) *UserHandler {
      return &UserHandler{pool: pool, store: store, deptStore: deptStore, auditLog: auditLog}
  }
  ```

Modify `internal/tenant/role_handler.go`:
- Add import `"github.com/valinor-ai/valinor/internal/audit"`
- Add `auditLog audit.Logger` to `RoleHandler` struct
- Update `NewRoleHandler`:
  ```go
  func NewRoleHandler(pool *pgxpool.Pool, store *RoleStore, userStore *UserStore, deptStore *DepartmentStore, evaluator RBACReloader, auditLog audit.Logger) *RoleHandler {
      return &RoleHandler{pool: pool, store: store, userStore: userStore, deptStore: deptStore, evaluator: evaluator, auditLog: auditLog}
  }
  ```

**Step 4: Run tests**

Run: `go test ./internal/tenant/ -run "TestNew.*_AcceptsAuditLogger" -v`
Expected: PASS

Note: Other tests may fail because call sites in `main.go` don't pass the logger yet. That's expected and will be fixed in Task 7.

**Step 5: Commit**

```bash
git add internal/tenant/handler.go internal/tenant/department_handler.go internal/tenant/user_handler.go internal/tenant/role_handler.go internal/tenant/audit_test.go
git commit -m "feat(tenant): add audit.Logger field to all handler constructors"
```

---

### Task 5: Inject audit.Logger into Orchestrator Handler

**Files:**
- Modify: `internal/orchestrator/handler.go`

**Step 1: Add audit.Logger field and update constructor**

Add import `"github.com/valinor-ai/valinor/internal/audit"`.

Update the Handler struct:

```go
type Handler struct {
	manager      *Manager
	configPusher ConfigPusher
	auditLog     audit.Logger
}

func NewHandler(manager *Manager, pusher ConfigPusher, auditLog audit.Logger) *Handler {
	return &Handler{manager: manager, configPusher: pusher, auditLog: auditLog}
}
```

**Step 2: Verify compilation of the package**

Run: `go build ./internal/orchestrator/...`
Expected: May fail because main.go still uses old signature — that's fine, fixed in Task 7.

**Step 3: Commit**

```bash
git add internal/orchestrator/handler.go
git commit -m "feat(orchestrator): add audit.Logger to handler constructor"
```

---

### Task 6: Emit Audit Events from All Handlers

**Files:**
- Modify: `internal/tenant/handler.go` (HandleCreate — tenant.created)
- Modify: `internal/tenant/department_handler.go` (HandleCreate — department.created)
- Modify: `internal/tenant/user_handler.go` (HandleCreate — user.created, HandleAddToDepartment, HandleRemoveFromDepartment)
- Modify: `internal/tenant/role_handler.go` (HandleCreate, HandleUpdate, HandleDelete, HandleAssignRole, HandleRemoveRole)
- Modify: `internal/orchestrator/handler.go` (HandleProvision, HandleDestroyAgent, HandleConfigure)

**Pattern for all audit calls:**

```go
if h.auditLog != nil {
    h.auditLog.Log(r.Context(), audit.Event{
        TenantID:     tenantUUID,
        UserID:       &actorUUID,
        Action:       audit.ActionXxxYyy,
        ResourceType: "resource_type",
        ResourceID:   &resourceUUID,
        Metadata:     map[string]any{"key": "value"},
        Source:       "api",
    })
}
```

For getting the actor identity, use `auth.GetIdentity(r.Context())`. The tenant handlers need a new import of `"github.com/valinor-ai/valinor/internal/auth"`.

**Step 1: Add audit emission to tenant HandleCreate**

In `internal/tenant/handler.go`, after `t, err := h.store.Create(...)` succeeds (before `writeJSON` at line 59), add:

```go
if h.auditLog != nil {
    identity := auth.GetIdentity(r.Context())
    var actorID *uuid.UUID
    if identity != nil {
        if uid, parseErr := uuid.Parse(identity.UserID); parseErr == nil {
            actorID = &uid
        }
    }
    h.auditLog.Log(r.Context(), audit.Event{
        TenantID:     t.ID,
        UserID:       actorID,
        Action:       audit.ActionTenantCreated,
        ResourceType: "tenant",
        ResourceID:   &t.ID,
        Metadata:     map[string]any{"name": t.Name, "slug": t.Slug},
        Source:       "api",
    })
}
```

Add imports: `"github.com/valinor-ai/valinor/internal/auth"`, `"github.com/google/uuid"`.

**Step 2: Add audit emission to DepartmentHandler.HandleCreate**

In `internal/tenant/department_handler.go`, after `dept` is created (before `writeJSON` at line 63), add:

```go
if h.auditLog != nil {
    tenantUUID, _ := uuid.Parse(tenantID)
    identity := auth.GetIdentity(r.Context())
    var actorID *uuid.UUID
    if identity != nil {
        if uid, parseErr := uuid.Parse(identity.UserID); parseErr == nil {
            actorID = &uid
        }
    }
    h.auditLog.Log(r.Context(), audit.Event{
        TenantID:     tenantUUID,
        UserID:       actorID,
        Action:       audit.ActionDepartmentCreated,
        ResourceType: "department",
        ResourceID:   &dept.ID,
        Metadata:     map[string]any{"name": dept.Name},
        Source:       "api",
    })
}
```

Add imports: `"github.com/valinor-ai/valinor/internal/audit"`, `"github.com/valinor-ai/valinor/internal/auth"`, `"github.com/google/uuid"`.

**Step 3: Add audit emission to UserHandler**

In `internal/tenant/user_handler.go`:

After user creation succeeds (before `writeJSON` at line 64):
```go
if h.auditLog != nil {
    tenantUUID, _ := uuid.Parse(tenantID)
    identity := auth.GetIdentity(r.Context())
    var actorID *uuid.UUID
    if identity != nil {
        if uid, parseErr := uuid.Parse(identity.UserID); parseErr == nil {
            actorID = &uid
        }
    }
    h.auditLog.Log(r.Context(), audit.Event{
        TenantID:     tenantUUID,
        UserID:       actorID,
        Action:       audit.ActionUserCreated,
        ResourceType: "user",
        ResourceID:   &user.ID,
        Metadata:     map[string]any{"email": user.Email, "display_name": user.DisplayName},
        Source:       "api",
    })
}
```

After HandleAddToDepartment succeeds (before `writeJSON` at line 177):
```go
if h.auditLog != nil {
    tenantUUID, _ := uuid.Parse(tenantID)
    identity := auth.GetIdentity(r.Context())
    var actorID *uuid.UUID
    if identity != nil {
        if uid, parseErr := uuid.Parse(identity.UserID); parseErr == nil {
            actorID = &uid
        }
    }
    userUUID, _ := uuid.Parse(userID)
    h.auditLog.Log(r.Context(), audit.Event{
        TenantID:     tenantUUID,
        UserID:       actorID,
        Action:       audit.ActionUserUpdated,
        ResourceType: "user",
        ResourceID:   &userUUID,
        Metadata:     map[string]any{"department_added": req.DepartmentID},
        Source:       "api",
    })
}
```

After HandleRemoveFromDepartment succeeds (before `writeJSON` at line 203):
```go
if h.auditLog != nil {
    tenantUUID, _ := uuid.Parse(tenantID)
    identity := auth.GetIdentity(r.Context())
    var actorID *uuid.UUID
    if identity != nil {
        if uid, parseErr := uuid.Parse(identity.UserID); parseErr == nil {
            actorID = &uid
        }
    }
    userUUID, _ := uuid.Parse(userID)
    h.auditLog.Log(r.Context(), audit.Event{
        TenantID:     tenantUUID,
        UserID:       actorID,
        Action:       audit.ActionUserUpdated,
        ResourceType: "user",
        ResourceID:   &userUUID,
        Metadata:     map[string]any{"department_removed": deptID},
        Source:       "api",
    })
}
```

Add imports: `"github.com/valinor-ai/valinor/internal/audit"`, `"github.com/valinor-ai/valinor/internal/auth"`, `"github.com/google/uuid"`.

**Step 4: Add audit emission to RoleHandler**

In `internal/tenant/role_handler.go`:

After HandleCreate succeeds (before RBAC reload, ~line 81):
```go
if h.auditLog != nil {
    tenantUUID, _ := uuid.Parse(tenantID)
    identity := auth.GetIdentity(r.Context())
    var actorID *uuid.UUID
    if identity != nil {
        if uid, parseErr := uuid.Parse(identity.UserID); parseErr == nil {
            actorID = &uid
        }
    }
    h.auditLog.Log(r.Context(), audit.Event{
        TenantID:     tenantUUID,
        UserID:       actorID,
        Action:       audit.ActionRoleCreated,
        ResourceType: "role",
        ResourceID:   &role.ID,
        Metadata:     map[string]any{"name": role.Name, "permissions": role.Permissions},
        Source:       "api",
    })
}
```

After HandleUpdate succeeds (before RBAC reload, ~line 177):
```go
if h.auditLog != nil {
    tenantUUID, _ := uuid.Parse(tenantID)
    identity := auth.GetIdentity(r.Context())
    var actorID *uuid.UUID
    if identity != nil {
        if uid, parseErr := uuid.Parse(identity.UserID); parseErr == nil {
            actorID = &uid
        }
    }
    h.auditLog.Log(r.Context(), audit.Event{
        TenantID:     tenantUUID,
        UserID:       actorID,
        Action:       audit.ActionRoleUpdated,
        ResourceType: "role",
        ResourceID:   &role.ID,
        Metadata:     map[string]any{"name": role.Name, "permissions": role.Permissions},
        Source:       "api",
    })
}
```

After HandleDelete succeeds (before RBAC reload, ~line 221):
```go
if h.auditLog != nil {
    tenantUUID, _ := uuid.Parse(tenantID)
    roleUUID, _ := uuid.Parse(roleID)
    identity := auth.GetIdentity(r.Context())
    var actorID *uuid.UUID
    if identity != nil {
        if uid, parseErr := uuid.Parse(identity.UserID); parseErr == nil {
            actorID = &uid
        }
    }
    h.auditLog.Log(r.Context(), audit.Event{
        TenantID:     tenantUUID,
        UserID:       actorID,
        Action:       audit.ActionRoleDeleted,
        ResourceType: "role",
        ResourceID:   &roleUUID,
        Source:       "api",
    })
}
```

After HandleAssignRole succeeds (before `writeJSON` at line 298):
```go
if h.auditLog != nil {
    tenantUUID, _ := uuid.Parse(tenantID)
    userUUID, _ := uuid.Parse(userID)
    identity := auth.GetIdentity(r.Context())
    var actorID *uuid.UUID
    if identity != nil {
        if uid, parseErr := uuid.Parse(identity.UserID); parseErr == nil {
            actorID = &uid
        }
    }
    h.auditLog.Log(r.Context(), audit.Event{
        TenantID:     tenantUUID,
        UserID:       actorID,
        Action:       audit.ActionUserRoleAssigned,
        ResourceType: "user",
        ResourceID:   &userUUID,
        Metadata:     map[string]any{"role_id": req.RoleID, "scope_type": req.ScopeType, "scope_id": req.ScopeID},
        Source:       "api",
    })
}
```

After HandleRemoveRole succeeds (before `writeJSON` at line 339):
```go
if h.auditLog != nil {
    tenantUUID, _ := uuid.Parse(tenantID)
    userUUID, _ := uuid.Parse(userID)
    identity := auth.GetIdentity(r.Context())
    var actorID *uuid.UUID
    if identity != nil {
        if uid, parseErr := uuid.Parse(identity.UserID); parseErr == nil {
            actorID = &uid
        }
    }
    h.auditLog.Log(r.Context(), audit.Event{
        TenantID:     tenantUUID,
        UserID:       actorID,
        Action:       audit.ActionUserRoleRevoked,
        ResourceType: "user",
        ResourceID:   &userUUID,
        Metadata:     map[string]any{"role_id": req.RoleID, "scope_type": req.ScopeType, "scope_id": req.ScopeID},
        Source:       "api",
    })
}
```

Add import: `"github.com/google/uuid"` (auth and audit already imported from Task 4).

**Step 5: Add audit emission to Orchestrator Handler**

In `internal/orchestrator/handler.go`:

After HandleProvision succeeds (before `writeJSON` at line 102):
```go
if h.auditLog != nil {
    tenantUUID, _ := uuid.Parse(tenantID)
    var actorID *uuid.UUID
    if identity != nil {
        if uid, parseErr := uuid.Parse(identity.UserID); parseErr == nil {
            actorID = &uid
        }
    }
    instID, _ := uuid.Parse(inst.ID)
    h.auditLog.Log(r.Context(), audit.Event{
        TenantID:     tenantUUID,
        UserID:       actorID,
        Action:       audit.ActionAgentProvisioned,
        ResourceType: "agent",
        ResourceID:   &instID,
        Metadata:     map[string]any{"status": inst.Status},
        Source:       "api",
    })
}
```

Add import: `"github.com/valinor-ai/valinor/internal/audit"`.

After HandleDestroyAgent succeeds (before `w.WriteHeader` at line 204):
```go
if h.auditLog != nil {
    tenantUUID, _ := uuid.Parse(middleware.GetTenantID(r.Context()))
    var actorID *uuid.UUID
    if identity != nil {
        if uid, parseErr := uuid.Parse(identity.UserID); parseErr == nil {
            actorID = &uid
        }
    }
    instID, _ := uuid.Parse(id)
    h.auditLog.Log(r.Context(), audit.Event{
        TenantID:     tenantUUID,
        UserID:       actorID,
        Action:       audit.ActionAgentDestroyed,
        ResourceType: "agent",
        ResourceID:   &instID,
        Source:       "api",
    })
}
```

After HandleConfigure succeeds (before returning the updated instance, ~line 273):
```go
if h.auditLog != nil {
    tenantUUID, _ := uuid.Parse(middleware.GetTenantID(r.Context()))
    var actorID *uuid.UUID
    if identity != nil {
        if uid, parseErr := uuid.Parse(identity.UserID); parseErr == nil {
            actorID = &uid
        }
    }
    instID, _ := uuid.Parse(id)
    h.auditLog.Log(r.Context(), audit.Event{
        TenantID:     tenantUUID,
        UserID:       actorID,
        Action:       audit.ActionAgentUpdated,
        ResourceType: "agent",
        ResourceID:   &instID,
        Metadata:     map[string]any{"tool_allowlist_count": len(req.ToolAllowlist)},
        Source:       "api",
    })
}
```

**Step 6: Verify package compilation**

Run: `go build ./internal/tenant/... ./internal/orchestrator/...`
Expected: May fail due to main.go wiring — fixed in Task 7.

**Step 7: Commit**

```bash
git add internal/tenant/ internal/orchestrator/handler.go
git commit -m "feat(audit): emit CRUD audit events from all resource handlers"
```

---

### Task 7: Wire Audit Logger in main.go

**Files:**
- Modify: `cmd/valinor/main.go:108-154` and `238`

**Step 1: Update handler constructor calls**

In `cmd/valinor/main.go`, the `auditLogger` variable is created at line 168. Move the handler creation that currently happens at lines 108-154 to AFTER the audit logger creation (line 178), or pass it through.

The simplest approach: since `auditLogger` is initialized to `audit.NopLogger{}` at line 168 before the `if pool != nil` block, just reorder so handlers are created after line 178. However, the handlers are already inside `if pool != nil` blocks, and the `auditLogger` is available at that point. The key issue is that tenant/dept/user/role handlers are created BEFORE the audit logger (lines 108-155 vs lines 167-178).

**Fix:** Move the audit logger creation block (lines 167-178) to BEFORE the handler creation block. Then update constructor calls:

```go
// Audit (moved before handler creation)
var auditLogger audit.Logger = audit.NopLogger{}
if pool != nil {
    auditStore := audit.NewStore()
    auditLogger = audit.NewAsyncLogger(pool, auditStore, audit.LoggerConfig{...})
    defer auditLogger.Close()
    slog.Info("audit logger started")
}

// Then create handlers with auditLogger:
tenantHandler = tenant.NewHandler(tenantStore, auditLogger)
deptHandler = tenant.NewDepartmentHandler(pool, deptStore, auditLogger)
userHandler = tenant.NewUserHandler(pool, userMgmtStore, deptStore, auditLogger)
roleHandler = tenant.NewRoleHandler(pool, roleStore, userMgmtStore, deptStore, rbacEngine, auditLogger)
agentHandler = orchestrator.NewHandler(orchManager, pusher, auditLogger)
```

**Step 2: Verify full build**

Run: `go build ./cmd/valinor/...`
Expected: success

**Step 3: Run all tests**

Run: `go test ./...`
Expected: ALL PASS

**Step 4: Commit**

```bash
git add cmd/valinor/main.go
git commit -m "feat(audit): wire audit logger into all resource handlers"
```

---

### Task 8: Integration Test — Full Audit Flow

**Files:**
- Modify: `internal/audit/handler_test.go`

**Step 1: Write test verifying filter param parsing produces valid ListEventsParams**

Add to `internal/audit/handler_test.go`:

```go
func TestHandleListEvents_ComposedFilters(t *testing.T) {
	h := NewHandler(nil)
	req := httptest.NewRequest("GET",
		"/api/v1/audit/events?action=user.created&resource_type=user&source=api&limit=25",
		nil,
	)
	req = req.WithContext(middleware.WithTenantID(req.Context(), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"))
	w := httptest.NewRecorder()

	h.HandleListEvents(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"count":0`)
	assert.Contains(t, w.Body.String(), `"events":[]`)
}
```

**Step 2: Run test**

Run: `go test ./internal/audit/ -run TestHandleListEvents_ComposedFilters -v`
Expected: PASS

**Step 3: Run full test suite**

Run: `go test ./...`
Expected: ALL PASS (this is the full verification gate)

**Step 4: Commit**

```bash
git add internal/audit/handler_test.go
git commit -m "test(audit): add composed filter integration test"
```

---

## Verification Commands

After all tasks complete, run:

```bash
# Unit tests
go test ./internal/audit/... -v
go test ./internal/tenant/... -v
go test ./internal/orchestrator/... -v

# Full test suite
go test ./...

# Build
go build ./cmd/valinor/...

# Lint (if configured)
golangci-lint run ./...
```
