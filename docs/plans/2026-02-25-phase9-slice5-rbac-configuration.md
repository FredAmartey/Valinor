# Phase 9 Slice 5 — RBAC Configuration Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** DB-backed RBAC evaluator with custom role CRUD and a permission checkbox matrix dashboard page.

**Architecture:** Extend the Go evaluator to load roles from the `roles` DB table instead of hardcoded `RegisterRole` calls. Add `PUT` and `DELETE` endpoints for roles. Build a `/rbac` dashboard page with role list + permission checkbox matrix.

**Tech Stack:** Go 1.23, pgx/v5, testify, Next.js 16, TypeScript, TanStack Query v5, Tailwind CSS v4, shadcn/ui, Vitest + RTL, Phosphor icons.

---

## Task 1: RoleLoader Interface and Evaluator ReloadRoles

**Files:**
- Modify: `internal/rbac/evaluator.go`
- Test: `internal/rbac/evaluator_test.go`

**Step 1: Write failing tests for ReloadRoles**

Add to `internal/rbac/evaluator_test.go`:

```go
type mockRoleLoader struct {
	roles []rbac.RoleDef
	err   error
}

func (m *mockRoleLoader) LoadRoles(ctx context.Context) ([]rbac.RoleDef, error) {
	return m.roles, m.err
}

func TestEvaluator_ReloadRoles(t *testing.T) {
	loader := &mockRoleLoader{
		roles: []rbac.RoleDef{
			{Name: "editor", Permissions: []string{"agents:read", "agents:write"}},
			{Name: "viewer", Permissions: []string{"agents:read"}},
		},
	}
	eval := rbac.NewEvaluator(nil, rbac.WithRoleLoader(loader))

	err := eval.ReloadRoles(context.Background())
	require.NoError(t, err)

	identity := &auth.Identity{UserID: "u1", TenantID: "t1", Roles: []string{"editor"}}
	d, err := eval.Authorize(context.Background(), identity, "agents:write", "", "")
	require.NoError(t, err)
	assert.True(t, d.Allowed)

	// viewer should not have agents:write
	identity2 := &auth.Identity{UserID: "u2", TenantID: "t1", Roles: []string{"viewer"}}
	d2, err := eval.Authorize(context.Background(), identity2, "agents:write", "", "")
	require.NoError(t, err)
	assert.False(t, d2.Allowed)
}

func TestEvaluator_ReloadRoles_ReplacesExisting(t *testing.T) {
	loader := &mockRoleLoader{
		roles: []rbac.RoleDef{
			{Name: "editor", Permissions: []string{"agents:read"}},
		},
	}
	eval := rbac.NewEvaluator(nil, rbac.WithRoleLoader(loader))
	require.NoError(t, eval.ReloadRoles(context.Background()))

	// Update loader to give editor more permissions
	loader.roles = []rbac.RoleDef{
		{Name: "editor", Permissions: []string{"agents:read", "agents:write"}},
	}
	require.NoError(t, eval.ReloadRoles(context.Background()))

	identity := &auth.Identity{UserID: "u1", TenantID: "t1", Roles: []string{"editor"}}
	d, err := eval.Authorize(context.Background(), identity, "agents:write", "", "")
	require.NoError(t, err)
	assert.True(t, d.Allowed)
}

func TestEvaluator_ReloadRoles_ErrorPreservesExisting(t *testing.T) {
	loader := &mockRoleLoader{
		roles: []rbac.RoleDef{
			{Name: "editor", Permissions: []string{"agents:read"}},
		},
	}
	eval := rbac.NewEvaluator(nil, rbac.WithRoleLoader(loader))
	require.NoError(t, eval.ReloadRoles(context.Background()))

	// Make loader fail
	loader.err = fmt.Errorf("db connection failed")
	err := eval.ReloadRoles(context.Background())
	require.Error(t, err)

	// Old permissions should still work
	identity := &auth.Identity{UserID: "u1", TenantID: "t1", Roles: []string{"editor"}}
	d, err := eval.Authorize(context.Background(), identity, "agents:read", "", "")
	require.NoError(t, err)
	assert.True(t, d.Allowed)
}
```

**Step 2: Run tests to verify they fail**

Run: `cd /Users/fred/Documents/Valinor && go test ./internal/rbac/ -run TestEvaluator_ReloadRoles -v`
Expected: compilation errors — `RoleDef`, `WithRoleLoader`, `ReloadRoles` not defined.

**Step 3: Implement RoleLoader and ReloadRoles**

In `internal/rbac/evaluator.go`:

1. Add the `RoleDef` type and `RoleLoader` interface:

```go
// RoleDef is a role name with its permission strings, used by RoleLoader.
type RoleDef struct {
	Name        string
	Permissions []string
}

// RoleLoader loads role definitions from a backing store.
type RoleLoader interface {
	LoadRoles(ctx context.Context) ([]RoleDef, error)
}
```

2. Add functional option for the loader:

```go
// EvaluatorOption configures the Evaluator.
type EvaluatorOption func(*Evaluator)

// WithRoleLoader sets a RoleLoader for DB-backed role loading.
func WithRoleLoader(loader RoleLoader) EvaluatorOption {
	return func(e *Evaluator) {
		e.loader = loader
	}
}
```

3. Add `loader` field to `Evaluator` struct and update `NewEvaluator`:

```go
type Evaluator struct {
	store  Store
	loader RoleLoader
	roles  map[string][]string
	mu     sync.RWMutex
}

func NewEvaluator(store Store, opts ...EvaluatorOption) *Evaluator {
	e := &Evaluator{
		store: store,
		roles: make(map[string][]string),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}
```

4. Add `ReloadRoles` method:

```go
// ReloadRoles loads roles from the RoleLoader and replaces the in-memory map.
// If loading fails, the existing map is preserved.
func (e *Evaluator) ReloadRoles(ctx context.Context) error {
	if e.loader == nil {
		return fmt.Errorf("no role loader configured")
	}

	defs, err := e.loader.LoadRoles(ctx)
	if err != nil {
		return fmt.Errorf("loading roles: %w", err)
	}

	newRoles := make(map[string][]string, len(defs))
	for _, d := range defs {
		newRoles[d.Name] = d.Permissions
	}

	e.mu.Lock()
	e.roles = newRoles
	e.mu.Unlock()

	return nil
}
```

**Step 4: Fix existing NewEvaluator call sites**

Since `NewEvaluator` signature changed to accept variadic options, all existing callers (`NewEvaluator(nil)` and `NewEvaluator(store)`) continue to work — no changes needed.

**Step 5: Run tests to verify they pass**

Run: `cd /Users/fred/Documents/Valinor && go test ./internal/rbac/ -v`
Expected: all tests pass, including existing ones.

**Step 6: Commit**

```bash
git add internal/rbac/evaluator.go internal/rbac/evaluator_test.go
git commit -m "feat: add RoleLoader interface and ReloadRoles to RBAC evaluator"
```

---

## Task 2: RoleLoader Implementation in Tenant Store

**Files:**
- Modify: `internal/tenant/role_store.go`
- Test: `internal/tenant/role_store_test.go`

**Step 1: Write failing test for LoadRoles**

The `LoadRoles` method needs to query all roles across all tenants (no RLS context). Add to `internal/tenant/role_store_test.go`:

```go
func TestRoleStore_LoadRoles(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ownerPool, rlsPool, cleanup := setupTestDBWithRLS(t)
	defer cleanup()

	ctx := context.Background()
	tenantStore := tenant.NewStore(ownerPool)
	ten, err := tenantStore.Create(ctx, "LoadRoles Org", "loadroles-org")
	require.NoError(t, err)

	// Create roles in tenant context
	err = database.WithTenantConnection(ctx, rlsPool, ten.ID, func(ctx context.Context, q database.Querier) error {
		store := tenant.NewRoleStore()
		_, err := store.Create(ctx, q, "admin", []string{"*"})
		require.NoError(t, err)
		_, err = store.Create(ctx, q, "viewer", []string{"agents:read"})
		require.NoError(t, err)
		return nil
	})
	require.NoError(t, err)

	// LoadRoles uses the owner pool directly (no RLS — cross-tenant)
	store := tenant.NewRoleStore()
	roles, err := store.LoadRoles(ctx, ownerPool)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(roles), 2)

	// Find our roles
	found := map[string]bool{}
	for _, r := range roles {
		if r.Name == "admin" || r.Name == "viewer" {
			found[r.Name] = true
		}
	}
	assert.True(t, found["admin"])
	assert.True(t, found["viewer"])
}
```

**Step 2: Run test to verify it fails**

Run: `cd /Users/fred/Documents/Valinor && go test ./internal/tenant/ -run TestRoleStore_LoadRoles -v`
Expected: compilation error — `LoadRoles` method not defined.

**Step 3: Implement LoadRoles**

Add to `internal/tenant/role_store.go`:

```go
// LoadRoles loads all role definitions across all tenants.
// Used by the RBAC evaluator at startup and after mutations.
// This queries the pool directly (no RLS context) because the evaluator
// needs a global view of all role names and their permissions.
func (s *RoleStore) LoadRoles(ctx context.Context, pool *pgxpool.Pool) ([]rbac.RoleDef, error) {
	rows, err := pool.Query(ctx,
		`SELECT name, permissions FROM roles ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("loading roles: %w", err)
	}
	defer rows.Close()

	var defs []rbac.RoleDef
	for rows.Next() {
		var name string
		var permBytes []byte
		if err := rows.Scan(&name, &permBytes); err != nil {
			return nil, fmt.Errorf("scanning role: %w", err)
		}
		var perms []string
		if err := json.Unmarshal(permBytes, &perms); err != nil {
			return nil, fmt.Errorf("unmarshaling permissions for %s: %w", name, err)
		}
		defs = append(defs, rbac.RoleDef{Name: name, Permissions: perms})
	}
	return defs, rows.Err()
}
```

This requires importing `rbac` — add `"github.com/valinor-ai/valinor/internal/rbac"` to imports. Also add `"github.com/jackc/pgx/v5/pgxpool"` if not already present.

**Step 4: Run test to verify it passes**

Run: `cd /Users/fred/Documents/Valinor && go test ./internal/tenant/ -run TestRoleStore_LoadRoles -v`
Expected: PASS.

**Step 5: Commit**

```bash
git add internal/tenant/role_store.go internal/tenant/role_store_test.go
git commit -m "feat: add LoadRoles to RoleStore for DB-backed evaluator"
```

---

## Task 3: Wire DB-Backed Evaluator in main.go

**Files:**
- Modify: `cmd/valinor/main.go:137-157`

**Step 1: Write a RoleLoaderAdapter**

The `RoleStore.LoadRoles` takes a `*pgxpool.Pool` arg, but `rbac.RoleLoader` interface expects just `ctx`. Create a small adapter. Add to `internal/tenant/role_store.go`:

```go
// RoleLoaderAdapter adapts RoleStore to the rbac.RoleLoader interface.
type RoleLoaderAdapter struct {
	store *RoleStore
	pool  *pgxpool.Pool
}

// NewRoleLoaderAdapter creates a RoleLoader backed by the roles table.
func NewRoleLoaderAdapter(store *RoleStore, pool *pgxpool.Pool) *RoleLoaderAdapter {
	return &RoleLoaderAdapter{store: store, pool: pool}
}

// LoadRoles implements rbac.RoleLoader.
func (a *RoleLoaderAdapter) LoadRoles(ctx context.Context) ([]rbac.RoleDef, error) {
	return a.store.LoadRoles(ctx, a.pool)
}
```

**Step 2: Update main.go — replace hardcoded roles with ReloadRoles**

Replace lines 137–157 of `cmd/valinor/main.go`:

```go
// RBAC
roleLoader := tenant.NewRoleLoaderAdapter(tenant.NewRoleStore(), pool)
rbacEngine := rbac.NewEvaluator(nil, rbac.WithRoleLoader(roleLoader))
if pool != nil {
	if err := rbacEngine.ReloadRoles(ctx); err != nil {
		return fmt.Errorf("loading roles from database: %w", err)
	}
	slog.Info("RBAC roles loaded from database")
} else {
	// Fallback for no-DB mode: register defaults in-memory
	rbacEngine.RegisterRole("org_admin", []string{"*"})
	rbacEngine.RegisterRole("dept_head", []string{
		"agents:read", "agents:write", "agents:message",
		"users:read", "users:write",
		"departments:read",
		"connectors:read", "connectors:write",
		"channels:links:read", "channels:links:write", "channels:messages:write",
		"channels:outbox:read", "channels:outbox:write",
		"channels:providers:read", "channels:providers:write",
	})
	rbacEngine.RegisterRole("standard_user", []string{
		"agents:read", "agents:message",
		"channels:messages:write",
	})
	rbacEngine.RegisterRole("read_only", []string{
		"agents:read",
	})
}
```

**Step 3: Verify compilation**

Run: `cd /Users/fred/Documents/Valinor && go build ./cmd/valinor/`
Expected: builds successfully.

**Step 4: Run full backend test suite**

Run: `cd /Users/fred/Documents/Valinor && go test ./... -short -count=1`
Expected: all tests pass.

**Step 5: Commit**

```bash
git add cmd/valinor/main.go internal/tenant/role_store.go
git commit -m "feat: wire DB-backed RBAC evaluator in main.go"
```

---

## Task 4: Update Seed Script Comment

**Files:**
- Modify: `scripts/seed_dev_roles.sql:6`

**Step 1: Update the outdated comment**

The comment says "enforcement uses the in-memory evaluator" — this is no longer true. Change line 6:

From: `-- The permissions column is stored for display; enforcement uses the in-memory evaluator.`
To: `-- The permissions column is used by the RBAC evaluator (loaded at startup and after mutations).`

**Step 2: Commit**

```bash
git add scripts/seed_dev_roles.sql
git commit -m "docs: update seed script comment to reflect DB-backed evaluator"
```

---

## Task 5: HandleUpdate and HandleDelete for Roles

**Files:**
- Modify: `internal/tenant/role.go` (new error sentinels)
- Modify: `internal/tenant/role_store.go` (new store methods)
- Modify: `internal/tenant/role_handler.go` (new handlers)
- Test: `internal/tenant/role_handler_test.go`

**Step 1: Add error sentinels to `internal/tenant/role.go`**

```go
var (
	ErrRoleNotFound    = errors.New("role not found")
	ErrRoleNameEmpty   = errors.New("role name is required")
	ErrRoleDuplicate   = errors.New("role name already exists in tenant")
	ErrRoleIsSystem    = errors.New("system roles cannot be modified")
	ErrRoleHasUsers    = errors.New("role is assigned to users")
	ErrWildcardDenied  = errors.New("wildcard permission not allowed for custom roles")
)
```

**Step 2: Write failing tests for HandleUpdate and HandleDelete**

Add to `internal/tenant/role_handler_test.go`:

```go
t.Run("Update", func(t *testing.T) {
	tenU, err := tenantStore.Create(ctx, "Update Role Org", "update-role-org")
	require.NoError(t, err)

	var roleID string
	err = database.WithTenantConnection(ctx, rlsPool, tenU.ID, func(ctx context.Context, q database.Querier) error {
		role, createErr := tenant.NewRoleStore().Create(ctx, q, "custom_role", []string{"agents:read"})
		require.NoError(t, createErr)
		roleID = role.ID
		return nil
	})
	require.NoError(t, err)

	body := `{"name": "custom_role", "permissions": ["agents:read", "agents:write"]}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/roles/"+roleID, strings.NewReader(body))
	req.SetPathValue("id", roleID)
	req.Header.Set("Content-Type", "application/json")
	req = withTenantIdentity(req, tenU.ID)
	w := httptest.NewRecorder()

	wrapWithTenantCtx(handler.HandleUpdate).ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var role tenant.Role
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &role))
	assert.Equal(t, []string{"agents:read", "agents:write"}, role.Permissions)
})

t.Run("Update_SystemRole_Rejected", func(t *testing.T) {
	tenS, err := tenantStore.Create(ctx, "System Update Org", "system-update-org")
	require.NoError(t, err)

	var systemRoleID string
	err = database.WithTenantConnection(ctx, rlsPool, tenS.ID, func(ctx context.Context, q database.Querier) error {
		_, execErr := q.Exec(ctx,
			`INSERT INTO roles (tenant_id, name, permissions, is_system) VALUES (current_setting('app.current_tenant_id', true)::UUID, 'sys_admin', '["*"]'::jsonb, true) RETURNING id`)
		require.NoError(t, execErr)
		row := q.QueryRow(ctx, `SELECT id FROM roles WHERE name = 'sys_admin' AND tenant_id = current_setting('app.current_tenant_id', true)::UUID`)
		require.NoError(t, row.Scan(&systemRoleID))
		return nil
	})
	require.NoError(t, err)

	body := `{"name": "sys_admin", "permissions": ["agents:read"]}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/roles/"+systemRoleID, strings.NewReader(body))
	req.SetPathValue("id", systemRoleID)
	req.Header.Set("Content-Type", "application/json")
	req = withTenantIdentity(req, tenS.ID)
	w := httptest.NewRecorder()

	wrapWithTenantCtx(handler.HandleUpdate).ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
})

t.Run("Update_WildcardRejected", func(t *testing.T) {
	tenW, err := tenantStore.Create(ctx, "Wildcard Update Org", "wildcard-update-org")
	require.NoError(t, err)

	var roleID string
	err = database.WithTenantConnection(ctx, rlsPool, tenW.ID, func(ctx context.Context, q database.Querier) error {
		role, createErr := tenant.NewRoleStore().Create(ctx, q, "sneaky", []string{"agents:read"})
		require.NoError(t, createErr)
		roleID = role.ID
		return nil
	})
	require.NoError(t, err)

	body := `{"name": "sneaky", "permissions": ["*"]}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/roles/"+roleID, strings.NewReader(body))
	req.SetPathValue("id", roleID)
	req.Header.Set("Content-Type", "application/json")
	req = withTenantIdentity(req, tenW.ID)
	w := httptest.NewRecorder()

	wrapWithTenantCtx(handler.HandleUpdate).ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
})

t.Run("Delete", func(t *testing.T) {
	tenD, err := tenantStore.Create(ctx, "Delete Role Org", "delete-role-org")
	require.NoError(t, err)

	var roleID string
	err = database.WithTenantConnection(ctx, rlsPool, tenD.ID, func(ctx context.Context, q database.Querier) error {
		role, createErr := tenant.NewRoleStore().Create(ctx, q, "temp_role", []string{"agents:read"})
		require.NoError(t, createErr)
		roleID = role.ID
		return nil
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/roles/"+roleID, nil)
	req.SetPathValue("id", roleID)
	req = withTenantIdentity(req, tenD.ID)
	w := httptest.NewRecorder()

	wrapWithTenantCtx(handler.HandleDelete).ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
})

t.Run("Delete_SystemRole_Rejected", func(t *testing.T) {
	tenDS, err := tenantStore.Create(ctx, "System Delete Org", "system-delete-org")
	require.NoError(t, err)

	var systemRoleID string
	err = database.WithTenantConnection(ctx, rlsPool, tenDS.ID, func(ctx context.Context, q database.Querier) error {
		_, execErr := q.Exec(ctx,
			`INSERT INTO roles (tenant_id, name, permissions, is_system) VALUES (current_setting('app.current_tenant_id', true)::UUID, 'sys_locked', '["*"]'::jsonb, true)`)
		require.NoError(t, execErr)
		row := q.QueryRow(ctx, `SELECT id FROM roles WHERE name = 'sys_locked' AND tenant_id = current_setting('app.current_tenant_id', true)::UUID`)
		require.NoError(t, row.Scan(&systemRoleID))
		return nil
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/roles/"+systemRoleID, nil)
	req.SetPathValue("id", systemRoleID)
	req = withTenantIdentity(req, tenDS.ID)
	w := httptest.NewRecorder()

	wrapWithTenantCtx(handler.HandleDelete).ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
})

t.Run("Delete_AssignedRole_Rejected", func(t *testing.T) {
	tenDA, err := tenantStore.Create(ctx, "Delete Assigned Org", "delete-assigned-org")
	require.NoError(t, err)

	var roleID string
	err = database.WithTenantConnection(ctx, rlsPool, tenDA.ID, func(ctx context.Context, q database.Querier) error {
		role, createErr := tenant.NewRoleStore().Create(ctx, q, "in_use", []string{"agents:read"})
		require.NoError(t, createErr)
		roleID = role.ID
		user, createErr := tenant.NewUserStore().Create(ctx, q, "assigned@test.com", "Assigned")
		require.NoError(t, createErr)
		assignErr := tenant.NewRoleStore().AssignToUser(ctx, q, user.ID, roleID, "org", tenDA.ID)
		require.NoError(t, assignErr)
		return nil
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/roles/"+roleID, nil)
	req.SetPathValue("id", roleID)
	req = withTenantIdentity(req, tenDA.ID)
	w := httptest.NewRecorder()

	wrapWithTenantCtx(handler.HandleDelete).ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
})
```

**Step 3: Run tests to verify they fail**

Run: `cd /Users/fred/Documents/Valinor && go test ./internal/tenant/ -run "TestRoleHandler/Update|TestRoleHandler/Delete" -v`
Expected: compilation errors — `HandleUpdate`, `HandleDelete` not defined.

**Step 4: Add store methods — Update, Delete, CountAssignments**

Add to `internal/tenant/role_store.go`:

```go
// Update modifies a custom role's name and permissions. Returns ErrRoleIsSystem for system roles.
func (s *RoleStore) Update(ctx context.Context, q database.Querier, id string, name string, permissions []string) (*Role, error) {
	if strings.TrimSpace(name) == "" {
		return nil, ErrRoleNameEmpty
	}

	// Check is_system before update
	var isSystem bool
	err := q.QueryRow(ctx, `SELECT is_system FROM roles WHERE id = $1`, id).Scan(&isSystem)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrRoleNotFound
		}
		return nil, fmt.Errorf("checking role: %w", err)
	}
	if isSystem {
		return nil, ErrRoleIsSystem
	}

	permJSON, err := json.Marshal(permissions)
	if err != nil {
		return nil, fmt.Errorf("marshaling permissions: %w", err)
	}

	var role Role
	var permBytes []byte
	err = q.QueryRow(ctx,
		`UPDATE roles SET name = $1, permissions = $2 WHERE id = $3
		 RETURNING id, tenant_id, name, permissions, is_system, created_at`,
		name, permJSON, id,
	).Scan(&role.ID, &role.TenantID, &role.Name, &permBytes, &role.IsSystem, &role.CreatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "unique constraint") {
			return nil, fmt.Errorf("%w: %s", ErrRoleDuplicate, name)
		}
		return nil, fmt.Errorf("updating role: %w", err)
	}
	if err := json.Unmarshal(permBytes, &role.Permissions); err != nil {
		return nil, fmt.Errorf("unmarshaling permissions: %w", err)
	}
	return &role, nil
}

// Delete removes a custom role. Returns ErrRoleIsSystem for system roles,
// ErrRoleHasUsers if the role is assigned to any users.
func (s *RoleStore) Delete(ctx context.Context, q database.Querier, id string) error {
	var isSystem bool
	err := q.QueryRow(ctx, `SELECT is_system FROM roles WHERE id = $1`, id).Scan(&isSystem)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrRoleNotFound
		}
		return fmt.Errorf("checking role: %w", err)
	}
	if isSystem {
		return ErrRoleIsSystem
	}

	var count int
	err = q.QueryRow(ctx, `SELECT COUNT(*) FROM user_roles WHERE role_id = $1`, id).Scan(&count)
	if err != nil {
		return fmt.Errorf("counting assignments: %w", err)
	}
	if count > 0 {
		return ErrRoleHasUsers
	}

	_, err = q.Exec(ctx, `DELETE FROM roles WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("deleting role: %w", err)
	}
	return nil
}
```

**Step 5: Add handler methods — HandleUpdate and HandleDelete**

Add to `internal/tenant/role_handler.go`:

```go
// HandleUpdate updates a custom role's name and permissions.
func (h *RoleHandler) HandleUpdate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 10<<10)

	roleID := r.PathValue("id")
	if roleID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing role id"})
		return
	}

	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant context required"})
		return
	}

	var req struct {
		Name        string   `json:"name"`
		Permissions []string `json:"permissions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	// Reject wildcard in permissions for non-system roles
	for _, p := range req.Permissions {
		if p == "*" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": ErrWildcardDenied.Error()})
			return
		}
	}

	var role *Role
	err := database.WithTenantConnection(r.Context(), h.pool, tenantID, func(ctx context.Context, q database.Querier) error {
		var updateErr error
		role, updateErr = h.store.Update(ctx, q, roleID, req.Name, req.Permissions)
		return updateErr
	})
	if err != nil {
		if errors.Is(err, ErrRoleNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		if errors.Is(err, ErrRoleIsSystem) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
			return
		}
		if errors.Is(err, ErrRoleNameEmpty) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if errors.Is(err, ErrRoleDuplicate) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "role update failed"})
		return
	}

	writeJSON(w, http.StatusOK, role)
}

// HandleDelete deletes a custom role.
func (h *RoleHandler) HandleDelete(w http.ResponseWriter, r *http.Request) {
	roleID := r.PathValue("id")
	if roleID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing role id"})
		return
	}

	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant context required"})
		return
	}

	err := database.WithTenantConnection(r.Context(), h.pool, tenantID, func(ctx context.Context, q database.Querier) error {
		return h.store.Delete(ctx, q, roleID)
	})
	if err != nil {
		if errors.Is(err, ErrRoleNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		if errors.Is(err, ErrRoleIsSystem) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
			return
		}
		if errors.Is(err, ErrRoleHasUsers) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "role deletion failed"})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
```

**Step 6: Run tests to verify they pass**

Run: `cd /Users/fred/Documents/Valinor && go test ./internal/tenant/ -run TestRoleHandler -v`
Expected: all role handler tests pass.

**Step 7: Commit**

```bash
git add internal/tenant/role.go internal/tenant/role_store.go internal/tenant/role_handler.go internal/tenant/role_handler_test.go
git commit -m "feat: add HandleUpdate and HandleDelete for custom roles"
```

---

## Task 6: Evaluator Reload After Role Mutations

**Files:**
- Modify: `internal/tenant/role_handler.go`
- Modify: `internal/tenant/role_handler.go` (add `evaluator` field to `RoleHandler`)

**Step 1: Add evaluator to RoleHandler**

Update the `RoleHandler` struct and constructor:

```go
type RoleHandler struct {
	pool      *pgxpool.Pool
	store     *RoleStore
	userStore *UserStore
	deptStore *DepartmentStore
	evaluator RBACReloader
}

// RBACReloader is called after role mutations to refresh the evaluator.
type RBACReloader interface {
	ReloadRoles(ctx context.Context) error
}

func NewRoleHandler(pool *pgxpool.Pool, store *RoleStore, userStore *UserStore, deptStore *DepartmentStore, evaluator RBACReloader) *RoleHandler {
	return &RoleHandler{pool: pool, store: store, userStore: userStore, deptStore: deptStore, evaluator: evaluator}
}
```

**Step 2: Add reload calls to HandleCreate, HandleUpdate, HandleDelete**

After the successful DB write in each handler, add:

```go
if h.evaluator != nil {
	if err := h.evaluator.ReloadRoles(r.Context()); err != nil {
		slog.Error("failed to reload RBAC roles after mutation", "error", err)
		// Don't fail the request — the DB write succeeded
	}
}
```

Add this block:
- In `HandleCreate`: after `writeJSON(w, http.StatusCreated, role)` — actually, before the writeJSON, after the successful `WithTenantConnection` block.
- In `HandleUpdate`: same position — after successful update, before response.
- In `HandleDelete`: same position — after successful delete, before response.

**Step 3: Update all NewRoleHandler call sites**

In `cmd/valinor/main.go`, find the `NewRoleHandler` call and add `rbacEngine` as the last argument. In test files, pass `nil` for the evaluator parameter.

**Step 4: Run all tests**

Run: `cd /Users/fred/Documents/Valinor && go test ./... -short -count=1`
Expected: all pass.

**Step 5: Commit**

```bash
git add internal/tenant/role_handler.go cmd/valinor/main.go internal/tenant/role_handler_test.go
git commit -m "feat: reload RBAC evaluator after role create/update/delete"
```

---

## Task 7: Register New Routes in Server

**Files:**
- Modify: `internal/platform/server/server.go:214-241`

**Step 1: Add PUT and DELETE routes**

After the existing `GET /api/v1/roles` route (line ~224), add:

```go
protectedMux.Handle("PUT /api/v1/roles/{id}",
	rbac.RequirePermission(deps.RBAC, "users:manage", rbacOpts...)(
		http.HandlerFunc(deps.RoleHandler.HandleUpdate),
	),
)
protectedMux.Handle("DELETE /api/v1/roles/{id}",
	rbac.RequirePermission(deps.RBAC, "users:manage", rbacOpts...)(
		http.HandlerFunc(deps.RoleHandler.HandleDelete),
	),
)
```

**Step 2: Also add wildcard rejection to HandleCreate**

In `HandleCreate` in `internal/tenant/role_handler.go`, add the same wildcard check as `HandleUpdate` — before calling `h.store.Create`:

```go
for _, p := range req.Permissions {
	if p == "*" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": ErrWildcardDenied.Error()})
		return
	}
}
```

**Step 3: Verify compilation and run tests**

Run: `cd /Users/fred/Documents/Valinor && go build ./cmd/valinor/ && go test ./... -short -count=1`
Expected: builds and all tests pass.

**Step 4: Commit**

```bash
git add internal/platform/server/server.go internal/tenant/role_handler.go
git commit -m "feat: register PUT/DELETE role routes and add wildcard rejection to create"
```

---

## Task 8: Dashboard — New Query Hooks

**Files:**
- Modify: `dashboard/src/lib/queries/roles.ts`
- Modify: `dashboard/src/lib/types.ts`

**Step 1: Add UpdateRoleRequest type to `dashboard/src/lib/types.ts`**

```typescript
export interface UpdateRoleRequest {
  name: string
  permissions: string[]
}
```

**Step 2: Add fetch functions and mutation hooks to `dashboard/src/lib/queries/roles.ts`**

```typescript
export async function updateRole(
  accessToken: string,
  roleId: string,
  data: UpdateRoleRequest,
): Promise<Role> {
  return apiClient<Role>(`/api/v1/roles/${roleId}`, accessToken, {
    method: "PUT",
    body: JSON.stringify(data),
  })
}

export async function deleteRole(
  accessToken: string,
  roleId: string,
): Promise<void> {
  return apiClient<void>(`/api/v1/roles/${roleId}`, accessToken, {
    method: "DELETE",
  })
}

export function useUpdateRoleMutation() {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ roleId, data }: { roleId: string; data: UpdateRoleRequest }) =>
      updateRole(session!.accessToken, roleId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: roleKeys.list() })
    },
  })
}

export function useDeleteRoleMutation() {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (roleId: string) =>
      deleteRole(session!.accessToken, roleId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: roleKeys.list() })
    },
  })
}
```

Also add the `UpdateRoleRequest` import to the existing imports at the top of `roles.ts`.

**Step 3: Verify TypeScript compilation**

Run: `cd /Users/fred/Documents/Valinor/dashboard && npx tsc --noEmit`
Expected: no errors.

**Step 4: Commit**

```bash
git add dashboard/src/lib/types.ts dashboard/src/lib/queries/roles.ts
git commit -m "feat: add updateRole/deleteRole query hooks"
```

---

## Task 9: Dashboard — Permission Matrix Component

**Files:**
- Create: `dashboard/src/components/rbac/permission-matrix.tsx`
- Create: `dashboard/src/components/rbac/permission-matrix.test.tsx`

**Step 1: Define the permission grid data structure**

The matrix maps resources to their valid actions. This is a static config:

```typescript
// In permission-matrix.tsx
export const PERMISSION_GRID = [
  { resource: "Agents", permissions: ["agents:read", "agents:write", "agents:message"] },
  { resource: "Users", permissions: ["users:read", "users:write", "users:manage"] },
  { resource: "Departments", permissions: ["departments:read", "departments:write"] },
  { resource: "Connectors", permissions: ["connectors:read", "connectors:write"] },
  { resource: "Channels: Links", permissions: ["channels:links:read", "channels:links:write"] },
  { resource: "Channels: Messages", permissions: ["channels:messages:write"] },
  { resource: "Channels: Outbox", permissions: ["channels:outbox:read", "channels:outbox:write"] },
  { resource: "Channels: Providers", permissions: ["channels:providers:read", "channels:providers:write"] },
] as const

export const ALL_ACTIONS = ["read", "write", "message", "manage"] as const
```

**Step 2: Write failing tests**

In `dashboard/src/components/rbac/permission-matrix.test.tsx`:

```typescript
import { render, screen, fireEvent } from "@testing-library/react"
import { describe, it, expect, vi } from "vitest"
import { PermissionMatrix, PERMISSION_GRID } from "./permission-matrix"

describe("PermissionMatrix", () => {
  it("renders resource rows", () => {
    render(<PermissionMatrix permissions={[]} readonly={false} onChange={vi.fn()} />)
    for (const row of PERMISSION_GRID) {
      expect(screen.getByText(row.resource)).toBeInTheDocument()
    }
  })

  it("checks boxes matching current permissions", () => {
    render(<PermissionMatrix permissions={["agents:read", "users:write"]} readonly={false} onChange={vi.fn()} />)
    const agentsRead = screen.getByTestId("perm-agents:read")
    expect(agentsRead).toBeChecked()
    const usersWrite = screen.getByTestId("perm-users:write")
    expect(usersWrite).toBeChecked()
    const agentsWrite = screen.getByTestId("perm-agents:write")
    expect(agentsWrite).not.toBeChecked()
  })

  it("disables all checkboxes when readonly", () => {
    render(<PermissionMatrix permissions={["agents:read"]} readonly={true} onChange={vi.fn()} />)
    const checkbox = screen.getByTestId("perm-agents:read")
    expect(checkbox).toBeDisabled()
  })

  it("calls onChange with toggled permission", () => {
    const onChange = vi.fn()
    render(<PermissionMatrix permissions={["agents:read"]} readonly={false} onChange={onChange} />)
    fireEvent.click(screen.getByTestId("perm-agents:write"))
    expect(onChange).toHaveBeenCalledWith(["agents:read", "agents:write"])
  })

  it("calls onChange removing unchecked permission", () => {
    const onChange = vi.fn()
    render(<PermissionMatrix permissions={["agents:read", "agents:write"]} readonly={false} onChange={onChange} />)
    fireEvent.click(screen.getByTestId("perm-agents:read"))
    expect(onChange).toHaveBeenCalledWith(["agents:write"])
  })
})
```

**Step 3: Run tests to verify they fail**

Run: `cd /Users/fred/Documents/Valinor/dashboard && npx vitest run src/components/rbac/permission-matrix.test.tsx`
Expected: fails — file not found.

**Step 4: Implement PermissionMatrix component**

Create `dashboard/src/components/rbac/permission-matrix.tsx`:

```typescript
"use client"

export const PERMISSION_GRID = [
  { resource: "Agents", permissions: ["agents:read", "agents:write", "agents:message"] },
  { resource: "Users", permissions: ["users:read", "users:write", "users:manage"] },
  { resource: "Departments", permissions: ["departments:read", "departments:write"] },
  { resource: "Connectors", permissions: ["connectors:read", "connectors:write"] },
  { resource: "Channels: Links", permissions: ["channels:links:read", "channels:links:write"] },
  { resource: "Channels: Messages", permissions: ["channels:messages:write"] },
  { resource: "Channels: Outbox", permissions: ["channels:outbox:read", "channels:outbox:write"] },
  { resource: "Channels: Providers", permissions: ["channels:providers:read", "channels:providers:write"] },
] as const

const ALL_ACTIONS = ["read", "write", "message", "manage"] as const

function extractAction(permission: string): string {
  const parts = permission.split(":")
  return parts[parts.length - 1]
}

interface PermissionMatrixProps {
  permissions: string[]
  readonly: boolean
  onChange: (permissions: string[]) => void
}

export function PermissionMatrix({ permissions, readonly, onChange }: PermissionMatrixProps) {
  const permSet = new Set(permissions)

  function handleToggle(perm: string) {
    if (readonly) return
    const next = new Set(permSet)
    if (next.has(perm)) {
      next.delete(perm)
    } else {
      next.add(perm)
    }
    onChange(Array.from(next))
  }

  // Build a lookup: which actions are valid for which resource row
  const actionColumns = ALL_ACTIONS

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-zinc-200">
            <th className="py-2 pr-4 text-left font-medium text-zinc-600">Resource</th>
            {actionColumns.map((action) => (
              <th key={action} className="px-3 py-2 text-center font-medium text-zinc-600 capitalize">
                {action}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {PERMISSION_GRID.map((row) => {
            const rowActions = new Map(
              row.permissions.map((p) => [extractAction(p), p])
            )
            return (
              <tr key={row.resource} className="border-b border-zinc-100">
                <td className="py-2.5 pr-4 font-medium text-zinc-800">{row.resource}</td>
                {actionColumns.map((action) => {
                  const perm = rowActions.get(action)
                  if (!perm) {
                    return <td key={action} className="px-3 py-2.5 text-center" />
                  }
                  return (
                    <td key={action} className="px-3 py-2.5 text-center">
                      <input
                        type="checkbox"
                        data-testid={`perm-${perm}`}
                        checked={permSet.has(perm)}
                        disabled={readonly}
                        onChange={() => handleToggle(perm)}
                        className="h-4 w-4 rounded border-zinc-300 text-zinc-900 focus:ring-zinc-500 disabled:opacity-50"
                      />
                    </td>
                  )
                })}
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
```

**Step 5: Run tests to verify they pass**

Run: `cd /Users/fred/Documents/Valinor/dashboard && npx vitest run src/components/rbac/permission-matrix.test.tsx`
Expected: all 5 tests pass.

**Step 6: Commit**

```bash
git add dashboard/src/components/rbac/permission-matrix.tsx dashboard/src/components/rbac/permission-matrix.test.tsx
git commit -m "feat: add PermissionMatrix checkbox grid component"
```

---

## Task 10: Dashboard — Role List and Role Detail Components

**Files:**
- Create: `dashboard/src/components/rbac/role-list.tsx`
- Create: `dashboard/src/components/rbac/role-detail.tsx`

**Step 1: Implement RoleList**

Create `dashboard/src/components/rbac/role-list.tsx`:

```typescript
"use client"

import { useRolesQuery } from "@/lib/queries/roles"
import { ShieldCheck } from "@phosphor-icons/react"
import type { Role } from "@/lib/types"

interface RoleListProps {
  selectedId: string | null
  onSelect: (role: Role) => void
}

export function RoleList({ selectedId, onSelect }: RoleListProps) {
  const { data: roles, isLoading } = useRolesQuery()

  if (isLoading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="h-14 animate-pulse rounded-lg bg-zinc-100" />
        ))}
      </div>
    )
  }

  if (!roles?.length) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-zinc-400">
        <ShieldCheck size={32} />
        <p className="mt-2 text-sm">No roles found.</p>
      </div>
    )
  }

  return (
    <div className="space-y-1">
      {roles.map((role) => (
        <button
          key={role.id}
          onClick={() => onSelect(role)}
          className={`flex w-full items-center justify-between rounded-lg px-3 py-2.5 text-left text-sm transition-colors ${
            selectedId === role.id
              ? "bg-zinc-900 text-white"
              : "text-zinc-700 hover:bg-zinc-100"
          }`}
        >
          <div className="flex items-center gap-2">
            <span className="font-medium">{role.name}</span>
            {role.is_system && (
              <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider ${
                selectedId === role.id
                  ? "bg-zinc-700 text-zinc-300"
                  : "bg-zinc-200 text-zinc-500"
              }`}>
                System
              </span>
            )}
          </div>
          <span className={`text-xs ${
            selectedId === role.id ? "text-zinc-400" : "text-zinc-400"
          }`}>
            {role.permissions.includes("*") ? "All" : `${role.permissions.length} perms`}
          </span>
        </button>
      ))}
    </div>
  )
}
```

**Step 2: Implement RoleDetail**

Create `dashboard/src/components/rbac/role-detail.tsx`:

```typescript
"use client"

import { useState, useEffect } from "react"
import { useUpdateRoleMutation, useDeleteRoleMutation } from "@/lib/queries/roles"
import { PermissionMatrix } from "./permission-matrix"
import { FloppyDisk, Trash } from "@phosphor-icons/react"
import type { Role } from "@/lib/types"

interface RoleDetailProps {
  role: Role
  onDeleted: () => void
}

export function RoleDetail({ role, onDeleted }: RoleDetailProps) {
  const [permissions, setPermissions] = useState<string[]>(role.permissions)
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)
  const updateMutation = useUpdateRoleMutation()
  const deleteMutation = useDeleteRoleMutation()

  const isDirty = JSON.stringify(permissions.sort()) !== JSON.stringify([...role.permissions].sort())
  const isSystem = role.is_system
  const isWildcard = role.permissions.includes("*")

  // Reset local state when selected role changes
  useEffect(() => {
    setPermissions(role.permissions)
    setShowDeleteConfirm(false)
  }, [role.id, role.permissions])

  function handleSave() {
    updateMutation.mutate(
      { roleId: role.id, data: { name: role.name, permissions } },
    )
  }

  function handleDelete() {
    deleteMutation.mutate(role.id, {
      onSuccess: () => onDeleted(),
    })
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold text-zinc-900">{role.name}</h2>
          <p className="text-xs text-zinc-400">
            Created {new Date(role.created_at).toLocaleDateString()}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {!isSystem && (
            <>
              {isDirty && (
                <button
                  onClick={handleSave}
                  disabled={updateMutation.isPending}
                  className="flex items-center gap-1.5 rounded-lg bg-zinc-900 px-3 py-1.5 text-sm font-medium text-white transition-colors hover:bg-zinc-800 disabled:opacity-50"
                >
                  <FloppyDisk size={14} />
                  {updateMutation.isPending ? "Saving…" : "Save"}
                </button>
              )}
              <button
                onClick={() => setShowDeleteConfirm(true)}
                disabled={deleteMutation.isPending}
                className="flex items-center gap-1.5 rounded-lg border border-red-200 px-3 py-1.5 text-sm font-medium text-red-600 transition-colors hover:bg-red-50 disabled:opacity-50"
              >
                <Trash size={14} />
                Delete
              </button>
            </>
          )}
        </div>
      </div>

      {isSystem && (
        <div className="rounded-lg border border-zinc-200 bg-zinc-50 px-4 py-3 text-sm text-zinc-600">
          System role — permissions are read-only.
        </div>
      )}

      {isWildcard ? (
        <div className="rounded-lg border border-zinc-200 bg-zinc-50 px-4 py-3 text-sm text-zinc-600">
          This role has wildcard access — all permissions are granted.
        </div>
      ) : (
        <PermissionMatrix
          permissions={permissions}
          readonly={isSystem}
          onChange={setPermissions}
        />
      )}

      {updateMutation.isError && (
        <p className="text-sm text-red-600">
          Failed to update: {(updateMutation.error as Error).message}
        </p>
      )}

      {showDeleteConfirm && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4">
          <p className="text-sm text-red-800">
            Delete role <strong>{role.name}</strong>? This cannot be undone.
            The role must not be assigned to any users.
          </p>
          <div className="mt-3 flex gap-2">
            <button
              onClick={handleDelete}
              disabled={deleteMutation.isPending}
              className="rounded-lg bg-red-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-red-700 disabled:opacity-50"
            >
              {deleteMutation.isPending ? "Deleting…" : "Confirm delete"}
            </button>
            <button
              onClick={() => setShowDeleteConfirm(false)}
              className="rounded-lg border border-zinc-200 px-3 py-1.5 text-sm text-zinc-600 hover:bg-zinc-50"
            >
              Cancel
            </button>
          </div>
          {deleteMutation.isError && (
            <p className="mt-2 text-sm text-red-600">
              {(deleteMutation.error as Error).message}
            </p>
          )}
        </div>
      )}
    </div>
  )
}
```

**Step 3: Verify TypeScript compilation**

Run: `cd /Users/fred/Documents/Valinor/dashboard && npx tsc --noEmit`
Expected: no errors.

**Step 4: Commit**

```bash
git add dashboard/src/components/rbac/role-list.tsx dashboard/src/components/rbac/role-detail.tsx
git commit -m "feat: add RoleList and RoleDetail components"
```

---

## Task 11: Dashboard — Create Role Dialog

**Files:**
- Create: `dashboard/src/components/rbac/create-role-dialog.tsx`

**Step 1: Implement CreateRoleDialog**

Create `dashboard/src/components/rbac/create-role-dialog.tsx`. Follow the same pattern as `create-user-form.tsx` and `create-tenant-form.tsx` — a dialog/sheet with a form:

```typescript
"use client"

import { useState } from "react"
import { useSession } from "next-auth/react"
import { useQueryClient } from "@tanstack/react-query"
import { roleKeys } from "@/lib/queries/roles"
import { apiClient } from "@/lib/api-client"
import { PermissionMatrix } from "./permission-matrix"
import type { Role } from "@/lib/types"

interface CreateRoleDialogProps {
  open: boolean
  onClose: () => void
  onCreated: (role: Role) => void
}

export function CreateRoleDialog({ open, onClose, onCreated }: CreateRoleDialogProps) {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  const [name, setName] = useState("")
  const [permissions, setPermissions] = useState<string[]>([])
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  if (!open) return null

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!name.trim()) {
      setError("Role name is required")
      return
    }
    setError(null)
    setSubmitting(true)
    try {
      const role = await apiClient<Role>("/api/v1/roles", session!.accessToken, {
        method: "POST",
        body: JSON.stringify({ name: name.trim(), permissions }),
      })
      queryClient.invalidateQueries({ queryKey: roleKeys.list() })
      setName("")
      setPermissions([])
      onCreated(role)
    } catch (err) {
      setError((err as Error).message)
    } finally {
      setSubmitting(false)
    }
  }

  function handleClose() {
    setName("")
    setPermissions([])
    setError(null)
    onClose()
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="w-full max-w-2xl rounded-xl bg-white p-6 shadow-xl">
        <h2 className="text-lg font-semibold text-zinc-900">Create Role</h2>
        <form onSubmit={handleSubmit} className="mt-4 space-y-4">
          <div>
            <label htmlFor="role-name" className="block text-sm font-medium text-zinc-700">
              Name
            </label>
            <input
              id="role-name"
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. analyst"
              className="mt-1 w-full rounded-lg border border-zinc-300 px-3 py-2 text-sm focus:border-zinc-500 focus:outline-none focus:ring-1 focus:ring-zinc-500"
            />
          </div>
          <div>
            <p className="mb-2 text-sm font-medium text-zinc-700">Permissions</p>
            <PermissionMatrix permissions={permissions} readonly={false} onChange={setPermissions} />
          </div>
          {error && <p className="text-sm text-red-600">{error}</p>}
          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={handleClose}
              className="rounded-lg border border-zinc-200 px-4 py-2 text-sm text-zinc-600 hover:bg-zinc-50"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800 disabled:opacity-50"
            >
              {submitting ? "Creating…" : "Create role"}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
```

**Step 2: Verify TypeScript compilation**

Run: `cd /Users/fred/Documents/Valinor/dashboard && npx tsc --noEmit`
Expected: no errors.

**Step 3: Commit**

```bash
git add dashboard/src/components/rbac/create-role-dialog.tsx
git commit -m "feat: add CreateRoleDialog component"
```

---

## Task 12: Dashboard — RBAC Page

**Files:**
- Create: `dashboard/src/app/(dashboard)/rbac/page.tsx`

**Step 1: Implement the RBAC page**

```typescript
import { RBACView } from "@/components/rbac/rbac-view"
import { ShieldCheck } from "@phosphor-icons/react/dist/ssr"

export default function RBACPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">RBAC</h1>
        <p className="mt-1 text-sm text-zinc-500">Manage roles and permissions.</p>
      </div>
      <RBACView />
    </div>
  )
}
```

**Step 2: Create the RBACView client component**

Create `dashboard/src/components/rbac/rbac-view.tsx`:

```typescript
"use client"

import { useState } from "react"
import { RoleList } from "./role-list"
import { RoleDetail } from "./role-detail"
import { CreateRoleDialog } from "./create-role-dialog"
import { Plus, ShieldCheck } from "@phosphor-icons/react"
import type { Role } from "@/lib/types"

export function RBACView() {
  const [selectedRole, setSelectedRole] = useState<Role | null>(null)
  const [showCreate, setShowCreate] = useState(false)

  return (
    <div className="grid grid-cols-1 gap-6 lg:grid-cols-[320px_1fr]">
      {/* Left panel — role list */}
      <div className="rounded-xl border border-zinc-200 bg-white p-4">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-zinc-900">Roles</h2>
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-1 rounded-lg bg-zinc-900 px-2.5 py-1.5 text-xs font-medium text-white transition-colors hover:bg-zinc-800"
          >
            <Plus size={12} />
            Create
          </button>
        </div>
        <RoleList
          selectedId={selectedRole?.id ?? null}
          onSelect={setSelectedRole}
        />
      </div>

      {/* Right panel — role detail */}
      <div className="rounded-xl border border-zinc-200 bg-white p-6">
        {selectedRole ? (
          <RoleDetail
            role={selectedRole}
            onDeleted={() => setSelectedRole(null)}
          />
        ) : (
          <div className="flex flex-col items-center justify-center py-20 text-zinc-400">
            <ShieldCheck size={40} />
            <p className="mt-3 text-sm">Select a role to view permissions.</p>
          </div>
        )}
      </div>

      <CreateRoleDialog
        open={showCreate}
        onClose={() => setShowCreate(false)}
        onCreated={(role) => {
          setShowCreate(false)
          setSelectedRole(role)
        }}
      />
    </div>
  )
}
```

**Step 3: Verify TypeScript compilation**

Run: `cd /Users/fred/Documents/Valinor/dashboard && npx tsc --noEmit`
Expected: no errors.

**Step 4: Commit**

```bash
git add dashboard/src/app/\(dashboard\)/rbac/page.tsx dashboard/src/components/rbac/rbac-view.tsx
git commit -m "feat: add /rbac page with two-panel role management view"
```

---

## Task 13: Keep RoleDetail in Sync After Save

**Files:**
- Modify: `dashboard/src/components/rbac/rbac-view.tsx`
- Modify: `dashboard/src/components/rbac/role-detail.tsx`

The `RoleDetail` receives a `Role` object from the list selection. After saving, the query cache updates but the selected role prop is stale. Fix this by having `RBACView` re-derive the selected role from the query data.

**Step 1: Update RBACView to keep selection in sync**

```typescript
// In rbac-view.tsx, add:
import { useRolesQuery } from "@/lib/queries/roles"

// Inside the component:
const { data: roles } = useRolesQuery()
const [selectedId, setSelectedId] = useState<string | null>(null)
const [showCreate, setShowCreate] = useState(false)

// Derive selected role from fresh query data
const selectedRole = roles?.find((r) => r.id === selectedId) ?? null
```

Replace `selectedRole` / `setSelectedRole` usage:
- `onSelect` becomes `(role) => setSelectedId(role.id)`
- `onDeleted` becomes `() => setSelectedId(null)`
- `onCreated` becomes `(role) => { setShowCreate(false); setSelectedId(role.id) }`

**Step 2: Verify TypeScript compilation**

Run: `cd /Users/fred/Documents/Valinor/dashboard && npx tsc --noEmit`
Expected: no errors.

**Step 3: Commit**

```bash
git add dashboard/src/components/rbac/rbac-view.tsx
git commit -m "fix: keep selected role in sync with query cache after save"
```

---

## Task 14: Frontend Tests — RBACView and RoleList

**Files:**
- Create: `dashboard/src/components/rbac/rbac-view.test.tsx`

**Step 1: Write RBACView smoke test**

```typescript
import { render, screen } from "@testing-library/react"
import { describe, it, expect, vi } from "vitest"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { SessionProvider } from "next-auth/react"

// Mock the queries module
vi.mock("@/lib/queries/roles", () => ({
  useRolesQuery: () => ({
    data: [
      { id: "1", name: "org_admin", permissions: ["*"], is_system: true, tenant_id: "t1", created_at: "2025-01-01" },
      { id: "2", name: "custom", permissions: ["agents:read"], is_system: false, tenant_id: "t1", created_at: "2025-01-01" },
    ],
    isLoading: false,
  }),
  useUpdateRoleMutation: () => ({ mutate: vi.fn(), isPending: false, isError: false }),
  useDeleteRoleMutation: () => ({ mutate: vi.fn(), isPending: false, isError: false }),
  roleKeys: { list: () => ["roles", "list"] },
}))

import { RBACView } from "./rbac-view"

function wrapper({ children }: { children: React.ReactNode }) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return (
    <SessionProvider session={{ user: { name: "test" }, expires: "2099-01-01" } as any}>
      <QueryClientProvider client={qc}>{children}</QueryClientProvider>
    </SessionProvider>
  )
}

describe("RBACView", () => {
  it("renders role list with system and custom roles", () => {
    render(<RBACView />, { wrapper })
    expect(screen.getByText("org_admin")).toBeInTheDocument()
    expect(screen.getByText("custom")).toBeInTheDocument()
    expect(screen.getByText("System")).toBeInTheDocument()
  })

  it("shows placeholder when no role selected", () => {
    render(<RBACView />, { wrapper })
    expect(screen.getByText("Select a role to view permissions.")).toBeInTheDocument()
  })
})
```

**Step 2: Run tests**

Run: `cd /Users/fred/Documents/Valinor/dashboard && npx vitest run src/components/rbac/`
Expected: all tests pass.

**Step 3: Commit**

```bash
git add dashboard/src/components/rbac/rbac-view.test.tsx
git commit -m "test: add RBACView smoke tests"
```

---

## Task 15: Full Verification

**Step 1: Run Go tests**

Run: `cd /Users/fred/Documents/Valinor && go test ./... -short -count=1`
Expected: all pass.

**Step 2: Run dashboard tests**

Run: `cd /Users/fred/Documents/Valinor/dashboard && npx vitest run`
Expected: all pass.

**Step 3: TypeScript check**

Run: `cd /Users/fred/Documents/Valinor/dashboard && npx tsc --noEmit`
Expected: no errors.

**Step 4: Build dashboard**

Run: `cd /Users/fred/Documents/Valinor/dashboard && npm run build`
Expected: builds successfully.

**Step 5: Build Go binary**

Run: `cd /Users/fred/Documents/Valinor && go build ./cmd/valinor/`
Expected: builds successfully.
