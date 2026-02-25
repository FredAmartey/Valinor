# Phase 3 P2: Department Hierarchy, User Management & Role Assignment — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build tenant-scoped CRUD APIs for departments, users, and roles — completing the tenant management module so that tenants can set up their organizational structure, invite users, and assign role-based permissions.

**Architecture:** All operations are tenant-scoped using the `WithTenantConnection` + RLS pattern. New stores accept `database.Querier` (not pool) so they can run inside an RLS-scoped connection. Handlers hold the pool and call `WithTenantConnection` themselves, then delegate to stores. Routes are protected by RBAC middleware (`RequirePermission`). This is the same pattern used by `handleListAgents` in `server.go:176-219`.

**Tech Stack:** Go 1.25, PostgreSQL 16 with RLS, pgx/v5, testcontainers-go, httptest, testify

**Key pattern — RLS-scoped stores (new for P2):**

```
Handler (holds pool)
  → middleware.GetTenantID(ctx)
  → database.WithTenantConnection(ctx, pool, tenantID, func(ctx, q) {
        store.Method(ctx, q, ...)   // store accepts Querier, not pool
    })
```

This differs from the existing `tenant.Store` which uses `s.pool.QueryRow()` directly because the `tenants` table has no RLS policy. All P2 stores operate on RLS-protected tables.

**API routes added by this plan:**

| Method | Path | Permission | Description |
|--------|------|-----------|-------------|
| POST | `/api/v1/departments` | `departments:write` | Create department |
| GET | `/api/v1/departments/{id}` | `departments:read` | Get department |
| GET | `/api/v1/departments` | `departments:read` | List departments |
| POST | `/api/v1/users` | `users:write` | Create user |
| GET | `/api/v1/users/{id}` | `users:read` | Get user |
| GET | `/api/v1/users` | `users:read` | List users |
| POST | `/api/v1/users/{id}/departments` | `users:write` | Add user to department |
| DELETE | `/api/v1/users/{id}/departments/{deptId}` | `users:write` | Remove from department |
| POST | `/api/v1/roles` | `users:manage` | Create role |
| GET | `/api/v1/roles` | `users:read` | List roles |
| POST | `/api/v1/users/{id}/roles` | `users:manage` | Assign role |
| DELETE | `/api/v1/users/{id}/roles` | `users:manage` | Remove role |

---

### Task 1: Migration — Junction Table RLS Policies

**Problem:** `user_roles` has RLS enabled (migration 000001) but NO policy — queries return 0 rows for non-superusers. `user_departments` has no RLS at all. Both need policies before P2 stores can query them through `WithTenantConnection`.

**Files:**
- Create: `migrations/000006_junction_rls.up.sql`
- Create: `migrations/000006_junction_rls.down.sql`
- Modify: `internal/platform/database/rls_test.go` (extend `seedTwoTenants` + add junction tables to `TestRLS_TenantIsolation`)

**Step 1: Write the migration files**

`migrations/000006_junction_rls.up.sql`:

```sql
-- user_roles: RLS enabled in 000001 but no policy exists — add one
CREATE POLICY tenant_isolation ON user_roles
    USING (EXISTS (
        SELECT 1 FROM users
        WHERE users.id = user_roles.user_id
        AND users.tenant_id = current_setting('app.current_tenant_id', true)::UUID
    ));

-- user_departments: no RLS at all — enable and add policy
ALTER TABLE user_departments ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON user_departments
    USING (EXISTS (
        SELECT 1 FROM users
        WHERE users.id = user_departments.user_id
        AND users.tenant_id = current_setting('app.current_tenant_id', true)::UUID
    ));
```

`migrations/000006_junction_rls.down.sql`:

```sql
DROP POLICY IF EXISTS tenant_isolation ON user_roles;
DROP POLICY IF EXISTS tenant_isolation ON user_departments;
ALTER TABLE user_departments DISABLE ROW LEVEL SECURITY;
```

**Step 2: Extend `seedTwoTenants` and RLS test**

In `internal/platform/database/rls_test.go`, modify `seedTwoTenants` to also insert junction table rows. After the existing role inserts, add:

```go
// Look up IDs needed for junction tables
var userAID, userBID string
err = pool.QueryRow(ctx, "SELECT id FROM users WHERE tenant_id = $1", tenantA).Scan(&userAID)
require.NoError(t, err)
err = pool.QueryRow(ctx, "SELECT id FROM users WHERE tenant_id = $1", tenantB).Scan(&userBID)
require.NoError(t, err)

var roleAID, roleBID string
err = pool.QueryRow(ctx, "SELECT id FROM roles WHERE tenant_id = $1", tenantA).Scan(&roleAID)
require.NoError(t, err)
err = pool.QueryRow(ctx, "SELECT id FROM roles WHERE tenant_id = $1", tenantB).Scan(&roleBID)
require.NoError(t, err)

var deptAID, deptBID string
err = pool.QueryRow(ctx, "SELECT id FROM departments WHERE tenant_id = $1", tenantA).Scan(&deptAID)
require.NoError(t, err)
err = pool.QueryRow(ctx, "SELECT id FROM departments WHERE tenant_id = $1", tenantB).Scan(&deptBID)
require.NoError(t, err)

// user_roles
_, err = pool.Exec(ctx,
    "INSERT INTO user_roles (user_id, role_id, scope_type, scope_id) VALUES ($1, $2, 'org', $3)",
    userAID, roleAID, tenantA)
require.NoError(t, err)
_, err = pool.Exec(ctx,
    "INSERT INTO user_roles (user_id, role_id, scope_type, scope_id) VALUES ($1, $2, 'org', $3)",
    userBID, roleBID, tenantB)
require.NoError(t, err)

// user_departments
_, err = pool.Exec(ctx,
    "INSERT INTO user_departments (user_id, department_id) VALUES ($1, $2)",
    userAID, deptAID)
require.NoError(t, err)
_, err = pool.Exec(ctx,
    "INSERT INTO user_departments (user_id, department_id) VALUES ($1, $2)",
    userBID, deptBID)
require.NoError(t, err)
```

Then add `"user_roles"` and `"user_departments"` to the `tables` slice in `TestRLS_TenantIsolation`:

```go
tables := []string{
    "users", "departments", "roles", "agent_instances", "connectors", "resource_policies",
    "user_roles", "user_departments",
}
```

**Step 3: Run the RLS tests**

Run: `go test ./internal/platform/database/ -run TestRLS -v -count=1`
Expected: PASS — junction tables show 1 row per tenant, 0 without context.

**Step 4: Commit**

```bash
git add migrations/000006_junction_rls.up.sql migrations/000006_junction_rls.down.sql internal/platform/database/rls_test.go
git commit -m "feat: add RLS policies for user_roles and user_departments junction tables"
```

---

### Task 2: Department Types + Validation

**Files:**
- Create: `internal/tenant/department.go`

**Step 1: Write department types and validation**

```go
package tenant

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrDepartmentNotFound = errors.New("department not found")
	ErrDepartmentNameEmpty = errors.New("department name is required")
)

// Department represents a department within a tenant.
type Department struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Name      string    `json:"name"`
	ParentID  *string   `json:"parent_id,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// ValidateDepartmentName checks that a department name is non-empty and within length limits.
func ValidateDepartmentName(name string) error {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return ErrDepartmentNameEmpty
	}
	if len(trimmed) > 255 {
		return fmt.Errorf("%w: must not exceed 255 characters", ErrDepartmentNameEmpty)
	}
	return nil
}
```

**Step 2: Verify compilation**

Run: `go build ./internal/tenant/`
Expected: Compiles successfully.

**Step 3: Commit**

```bash
git add internal/tenant/department.go
git commit -m "feat: add Department type and name validation"
```

---

### Task 3: Department Store (TDD)

**Files:**
- Create: `internal/tenant/department_store_test.go`
- Create: `internal/tenant/department_store.go`

**Step 1: Write the failing tests**

`internal/tenant/department_store_test.go`:

```go
package tenant_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/platform/database"
	"github.com/valinor-ai/valinor/internal/tenant"
)

func TestDepartmentStore(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	tenantStore := tenant.NewStore(pool)
	ten, err := tenantStore.Create(ctx, "Test Org", "test-org")
	require.NoError(t, err)

	store := tenant.NewDepartmentStore()

	t.Run("Create", func(t *testing.T) {
		err := database.WithTenantConnection(ctx, pool, ten.ID, func(ctx context.Context, q database.Querier) error {
			dept, createErr := store.Create(ctx, q, "Engineering", nil)
			require.NoError(t, createErr)
			assert.NotEmpty(t, dept.ID)
			assert.Equal(t, ten.ID, dept.TenantID)
			assert.Equal(t, "Engineering", dept.Name)
			assert.Nil(t, dept.ParentID)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("Create_WithParent", func(t *testing.T) {
		err := database.WithTenantConnection(ctx, pool, ten.ID, func(ctx context.Context, q database.Querier) error {
			parent, createErr := store.Create(ctx, q, "Product", nil)
			require.NoError(t, createErr)

			child, createErr := store.Create(ctx, q, "Backend", &parent.ID)
			require.NoError(t, createErr)
			assert.Equal(t, &parent.ID, child.ParentID)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("Create_EmptyName", func(t *testing.T) {
		err := database.WithTenantConnection(ctx, pool, ten.ID, func(ctx context.Context, q database.Querier) error {
			_, createErr := store.Create(ctx, q, "", nil)
			assert.ErrorIs(t, createErr, tenant.ErrDepartmentNameEmpty)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("GetByID", func(t *testing.T) {
		err := database.WithTenantConnection(ctx, pool, ten.ID, func(ctx context.Context, q database.Querier) error {
			created, createErr := store.Create(ctx, q, "Scouting", nil)
			require.NoError(t, createErr)

			got, getErr := store.GetByID(ctx, q, created.ID)
			require.NoError(t, getErr)
			assert.Equal(t, created.ID, got.ID)
			assert.Equal(t, "Scouting", got.Name)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("GetByID_NotFound", func(t *testing.T) {
		err := database.WithTenantConnection(ctx, pool, ten.ID, func(ctx context.Context, q database.Querier) error {
			_, getErr := store.GetByID(ctx, q, "00000000-0000-0000-0000-000000000000")
			assert.ErrorIs(t, getErr, tenant.ErrDepartmentNotFound)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("List", func(t *testing.T) {
		// Create a fresh tenant to avoid interference from other subtests
		ten2, err := tenantStore.Create(ctx, "List Org", "list-org")
		require.NoError(t, err)

		err = database.WithTenantConnection(ctx, pool, ten2.ID, func(ctx context.Context, q database.Querier) error {
			_, createErr := store.Create(ctx, q, "First Team", nil)
			require.NoError(t, createErr)
			_, createErr = store.Create(ctx, q, "Academy", nil)
			require.NoError(t, createErr)

			departments, listErr := store.List(ctx, q)
			require.NoError(t, listErr)
			assert.Len(t, departments, 2)
			return nil
		})
		require.NoError(t, err)
	})
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/tenant/ -run TestDepartmentStore -v -count=1`
Expected: FAIL — `NewDepartmentStore` undefined.

**Step 3: Implement the department store**

`internal/tenant/department_store.go`:

```go
package tenant

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

// DepartmentStore handles department database operations.
// Methods accept database.Querier so they can run inside WithTenantConnection.
type DepartmentStore struct{}

// NewDepartmentStore creates a new department store.
func NewDepartmentStore() *DepartmentStore {
	return &DepartmentStore{}
}

// Create inserts a new department. The tenant_id is read from the RLS session variable.
// If parentID is provided, it must reference a department visible through RLS (same tenant).
func (s *DepartmentStore) Create(ctx context.Context, q database.Querier, name string, parentID *string) (*Department, error) {
	if err := ValidateDepartmentName(name); err != nil {
		return nil, err
	}

	// Validate parent exists in this tenant (FK checks bypass RLS, so we verify manually)
	if parentID != nil {
		_, err := s.GetByID(ctx, q, *parentID)
		if err != nil {
			return nil, fmt.Errorf("invalid parent department: %w", err)
		}
	}

	var dept Department
	err := q.QueryRow(ctx,
		`INSERT INTO departments (tenant_id, name, parent_id)
		 VALUES (current_setting('app.current_tenant_id', true)::UUID, $1, $2)
		 RETURNING id, tenant_id, name, parent_id, created_at`,
		name, parentID,
	).Scan(&dept.ID, &dept.TenantID, &dept.Name, &dept.ParentID, &dept.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("creating department: %w", err)
	}
	return &dept, nil
}

// GetByID retrieves a department by ID. RLS ensures tenant isolation.
func (s *DepartmentStore) GetByID(ctx context.Context, q database.Querier, id string) (*Department, error) {
	var dept Department
	err := q.QueryRow(ctx,
		`SELECT id, tenant_id, name, parent_id, created_at
		 FROM departments WHERE id = $1`,
		id,
	).Scan(&dept.ID, &dept.TenantID, &dept.Name, &dept.ParentID, &dept.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrDepartmentNotFound
		}
		return nil, fmt.Errorf("getting department: %w", err)
	}
	return &dept, nil
}

// List returns all departments visible through RLS (current tenant).
func (s *DepartmentStore) List(ctx context.Context, q database.Querier) ([]Department, error) {
	rows, err := q.Query(ctx,
		`SELECT id, tenant_id, name, parent_id, created_at
		 FROM departments ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("listing departments: %w", err)
	}
	defer rows.Close()

	var departments []Department
	for rows.Next() {
		var d Department
		if err := rows.Scan(&d.ID, &d.TenantID, &d.Name, &d.ParentID, &d.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning department: %w", err)
		}
		departments = append(departments, d)
	}
	return departments, rows.Err()
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/tenant/ -run TestDepartmentStore -v -count=1`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/tenant/department_store.go internal/tenant/department_store_test.go
git commit -m "feat: add department store with Create/GetByID/List (TDD)"
```

---

### Task 4: Department HTTP Handler (TDD)

**Files:**
- Create: `internal/tenant/department_handler_test.go`
- Create: `internal/tenant/department_handler.go`

**Step 1: Write the failing tests**

`internal/tenant/department_handler_test.go`:

```go
package tenant_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
	"github.com/valinor-ai/valinor/internal/tenant"
)

// withTenantIdentity sets auth identity and tenant context for handler tests.
func withTenantIdentity(req *http.Request, tenantID string) *http.Request {
	identity := &auth.Identity{
		UserID:   "test-user",
		TenantID: tenantID,
		Roles:    []string{"org_admin"},
	}
	return req.WithContext(auth.WithIdentity(req.Context(), identity))
}

// wrapWithTenantCtx wraps a handler with TenantContext middleware so
// middleware.GetTenantID works in tests.
func wrapWithTenantCtx(h http.HandlerFunc) http.Handler {
	return middleware.TenantContext(h)
}

func TestDepartmentHandler(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	tenantStore := tenant.NewStore(pool)
	ten, err := tenantStore.Create(ctx, "Handler Org", "handler-org")
	require.NoError(t, err)

	handler := tenant.NewDepartmentHandler(pool, tenant.NewDepartmentStore())

	t.Run("Create", func(t *testing.T) {
		body := `{"name": "Engineering"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/departments", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withTenantIdentity(req, ten.ID)
		w := httptest.NewRecorder()

		wrapWithTenantCtx(handler.HandleCreate).ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		var dept tenant.Department
		err := json.Unmarshal(w.Body.Bytes(), &dept)
		require.NoError(t, err)
		assert.Equal(t, "Engineering", dept.Name)
		assert.NotEmpty(t, dept.ID)
	})

	t.Run("Create_EmptyName", func(t *testing.T) {
		body := `{"name": ""}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/departments", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withTenantIdentity(req, ten.ID)
		w := httptest.NewRecorder()

		wrapWithTenantCtx(handler.HandleCreate).ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Create_WithParent", func(t *testing.T) {
		// First create the parent
		body := `{"name": "Product"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/departments", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withTenantIdentity(req, ten.ID)
		w := httptest.NewRecorder()
		wrapWithTenantCtx(handler.HandleCreate).ServeHTTP(w, req)
		require.Equal(t, http.StatusCreated, w.Code)
		var parent tenant.Department
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &parent))

		// Now create child
		body = `{"name": "Backend", "parent_id": "` + parent.ID + `"}`
		req = httptest.NewRequest(http.MethodPost, "/api/v1/departments", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withTenantIdentity(req, ten.ID)
		w = httptest.NewRecorder()
		wrapWithTenantCtx(handler.HandleCreate).ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		var child tenant.Department
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &child))
		assert.Equal(t, &parent.ID, child.ParentID)
	})

	t.Run("Get", func(t *testing.T) {
		// Create a department first
		body := `{"name": "Scouting"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/departments", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withTenantIdentity(req, ten.ID)
		w := httptest.NewRecorder()
		wrapWithTenantCtx(handler.HandleCreate).ServeHTTP(w, req)
		require.Equal(t, http.StatusCreated, w.Code)
		var created tenant.Department
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))

		// Now get it
		req = httptest.NewRequest(http.MethodGet, "/api/v1/departments/"+created.ID, nil)
		req.SetPathValue("id", created.ID)
		req = withTenantIdentity(req, ten.ID)
		w = httptest.NewRecorder()
		wrapWithTenantCtx(handler.HandleGet).ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var got tenant.Department
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
		assert.Equal(t, "Scouting", got.Name)
	})

	t.Run("List", func(t *testing.T) {
		// Create a fresh tenant for clean list
		ten2, err := tenantStore.Create(ctx, "List Org 2", "list-org-2")
		require.NoError(t, err)

		// Create two departments
		for _, name := range []string{"Dept A", "Dept B"} {
			body := `{"name": "` + name + `"}`
			req := httptest.NewRequest(http.MethodPost, "/api/v1/departments", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req = withTenantIdentity(req, ten2.ID)
			w := httptest.NewRecorder()
			wrapWithTenantCtx(handler.HandleCreate).ServeHTTP(w, req)
			require.Equal(t, http.StatusCreated, w.Code)
		}

		req := httptest.NewRequest(http.MethodGet, "/api/v1/departments", nil)
		req = withTenantIdentity(req, ten2.ID)
		w := httptest.NewRecorder()
		wrapWithTenantCtx(handler.HandleList).ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var departments []tenant.Department
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &departments))
		assert.Len(t, departments, 2)
	})
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/tenant/ -run TestDepartmentHandler -v -count=1`
Expected: FAIL — `NewDepartmentHandler` undefined.

**Step 3: Implement the department handler**

`internal/tenant/department_handler.go`:

```go
package tenant

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/valinor-ai/valinor/internal/platform/database"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
)

// DepartmentHandler handles department HTTP endpoints.
type DepartmentHandler struct {
	pool  *pgxpool.Pool
	store *DepartmentStore
}

// NewDepartmentHandler creates a new department handler.
func NewDepartmentHandler(pool *pgxpool.Pool, store *DepartmentStore) *DepartmentHandler {
	return &DepartmentHandler{pool: pool, store: store}
}

// HandleCreate creates a new department within the authenticated tenant.
func (h *DepartmentHandler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 10<<10)

	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant context required"})
		return
	}

	var req struct {
		Name     string  `json:"name"`
		ParentID *string `json:"parent_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	var dept *Department
	err := database.WithTenantConnection(r.Context(), h.pool, tenantID, func(ctx context.Context, q database.Querier) error {
		var createErr error
		dept, createErr = h.store.Create(ctx, q, req.Name, req.ParentID)
		return createErr
	})
	if err != nil {
		if errors.Is(err, ErrDepartmentNameEmpty) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if errors.Is(err, ErrDepartmentNotFound) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "parent department not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "department creation failed"})
		return
	}

	writeJSON(w, http.StatusCreated, dept)
}

// HandleGet returns a department by ID.
func (h *DepartmentHandler) HandleGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing department id"})
		return
	}

	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant context required"})
		return
	}

	var dept *Department
	err := database.WithTenantConnection(r.Context(), h.pool, tenantID, func(ctx context.Context, q database.Querier) error {
		var getErr error
		dept, getErr = h.store.GetByID(ctx, q, id)
		return getErr
	})
	if err != nil {
		if errors.Is(err, ErrDepartmentNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "department not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "fetching department failed"})
		return
	}

	writeJSON(w, http.StatusOK, dept)
}

// HandleList returns all departments in the authenticated tenant.
func (h *DepartmentHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant context required"})
		return
	}

	var departments []Department
	err := database.WithTenantConnection(r.Context(), h.pool, tenantID, func(ctx context.Context, q database.Querier) error {
		var listErr error
		departments, listErr = h.store.List(ctx, q)
		return listErr
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "listing departments failed"})
		return
	}

	if departments == nil {
		departments = []Department{}
	}

	writeJSON(w, http.StatusOK, departments)
}
```

**Note:** This file uses `context.Context` in the closures — you need to add `"context"` to the import block.

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/tenant/ -run TestDepartmentHandler -v -count=1`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/tenant/department_handler.go internal/tenant/department_handler_test.go
git commit -m "feat: add department HTTP handler with Create/Get/List (TDD)"
```

---

### Task 5: User Types

**Files:**
- Create: `internal/tenant/user.go`

**Step 1: Write user types**

```go
package tenant

import (
	"errors"
	"fmt"
	"net/mail"
	"time"
)

var (
	ErrUserNotFound   = errors.New("user not found")
	ErrEmailInvalid   = errors.New("invalid email address")
	ErrEmailDuplicate = errors.New("email already exists in tenant")
)

// User represents a user within a tenant (management domain model).
type User struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name,omitempty"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
}

// ValidateEmail checks that an email address is syntactically valid.
func ValidateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("%w: email is required", ErrEmailInvalid)
	}
	_, err := mail.ParseAddress(email)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrEmailInvalid, err)
	}
	return nil
}
```

**Step 2: Verify compilation**

Run: `go build ./internal/tenant/`
Expected: Compiles successfully.

**Step 3: Commit**

```bash
git add internal/tenant/user.go
git commit -m "feat: add User type and email validation"
```

---

### Task 6: User Store (TDD)

Includes user CRUD + department membership management.

**Files:**
- Create: `internal/tenant/user_store_test.go`
- Create: `internal/tenant/user_store.go`

**Step 1: Write the failing tests**

`internal/tenant/user_store_test.go`:

```go
package tenant_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/platform/database"
	"github.com/valinor-ai/valinor/internal/tenant"
)

func TestUserStore(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	tenantStore := tenant.NewStore(pool)
	ten, err := tenantStore.Create(ctx, "User Org", "user-org")
	require.NoError(t, err)

	userStore := tenant.NewUserStore()
	deptStore := tenant.NewDepartmentStore()

	t.Run("Create", func(t *testing.T) {
		err := database.WithTenantConnection(ctx, pool, ten.ID, func(ctx context.Context, q database.Querier) error {
			user, createErr := userStore.Create(ctx, q, "alice@example.com", "Alice")
			require.NoError(t, createErr)
			assert.NotEmpty(t, user.ID)
			assert.Equal(t, ten.ID, user.TenantID)
			assert.Equal(t, "alice@example.com", user.Email)
			assert.Equal(t, "Alice", user.DisplayName)
			assert.Equal(t, "active", user.Status)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("Create_InvalidEmail", func(t *testing.T) {
		err := database.WithTenantConnection(ctx, pool, ten.ID, func(ctx context.Context, q database.Querier) error {
			_, createErr := userStore.Create(ctx, q, "not-an-email", "Bad")
			assert.ErrorIs(t, createErr, tenant.ErrEmailInvalid)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("Create_DuplicateEmail", func(t *testing.T) {
		ten2, err := tenantStore.Create(ctx, "Dup Org", "dup-org")
		require.NoError(t, err)

		err = database.WithTenantConnection(ctx, pool, ten2.ID, func(ctx context.Context, q database.Querier) error {
			_, createErr := userStore.Create(ctx, q, "dup@example.com", "First")
			require.NoError(t, createErr)
			_, createErr = userStore.Create(ctx, q, "dup@example.com", "Second")
			assert.ErrorIs(t, createErr, tenant.ErrEmailDuplicate)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("GetByID", func(t *testing.T) {
		ten3, err := tenantStore.Create(ctx, "Get Org", "get-org")
		require.NoError(t, err)

		err = database.WithTenantConnection(ctx, pool, ten3.ID, func(ctx context.Context, q database.Querier) error {
			created, createErr := userStore.Create(ctx, q, "bob@example.com", "Bob")
			require.NoError(t, createErr)

			got, getErr := userStore.GetByID(ctx, q, created.ID)
			require.NoError(t, getErr)
			assert.Equal(t, "bob@example.com", got.Email)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("List", func(t *testing.T) {
		ten4, err := tenantStore.Create(ctx, "List Org", "list-user-org")
		require.NoError(t, err)

		err = database.WithTenantConnection(ctx, pool, ten4.ID, func(ctx context.Context, q database.Querier) error {
			_, createErr := userStore.Create(ctx, q, "u1@example.com", "User 1")
			require.NoError(t, createErr)
			_, createErr = userStore.Create(ctx, q, "u2@example.com", "User 2")
			require.NoError(t, createErr)

			users, listErr := userStore.List(ctx, q)
			require.NoError(t, listErr)
			assert.Len(t, users, 2)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("DepartmentMembership", func(t *testing.T) {
		ten5, err := tenantStore.Create(ctx, "Dept Membership Org", "dept-member-org")
		require.NoError(t, err)

		err = database.WithTenantConnection(ctx, pool, ten5.ID, func(ctx context.Context, q database.Querier) error {
			user, createErr := userStore.Create(ctx, q, "member@example.com", "Member")
			require.NoError(t, createErr)
			dept, createErr := deptStore.Create(ctx, q, "Engineering", nil)
			require.NoError(t, createErr)

			// Add to department
			addErr := userStore.AddToDepartment(ctx, q, user.ID, dept.ID)
			require.NoError(t, addErr)

			// List departments
			departments, listErr := userStore.ListDepartments(ctx, q, user.ID)
			require.NoError(t, listErr)
			assert.Len(t, departments, 1)
			assert.Equal(t, dept.ID, departments[0].ID)

			// Remove from department
			removeErr := userStore.RemoveFromDepartment(ctx, q, user.ID, dept.ID)
			require.NoError(t, removeErr)

			departments, listErr = userStore.ListDepartments(ctx, q, user.ID)
			require.NoError(t, listErr)
			assert.Len(t, departments, 0)

			return nil
		})
		require.NoError(t, err)
	})
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/tenant/ -run TestUserStore -v -count=1`
Expected: FAIL — `NewUserStore` undefined.

**Step 3: Implement the user store**

`internal/tenant/user_store.go`:

```go
package tenant

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

// UserStore handles user database operations within a tenant.
type UserStore struct{}

// NewUserStore creates a new user store.
func NewUserStore() *UserStore {
	return &UserStore{}
}

// Create inserts a new user. The tenant_id is read from the RLS session variable.
func (s *UserStore) Create(ctx context.Context, q database.Querier, email, displayName string) (*User, error) {
	if err := ValidateEmail(email); err != nil {
		return nil, err
	}

	var user User
	err := q.QueryRow(ctx,
		`INSERT INTO users (tenant_id, email, display_name)
		 VALUES (current_setting('app.current_tenant_id', true)::UUID, $1, $2)
		 RETURNING id, tenant_id, email, COALESCE(display_name, ''), status, created_at`,
		email, displayName,
	).Scan(&user.ID, &user.TenantID, &user.Email, &user.DisplayName, &user.Status, &user.CreatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "unique constraint") {
			return nil, fmt.Errorf("%w: %s", ErrEmailDuplicate, email)
		}
		return nil, fmt.Errorf("creating user: %w", err)
	}
	return &user, nil
}

// GetByID retrieves a user by ID. RLS ensures tenant isolation.
func (s *UserStore) GetByID(ctx context.Context, q database.Querier, id string) (*User, error) {
	var user User
	err := q.QueryRow(ctx,
		`SELECT id, tenant_id, email, COALESCE(display_name, ''), status, created_at
		 FROM users WHERE id = $1`,
		id,
	).Scan(&user.ID, &user.TenantID, &user.Email, &user.DisplayName, &user.Status, &user.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("getting user: %w", err)
	}
	return &user, nil
}

// List returns all users visible through RLS (current tenant).
func (s *UserStore) List(ctx context.Context, q database.Querier) ([]User, error) {
	rows, err := q.Query(ctx,
		`SELECT id, tenant_id, email, COALESCE(display_name, ''), status, created_at
		 FROM users ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("listing users: %w", err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.TenantID, &u.Email, &u.DisplayName, &u.Status, &u.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning user: %w", err)
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// AddToDepartment adds a user to a department.
func (s *UserStore) AddToDepartment(ctx context.Context, q database.Querier, userID, departmentID string) error {
	_, err := q.Exec(ctx,
		"INSERT INTO user_departments (user_id, department_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
		userID, departmentID,
	)
	if err != nil {
		return fmt.Errorf("adding user to department: %w", err)
	}
	return nil
}

// RemoveFromDepartment removes a user from a department.
func (s *UserStore) RemoveFromDepartment(ctx context.Context, q database.Querier, userID, departmentID string) error {
	_, err := q.Exec(ctx,
		"DELETE FROM user_departments WHERE user_id = $1 AND department_id = $2",
		userID, departmentID,
	)
	if err != nil {
		return fmt.Errorf("removing user from department: %w", err)
	}
	return nil
}

// ListDepartments returns all departments a user belongs to.
func (s *UserStore) ListDepartments(ctx context.Context, q database.Querier, userID string) ([]Department, error) {
	rows, err := q.Query(ctx,
		`SELECT d.id, d.tenant_id, d.name, d.parent_id, d.created_at
		 FROM departments d
		 JOIN user_departments ud ON ud.department_id = d.id
		 WHERE ud.user_id = $1
		 ORDER BY d.name`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("listing user departments: %w", err)
	}
	defer rows.Close()

	var departments []Department
	for rows.Next() {
		var d Department
		if err := rows.Scan(&d.ID, &d.TenantID, &d.Name, &d.ParentID, &d.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning department: %w", err)
		}
		departments = append(departments, d)
	}
	return departments, rows.Err()
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/tenant/ -run TestUserStore -v -count=1`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/tenant/user_store.go internal/tenant/user_store_test.go
git commit -m "feat: add user store with Create/Get/List and department membership (TDD)"
```

---

### Task 7: User HTTP Handler (TDD)

**Files:**
- Create: `internal/tenant/user_handler_test.go`
- Create: `internal/tenant/user_handler.go`

**Step 1: Write the failing tests**

`internal/tenant/user_handler_test.go`:

```go
package tenant_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/platform/database"
	"github.com/valinor-ai/valinor/internal/tenant"
)

func TestUserHandler(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	tenantStore := tenant.NewStore(pool)
	ten, err := tenantStore.Create(ctx, "User Handler Org", "user-handler-org")
	require.NoError(t, err)

	handler := tenant.NewUserHandler(pool, tenant.NewUserStore(), tenant.NewDepartmentStore())

	t.Run("Create", func(t *testing.T) {
		body := `{"email": "alice@example.com", "display_name": "Alice"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withTenantIdentity(req, ten.ID)
		w := httptest.NewRecorder()

		wrapWithTenantCtx(handler.HandleCreate).ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		var user tenant.User
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &user))
		assert.Equal(t, "alice@example.com", user.Email)
	})

	t.Run("Create_InvalidEmail", func(t *testing.T) {
		body := `{"email": "bad", "display_name": "Bad"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withTenantIdentity(req, ten.ID)
		w := httptest.NewRecorder()

		wrapWithTenantCtx(handler.HandleCreate).ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Get", func(t *testing.T) {
		// Create user first
		var userID string
		err := database.WithTenantConnection(ctx, pool, ten.ID, func(ctx context.Context, q database.Querier) error {
			u, createErr := tenant.NewUserStore().Create(ctx, q, "getme@example.com", "Get Me")
			if createErr != nil {
				return createErr
			}
			userID = u.ID
			return nil
		})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/users/"+userID, nil)
		req.SetPathValue("id", userID)
		req = withTenantIdentity(req, ten.ID)
		w := httptest.NewRecorder()

		wrapWithTenantCtx(handler.HandleGet).ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("List", func(t *testing.T) {
		ten2, err := tenantStore.Create(ctx, "User List Org", "user-list-org")
		require.NoError(t, err)

		err = database.WithTenantConnection(ctx, pool, ten2.ID, func(ctx context.Context, q database.Querier) error {
			_, createErr := tenant.NewUserStore().Create(ctx, q, "u1@test.com", "U1")
			require.NoError(t, createErr)
			_, createErr = tenant.NewUserStore().Create(ctx, q, "u2@test.com", "U2")
			require.NoError(t, createErr)
			return nil
		})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
		req = withTenantIdentity(req, ten2.ID)
		w := httptest.NewRecorder()

		wrapWithTenantCtx(handler.HandleList).ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var users []tenant.User
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &users))
		assert.Len(t, users, 2)
	})

	t.Run("AddToDepartment", func(t *testing.T) {
		ten3, err := tenantStore.Create(ctx, "Dept Member Org", "dept-member-handler-org")
		require.NoError(t, err)

		var userID, deptID string
		err = database.WithTenantConnection(ctx, pool, ten3.ID, func(ctx context.Context, q database.Querier) error {
			u, createErr := tenant.NewUserStore().Create(ctx, q, "member@test.com", "Member")
			require.NoError(t, createErr)
			userID = u.ID
			d, createErr := tenant.NewDepartmentStore().Create(ctx, q, "Eng", nil)
			require.NoError(t, createErr)
			deptID = d.ID
			return nil
		})
		require.NoError(t, err)

		body := `{"department_id": "` + deptID + `"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/users/"+userID+"/departments", strings.NewReader(body))
		req.SetPathValue("id", userID)
		req.Header.Set("Content-Type", "application/json")
		req = withTenantIdentity(req, ten3.ID)
		w := httptest.NewRecorder()

		wrapWithTenantCtx(handler.HandleAddToDepartment).ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("RemoveFromDepartment", func(t *testing.T) {
		ten4, err := tenantStore.Create(ctx, "Remove Dept Org", "remove-dept-org")
		require.NoError(t, err)

		var userID, deptID string
		err = database.WithTenantConnection(ctx, pool, ten4.ID, func(ctx context.Context, q database.Querier) error {
			u, createErr := tenant.NewUserStore().Create(ctx, q, "removeme@test.com", "Remove")
			require.NoError(t, createErr)
			userID = u.ID
			d, createErr := tenant.NewDepartmentStore().Create(ctx, q, "Eng", nil)
			require.NoError(t, createErr)
			deptID = d.ID
			addErr := tenant.NewUserStore().AddToDepartment(ctx, q, userID, deptID)
			require.NoError(t, addErr)
			return nil
		})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/"+userID+"/departments/"+deptID, nil)
		req.SetPathValue("id", userID)
		req.SetPathValue("deptId", deptID)
		req = withTenantIdentity(req, ten4.ID)
		w := httptest.NewRecorder()

		wrapWithTenantCtx(handler.HandleRemoveFromDepartment).ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/tenant/ -run TestUserHandler -v -count=1`
Expected: FAIL — `NewUserHandler` undefined.

**Step 3: Implement the user handler**

`internal/tenant/user_handler.go`:

```go
package tenant

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/valinor-ai/valinor/internal/platform/database"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
)

// UserHandler handles user HTTP endpoints within a tenant.
type UserHandler struct {
	pool      *pgxpool.Pool
	store     *UserStore
	deptStore *DepartmentStore
}

// NewUserHandler creates a new user handler.
func NewUserHandler(pool *pgxpool.Pool, store *UserStore, deptStore *DepartmentStore) *UserHandler {
	return &UserHandler{pool: pool, store: store, deptStore: deptStore}
}

// HandleCreate creates a new user within the authenticated tenant.
func (h *UserHandler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 10<<10)

	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant context required"})
		return
	}

	var req struct {
		Email       string `json:"email"`
		DisplayName string `json:"display_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	var user *User
	err := database.WithTenantConnection(r.Context(), h.pool, tenantID, func(ctx context.Context, q database.Querier) error {
		var createErr error
		user, createErr = h.store.Create(ctx, q, req.Email, req.DisplayName)
		return createErr
	})
	if err != nil {
		if errors.Is(err, ErrEmailInvalid) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if errors.Is(err, ErrEmailDuplicate) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "user creation failed"})
		return
	}

	writeJSON(w, http.StatusCreated, user)
}

// HandleGet returns a user by ID.
func (h *UserHandler) HandleGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing user id"})
		return
	}

	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant context required"})
		return
	}

	var user *User
	err := database.WithTenantConnection(r.Context(), h.pool, tenantID, func(ctx context.Context, q database.Querier) error {
		var getErr error
		user, getErr = h.store.GetByID(ctx, q, id)
		return getErr
	})
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "fetching user failed"})
		return
	}

	writeJSON(w, http.StatusOK, user)
}

// HandleList returns all users in the authenticated tenant.
func (h *UserHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant context required"})
		return
	}

	var users []User
	err := database.WithTenantConnection(r.Context(), h.pool, tenantID, func(ctx context.Context, q database.Querier) error {
		var listErr error
		users, listErr = h.store.List(ctx, q)
		return listErr
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "listing users failed"})
		return
	}

	if users == nil {
		users = []User{}
	}

	writeJSON(w, http.StatusOK, users)
}

// HandleAddToDepartment adds a user to a department.
func (h *UserHandler) HandleAddToDepartment(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 10<<10)

	userID := r.PathValue("id")
	if userID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing user id"})
		return
	}

	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant context required"})
		return
	}

	var req struct {
		DepartmentID string `json:"department_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.DepartmentID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "department_id is required"})
		return
	}

	err := database.WithTenantConnection(r.Context(), h.pool, tenantID, func(ctx context.Context, q database.Querier) error {
		// Verify user exists in this tenant
		if _, getErr := h.store.GetByID(ctx, q, userID); getErr != nil {
			return getErr
		}
		// Verify department exists in this tenant
		if _, getErr := h.deptStore.GetByID(ctx, q, req.DepartmentID); getErr != nil {
			return getErr
		}
		return h.store.AddToDepartment(ctx, q, userID, req.DepartmentID)
	})
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}
		if errors.Is(err, ErrDepartmentNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "department not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "adding user to department failed"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// HandleRemoveFromDepartment removes a user from a department.
func (h *UserHandler) HandleRemoveFromDepartment(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	deptID := r.PathValue("deptId")
	if userID == "" || deptID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing user id or department id"})
		return
	}

	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant context required"})
		return
	}

	err := database.WithTenantConnection(r.Context(), h.pool, tenantID, func(ctx context.Context, q database.Querier) error {
		return h.store.RemoveFromDepartment(ctx, q, userID, deptID)
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "removing user from department failed"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/tenant/ -run TestUserHandler -v -count=1`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/tenant/user_handler.go internal/tenant/user_handler_test.go
git commit -m "feat: add user HTTP handler with Create/Get/List and department membership (TDD)"
```

---

### Task 8: Role Types + Store (TDD)

**Files:**
- Create: `internal/tenant/role.go`
- Create: `internal/tenant/role_store_test.go`
- Create: `internal/tenant/role_store.go`

**Step 1: Write role types**

`internal/tenant/role.go`:

```go
package tenant

import (
	"errors"
	"time"
)

var (
	ErrRoleNotFound   = errors.New("role not found")
	ErrRoleNameEmpty  = errors.New("role name is required")
	ErrRoleDuplicate  = errors.New("role name already exists in tenant")
)

// Role represents a role within a tenant.
type Role struct {
	ID          string   `json:"id"`
	TenantID    string   `json:"tenant_id"`
	Name        string   `json:"name"`
	Permissions []string `json:"permissions"`
	IsSystem    bool     `json:"is_system"`
	CreatedAt   time.Time `json:"created_at"`
}

// UserRole represents a role assignment for a user, scoped to an org or department.
type UserRole struct {
	UserID    string `json:"user_id"`
	RoleID    string `json:"role_id"`
	RoleName  string `json:"role_name"`
	ScopeType string `json:"scope_type"` // "org" or "department"
	ScopeID   string `json:"scope_id"`
}
```

**Step 2: Write the failing tests**

`internal/tenant/role_store_test.go`:

```go
package tenant_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/platform/database"
	"github.com/valinor-ai/valinor/internal/tenant"
)

func TestRoleStore(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	tenantStore := tenant.NewStore(pool)
	ten, err := tenantStore.Create(ctx, "Role Org", "role-org")
	require.NoError(t, err)

	roleStore := tenant.NewRoleStore()
	userStore := tenant.NewUserStore()

	t.Run("Create", func(t *testing.T) {
		err := database.WithTenantConnection(ctx, pool, ten.ID, func(ctx context.Context, q database.Querier) error {
			role, createErr := roleStore.Create(ctx, q, "viewer", []string{"agents:read"})
			require.NoError(t, createErr)
			assert.NotEmpty(t, role.ID)
			assert.Equal(t, "viewer", role.Name)
			assert.Equal(t, []string{"agents:read"}, role.Permissions)
			assert.False(t, role.IsSystem)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("Create_EmptyName", func(t *testing.T) {
		err := database.WithTenantConnection(ctx, pool, ten.ID, func(ctx context.Context, q database.Querier) error {
			_, createErr := roleStore.Create(ctx, q, "", []string{"agents:read"})
			assert.ErrorIs(t, createErr, tenant.ErrRoleNameEmpty)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("Create_DuplicateName", func(t *testing.T) {
		ten2, err := tenantStore.Create(ctx, "Dup Role Org", "dup-role-org")
		require.NoError(t, err)

		err = database.WithTenantConnection(ctx, pool, ten2.ID, func(ctx context.Context, q database.Querier) error {
			_, createErr := roleStore.Create(ctx, q, "editor", []string{"agents:write"})
			require.NoError(t, createErr)
			_, createErr = roleStore.Create(ctx, q, "editor", []string{"agents:read"})
			assert.ErrorIs(t, createErr, tenant.ErrRoleDuplicate)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("List", func(t *testing.T) {
		ten3, err := tenantStore.Create(ctx, "List Role Org", "list-role-org")
		require.NoError(t, err)

		err = database.WithTenantConnection(ctx, pool, ten3.ID, func(ctx context.Context, q database.Querier) error {
			_, createErr := roleStore.Create(ctx, q, "admin", []string{"*"})
			require.NoError(t, createErr)
			_, createErr = roleStore.Create(ctx, q, "viewer", []string{"agents:read"})
			require.NoError(t, createErr)

			roles, listErr := roleStore.List(ctx, q)
			require.NoError(t, listErr)
			assert.Len(t, roles, 2)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("AssignAndListForUser", func(t *testing.T) {
		ten4, err := tenantStore.Create(ctx, "Assign Org", "assign-org")
		require.NoError(t, err)

		err = database.WithTenantConnection(ctx, pool, ten4.ID, func(ctx context.Context, q database.Querier) error {
			role, createErr := roleStore.Create(ctx, q, "manager", []string{"agents:write"})
			require.NoError(t, createErr)
			user, createErr := userStore.Create(ctx, q, "mgr@test.com", "Manager")
			require.NoError(t, createErr)

			// Assign role scoped to org
			assignErr := roleStore.AssignToUser(ctx, q, user.ID, role.ID, "org", ten4.ID)
			require.NoError(t, assignErr)

			// List roles for user
			roles, listErr := roleStore.ListForUser(ctx, q, user.ID)
			require.NoError(t, listErr)
			assert.Len(t, roles, 1)
			assert.Equal(t, role.ID, roles[0].RoleID)
			assert.Equal(t, "manager", roles[0].RoleName)
			assert.Equal(t, "org", roles[0].ScopeType)

			return nil
		})
		require.NoError(t, err)
	})

	t.Run("RemoveFromUser", func(t *testing.T) {
		ten5, err := tenantStore.Create(ctx, "Remove Role Org", "remove-role-org")
		require.NoError(t, err)

		err = database.WithTenantConnection(ctx, pool, ten5.ID, func(ctx context.Context, q database.Querier) error {
			role, createErr := roleStore.Create(ctx, q, "temp", []string{"agents:read"})
			require.NoError(t, createErr)
			user, createErr := userStore.Create(ctx, q, "temp@test.com", "Temp")
			require.NoError(t, createErr)

			assignErr := roleStore.AssignToUser(ctx, q, user.ID, role.ID, "org", ten5.ID)
			require.NoError(t, assignErr)

			removeErr := roleStore.RemoveFromUser(ctx, q, user.ID, role.ID, "org", ten5.ID)
			require.NoError(t, removeErr)

			roles, listErr := roleStore.ListForUser(ctx, q, user.ID)
			require.NoError(t, listErr)
			assert.Len(t, roles, 0)

			return nil
		})
		require.NoError(t, err)
	})
}
```

**Step 3: Run tests to verify they fail**

Run: `go test ./internal/tenant/ -run TestRoleStore -v -count=1`
Expected: FAIL — `NewRoleStore` undefined.

**Step 4: Implement the role store**

`internal/tenant/role_store.go`:

```go
package tenant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

// RoleStore handles role database operations within a tenant.
type RoleStore struct{}

// NewRoleStore creates a new role store.
func NewRoleStore() *RoleStore {
	return &RoleStore{}
}

// Create inserts a new role. The tenant_id is read from the RLS session variable.
func (s *RoleStore) Create(ctx context.Context, q database.Querier, name string, permissions []string) (*Role, error) {
	if strings.TrimSpace(name) == "" {
		return nil, ErrRoleNameEmpty
	}

	permJSON, err := json.Marshal(permissions)
	if err != nil {
		return nil, fmt.Errorf("marshaling permissions: %w", err)
	}

	var role Role
	var permBytes []byte
	err = q.QueryRow(ctx,
		`INSERT INTO roles (tenant_id, name, permissions)
		 VALUES (current_setting('app.current_tenant_id', true)::UUID, $1, $2)
		 RETURNING id, tenant_id, name, permissions, is_system, created_at`,
		name, permJSON,
	).Scan(&role.ID, &role.TenantID, &role.Name, &permBytes, &role.IsSystem, &role.CreatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "unique constraint") {
			return nil, fmt.Errorf("%w: %s", ErrRoleDuplicate, name)
		}
		return nil, fmt.Errorf("creating role: %w", err)
	}

	if err := json.Unmarshal(permBytes, &role.Permissions); err != nil {
		return nil, fmt.Errorf("unmarshaling permissions: %w", err)
	}

	return &role, nil
}

// List returns all roles visible through RLS (current tenant).
func (s *RoleStore) List(ctx context.Context, q database.Querier) ([]Role, error) {
	rows, err := q.Query(ctx,
		`SELECT id, tenant_id, name, permissions, is_system, created_at
		 FROM roles ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("listing roles: %w", err)
	}
	defer rows.Close()

	var roles []Role
	for rows.Next() {
		var r Role
		var permBytes []byte
		if err := rows.Scan(&r.ID, &r.TenantID, &r.Name, &permBytes, &r.IsSystem, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning role: %w", err)
		}
		if err := json.Unmarshal(permBytes, &r.Permissions); err != nil {
			return nil, fmt.Errorf("unmarshaling permissions: %w", err)
		}
		roles = append(roles, r)
	}
	return roles, rows.Err()
}

// AssignToUser assigns a role to a user with a scope (org or department).
func (s *RoleStore) AssignToUser(ctx context.Context, q database.Querier, userID, roleID, scopeType, scopeID string) error {
	_, err := q.Exec(ctx,
		`INSERT INTO user_roles (user_id, role_id, scope_type, scope_id)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT DO NOTHING`,
		userID, roleID, scopeType, scopeID,
	)
	if err != nil {
		return fmt.Errorf("assigning role: %w", err)
	}
	return nil
}

// RemoveFromUser removes a role assignment from a user.
func (s *RoleStore) RemoveFromUser(ctx context.Context, q database.Querier, userID, roleID, scopeType, scopeID string) error {
	_, err := q.Exec(ctx,
		`DELETE FROM user_roles
		 WHERE user_id = $1 AND role_id = $2 AND scope_type = $3 AND scope_id = $4`,
		userID, roleID, scopeType, scopeID,
	)
	if err != nil {
		return fmt.Errorf("removing role: %w", err)
	}
	return nil
}

// ListForUser returns all role assignments for a user.
func (s *RoleStore) ListForUser(ctx context.Context, q database.Querier, userID string) ([]UserRole, error) {
	rows, err := q.Query(ctx,
		`SELECT ur.user_id, ur.role_id, r.name, ur.scope_type, ur.scope_id
		 FROM user_roles ur
		 JOIN roles r ON r.id = ur.role_id
		 WHERE ur.user_id = $1
		 ORDER BY r.name`,
		userID,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("listing user roles: %w", err)
	}
	defer rows.Close()

	var roles []UserRole
	for rows.Next() {
		var ur UserRole
		if err := rows.Scan(&ur.UserID, &ur.RoleID, &ur.RoleName, &ur.ScopeType, &ur.ScopeID); err != nil {
			return nil, fmt.Errorf("scanning user role: %w", err)
		}
		roles = append(roles, ur)
	}
	return roles, rows.Err()
}
```

**Step 5: Run tests to verify they pass**

Run: `go test ./internal/tenant/ -run TestRoleStore -v -count=1`
Expected: PASS

**Step 6: Commit**

```bash
git add internal/tenant/role.go internal/tenant/role_store.go internal/tenant/role_store_test.go
git commit -m "feat: add role store with Create/List/Assign/Remove (TDD)"
```

---

### Task 9: Role HTTP Handler (TDD)

**Files:**
- Create: `internal/tenant/role_handler_test.go`
- Create: `internal/tenant/role_handler.go`

**Step 1: Write the failing tests**

`internal/tenant/role_handler_test.go`:

```go
package tenant_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/platform/database"
	"github.com/valinor-ai/valinor/internal/tenant"
)

func TestRoleHandler(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	tenantStore := tenant.NewStore(pool)
	ten, err := tenantStore.Create(ctx, "Role Handler Org", "role-handler-org")
	require.NoError(t, err)

	handler := tenant.NewRoleHandler(pool, tenant.NewRoleStore(), tenant.NewUserStore())

	t.Run("Create", func(t *testing.T) {
		body := `{"name": "viewer", "permissions": ["agents:read"]}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/roles", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withTenantIdentity(req, ten.ID)
		w := httptest.NewRecorder()

		wrapWithTenantCtx(handler.HandleCreate).ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		var role tenant.Role
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &role))
		assert.Equal(t, "viewer", role.Name)
		assert.Equal(t, []string{"agents:read"}, role.Permissions)
	})

	t.Run("List", func(t *testing.T) {
		ten2, err := tenantStore.Create(ctx, "Role List Org", "role-list-org")
		require.NoError(t, err)

		err = database.WithTenantConnection(ctx, pool, ten2.ID, func(ctx context.Context, q database.Querier) error {
			_, createErr := tenant.NewRoleStore().Create(ctx, q, "admin", []string{"*"})
			require.NoError(t, createErr)
			_, createErr = tenant.NewRoleStore().Create(ctx, q, "reader", []string{"agents:read"})
			require.NoError(t, createErr)
			return nil
		})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/roles", nil)
		req = withTenantIdentity(req, ten2.ID)
		w := httptest.NewRecorder()

		wrapWithTenantCtx(handler.HandleList).ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var roles []tenant.Role
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &roles))
		assert.Len(t, roles, 2)
	})

	t.Run("AssignRole", func(t *testing.T) {
		ten3, err := tenantStore.Create(ctx, "Assign Handler Org", "assign-handler-org")
		require.NoError(t, err)

		var roleID, userID string
		err = database.WithTenantConnection(ctx, pool, ten3.ID, func(ctx context.Context, q database.Querier) error {
			role, createErr := tenant.NewRoleStore().Create(ctx, q, "operator", []string{"agents:write"})
			require.NoError(t, createErr)
			roleID = role.ID
			user, createErr := tenant.NewUserStore().Create(ctx, q, "assign@test.com", "Assign")
			require.NoError(t, createErr)
			userID = user.ID
			return nil
		})
		require.NoError(t, err)

		body := `{"role_id": "` + roleID + `", "scope_type": "org", "scope_id": "` + ten3.ID + `"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/users/"+userID+"/roles", strings.NewReader(body))
		req.SetPathValue("id", userID)
		req.Header.Set("Content-Type", "application/json")
		req = withTenantIdentity(req, ten3.ID)
		w := httptest.NewRecorder()

		wrapWithTenantCtx(handler.HandleAssignRole).ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("RemoveRole", func(t *testing.T) {
		ten4, err := tenantStore.Create(ctx, "Remove Handler Org", "remove-handler-org")
		require.NoError(t, err)

		var roleID, userID string
		err = database.WithTenantConnection(ctx, pool, ten4.ID, func(ctx context.Context, q database.Querier) error {
			role, createErr := tenant.NewRoleStore().Create(ctx, q, "temp", []string{"agents:read"})
			require.NoError(t, createErr)
			roleID = role.ID
			user, createErr := tenant.NewUserStore().Create(ctx, q, "remove@test.com", "Remove")
			require.NoError(t, createErr)
			userID = user.ID
			assignErr := tenant.NewRoleStore().AssignToUser(ctx, q, userID, roleID, "org", ten4.ID)
			require.NoError(t, assignErr)
			return nil
		})
		require.NoError(t, err)

		body := `{"role_id": "` + roleID + `", "scope_type": "org", "scope_id": "` + ten4.ID + `"}`
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/"+userID+"/roles", strings.NewReader(body))
		req.SetPathValue("id", userID)
		req.Header.Set("Content-Type", "application/json")
		req = withTenantIdentity(req, ten4.ID)
		w := httptest.NewRecorder()

		wrapWithTenantCtx(handler.HandleRemoveRole).ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("ListUserRoles", func(t *testing.T) {
		ten5, err := tenantStore.Create(ctx, "List Roles Handler Org", "list-roles-handler-org")
		require.NoError(t, err)

		var userID string
		err = database.WithTenantConnection(ctx, pool, ten5.ID, func(ctx context.Context, q database.Querier) error {
			role, createErr := tenant.NewRoleStore().Create(ctx, q, "analyst", []string{"agents:read"})
			require.NoError(t, createErr)
			user, createErr := tenant.NewUserStore().Create(ctx, q, "analyst@test.com", "Analyst")
			require.NoError(t, createErr)
			userID = user.ID
			assignErr := tenant.NewRoleStore().AssignToUser(ctx, q, userID, role.ID, "org", ten5.ID)
			require.NoError(t, assignErr)
			return nil
		})
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/users/"+userID+"/roles", nil)
		req.SetPathValue("id", userID)
		req = withTenantIdentity(req, ten5.ID)
		w := httptest.NewRecorder()

		wrapWithTenantCtx(handler.HandleListUserRoles).ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var roles []tenant.UserRole
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &roles))
		assert.Len(t, roles, 1)
		assert.Equal(t, "analyst", roles[0].RoleName)
	})
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/tenant/ -run TestRoleHandler -v -count=1`
Expected: FAIL — `NewRoleHandler` undefined.

**Step 3: Implement the role handler**

`internal/tenant/role_handler.go`:

```go
package tenant

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/valinor-ai/valinor/internal/platform/database"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
)

// RoleHandler handles role HTTP endpoints within a tenant.
type RoleHandler struct {
	pool      *pgxpool.Pool
	store     *RoleStore
	userStore *UserStore
}

// NewRoleHandler creates a new role handler.
func NewRoleHandler(pool *pgxpool.Pool, store *RoleStore, userStore *UserStore) *RoleHandler {
	return &RoleHandler{pool: pool, store: store, userStore: userStore}
}

// HandleCreate creates a new role within the authenticated tenant.
func (h *RoleHandler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 10<<10)

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

	var role *Role
	err := database.WithTenantConnection(r.Context(), h.pool, tenantID, func(ctx context.Context, q database.Querier) error {
		var createErr error
		role, createErr = h.store.Create(ctx, q, req.Name, req.Permissions)
		return createErr
	})
	if err != nil {
		if errors.Is(err, ErrRoleNameEmpty) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if errors.Is(err, ErrRoleDuplicate) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "role creation failed"})
		return
	}

	writeJSON(w, http.StatusCreated, role)
}

// HandleList returns all roles in the authenticated tenant.
func (h *RoleHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant context required"})
		return
	}

	var roles []Role
	err := database.WithTenantConnection(r.Context(), h.pool, tenantID, func(ctx context.Context, q database.Querier) error {
		var listErr error
		roles, listErr = h.store.List(ctx, q)
		return listErr
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "listing roles failed"})
		return
	}

	if roles == nil {
		roles = []Role{}
	}

	writeJSON(w, http.StatusOK, roles)
}

// HandleAssignRole assigns a role to a user.
func (h *RoleHandler) HandleAssignRole(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 10<<10)

	userID := r.PathValue("id")
	if userID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing user id"})
		return
	}

	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant context required"})
		return
	}

	var req struct {
		RoleID    string `json:"role_id"`
		ScopeType string `json:"scope_type"`
		ScopeID   string `json:"scope_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.RoleID == "" || req.ScopeType == "" || req.ScopeID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "role_id, scope_type, and scope_id are required"})
		return
	}
	if req.ScopeType != "org" && req.ScopeType != "department" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "scope_type must be 'org' or 'department'"})
		return
	}

	err := database.WithTenantConnection(r.Context(), h.pool, tenantID, func(ctx context.Context, q database.Querier) error {
		// Verify user exists in this tenant
		if _, getErr := h.userStore.GetByID(ctx, q, userID); getErr != nil {
			return getErr
		}
		return h.store.AssignToUser(ctx, q, userID, req.RoleID, req.ScopeType, req.ScopeID)
	})
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "role assignment failed"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// HandleRemoveRole removes a role assignment from a user.
func (h *RoleHandler) HandleRemoveRole(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 10<<10)

	userID := r.PathValue("id")
	if userID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing user id"})
		return
	}

	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant context required"})
		return
	}

	var req struct {
		RoleID    string `json:"role_id"`
		ScopeType string `json:"scope_type"`
		ScopeID   string `json:"scope_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.RoleID == "" || req.ScopeType == "" || req.ScopeID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "role_id, scope_type, and scope_id are required"})
		return
	}

	err := database.WithTenantConnection(r.Context(), h.pool, tenantID, func(ctx context.Context, q database.Querier) error {
		return h.store.RemoveFromUser(ctx, q, userID, req.RoleID, req.ScopeType, req.ScopeID)
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "role removal failed"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// HandleListUserRoles returns all role assignments for a user.
func (h *RoleHandler) HandleListUserRoles(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("id")
	if userID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing user id"})
		return
	}

	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant context required"})
		return
	}

	var roles []UserRole
	err := database.WithTenantConnection(r.Context(), h.pool, tenantID, func(ctx context.Context, q database.Querier) error {
		var listErr error
		roles, listErr = h.store.ListForUser(ctx, q, userID)
		return listErr
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "listing user roles failed"})
		return
	}

	if roles == nil {
		roles = []UserRole{}
	}

	writeJSON(w, http.StatusOK, roles)
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/tenant/ -run TestRoleHandler -v -count=1`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/tenant/role_handler.go internal/tenant/role_handler_test.go
git commit -m "feat: add role HTTP handler with Create/List/Assign/Remove (TDD)"
```

---

### Task 10: Server Wiring

Wire all new handlers into `server.go` with RBAC middleware.

**Files:**
- Modify: `internal/platform/server/server.go`

**Step 1: Update Dependencies struct and route registration**

Add to `Dependencies`:

```go
DepartmentHandler *tenant.DepartmentHandler
UserHandler       *tenant.UserHandler
RoleHandler       *tenant.RoleHandler
```

Add route registration in `New()`, after the existing tenant handler block:

```go
// Department routes (tenant-scoped, RBAC-protected)
if deps.DepartmentHandler != nil && deps.RBAC != nil {
    protectedMux.Handle("POST /api/v1/departments",
        rbac.RequirePermission(deps.RBAC, "departments:write")(
            http.HandlerFunc(deps.DepartmentHandler.HandleCreate),
        ),
    )
    protectedMux.Handle("GET /api/v1/departments/{id}",
        rbac.RequirePermission(deps.RBAC, "departments:read")(
            http.HandlerFunc(deps.DepartmentHandler.HandleGet),
        ),
    )
    protectedMux.Handle("GET /api/v1/departments",
        rbac.RequirePermission(deps.RBAC, "departments:read")(
            http.HandlerFunc(deps.DepartmentHandler.HandleList),
        ),
    )
}

// User routes (tenant-scoped, RBAC-protected)
if deps.UserHandler != nil && deps.RBAC != nil {
    protectedMux.Handle("POST /api/v1/users",
        rbac.RequirePermission(deps.RBAC, "users:write")(
            http.HandlerFunc(deps.UserHandler.HandleCreate),
        ),
    )
    protectedMux.Handle("GET /api/v1/users/{id}",
        rbac.RequirePermission(deps.RBAC, "users:read")(
            http.HandlerFunc(deps.UserHandler.HandleGet),
        ),
    )
    protectedMux.Handle("GET /api/v1/users",
        rbac.RequirePermission(deps.RBAC, "users:read")(
            http.HandlerFunc(deps.UserHandler.HandleList),
        ),
    )
    protectedMux.Handle("POST /api/v1/users/{id}/departments",
        rbac.RequirePermission(deps.RBAC, "users:write")(
            http.HandlerFunc(deps.UserHandler.HandleAddToDepartment),
        ),
    )
    protectedMux.Handle("DELETE /api/v1/users/{id}/departments/{deptId}",
        rbac.RequirePermission(deps.RBAC, "users:write")(
            http.HandlerFunc(deps.UserHandler.HandleRemoveFromDepartment),
        ),
    )
}

// Role routes (tenant-scoped, RBAC-protected)
if deps.RoleHandler != nil && deps.RBAC != nil {
    protectedMux.Handle("POST /api/v1/roles",
        rbac.RequirePermission(deps.RBAC, "users:manage")(
            http.HandlerFunc(deps.RoleHandler.HandleCreate),
        ),
    )
    protectedMux.Handle("GET /api/v1/roles",
        rbac.RequirePermission(deps.RBAC, "users:read")(
            http.HandlerFunc(deps.RoleHandler.HandleList),
        ),
    )
    protectedMux.Handle("POST /api/v1/users/{id}/roles",
        rbac.RequirePermission(deps.RBAC, "users:manage")(
            http.HandlerFunc(deps.RoleHandler.HandleAssignRole),
        ),
    )
    protectedMux.Handle("DELETE /api/v1/users/{id}/roles",
        rbac.RequirePermission(deps.RBAC, "users:manage")(
            http.HandlerFunc(deps.RoleHandler.HandleRemoveRole),
        ),
    )
    protectedMux.Handle("GET /api/v1/users/{id}/roles",
        rbac.RequirePermission(deps.RBAC, "users:read")(
            http.HandlerFunc(deps.RoleHandler.HandleListUserRoles),
        ),
    )
}
```

**Step 2: Verify compilation**

Run: `go build ./internal/platform/server/`
Expected: Compiles (Dependencies struct has new fields but they're pointer types, so existing callers where they're nil still work).

**Step 3: Update server_test.go if needed**

The existing `server_test.go` creates `Dependencies{}` without the new fields — this should still compile since pointer fields default to nil. Verify:

Run: `go test ./internal/platform/server/ -v -count=1`
Expected: PASS (existing tests unaffected)

**Step 4: Commit**

```bash
git add internal/platform/server/server.go
git commit -m "feat: wire department/user/role routes with RBAC middleware"
```

---

### Task 11: Main.go Wiring

Create and inject the new handlers in `cmd/valinor/main.go`.

**Files:**
- Modify: `cmd/valinor/main.go`

**Step 1: Add handler creation after tenant handler block**

After the existing tenant handler creation (around line 98-102), add:

```go
// Department, user, and role management (tenant-scoped)
var deptHandler *tenant.DepartmentHandler
var userHandler *tenant.UserHandler
var roleHandler *tenant.RoleHandler
if pool != nil {
    deptStore := tenant.NewDepartmentStore()
    userMgmtStore := tenant.NewUserStore()
    roleStore := tenant.NewRoleStore()
    deptHandler = tenant.NewDepartmentHandler(pool, deptStore)
    userHandler = tenant.NewUserHandler(pool, userMgmtStore, deptStore)
    roleHandler = tenant.NewRoleHandler(pool, roleStore, userMgmtStore)
}
```

Update the `server.Dependencies` to include the new handlers:

```go
srv := server.New(addr, server.Dependencies{
    Pool:              pool,
    Auth:              tokenSvc,
    AuthHandler:       authHandler,
    RBAC:              rbacEngine,
    TenantHandler:     tenantHandler,
    DepartmentHandler: deptHandler,
    UserHandler:       userHandler,
    RoleHandler:       roleHandler,
    DevMode:           cfg.Auth.DevMode,
    DevIdentity:       devIdentity,
    Logger:            logger,
})
```

**Step 2: Verify compilation and startup**

Run: `go build ./cmd/valinor/`
Expected: Compiles successfully.

**Step 3: Commit**

```bash
git add cmd/valinor/main.go
git commit -m "feat: wire department/user/role handlers in main.go"
```

---

### Task 12: End-to-End Integration Test

Test the full flow: create tenant → create department → create user → add to department → create role → assign role.

**Files:**
- Create: `internal/tenant/integration_test.go`

**Step 1: Write the integration test**

```go
package tenant_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
	"github.com/valinor-ai/valinor/internal/platform/server"
	"github.com/valinor-ai/valinor/internal/rbac"
	"github.com/valinor-ai/valinor/internal/tenant"
)

func TestEndToEnd_TenantOrgSetup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	pool, cleanup := setupTestDB(t)
	defer cleanup()

	// Create all stores and handlers
	tenantStore := tenant.NewStore(pool)
	deptStore := tenant.NewDepartmentStore()
	userStore := tenant.NewUserStore()
	roleStore := tenant.NewRoleStore()

	tenantHandler := tenant.NewHandler(tenantStore)
	deptHandler := tenant.NewDepartmentHandler(pool, deptStore)
	userHandler := tenant.NewUserHandler(pool, userStore, deptStore)
	roleHandler := tenant.NewRoleHandler(pool, roleStore, userStore)

	// Wire up server with RBAC
	tokenSvc := auth.NewTokenService("test-signing-key-must-be-32-chars!!", "test", 24, 168)
	rbacEngine := rbac.NewEvaluator(nil)
	rbacEngine.RegisterRole("org_admin", []string{"*"})

	srv := server.New(":0", server.Dependencies{
		Pool:              pool,
		Auth:              tokenSvc,
		RBAC:              rbacEngine,
		TenantHandler:     tenantHandler,
		DepartmentHandler: deptHandler,
		UserHandler:       userHandler,
		RoleHandler:       roleHandler,
		DevMode:           true,
		DevIdentity: &auth.Identity{
			UserID:          "e2e-admin",
			TenantID:        "will-be-set-per-request",
			Roles:           []string{"org_admin"},
			IsPlatformAdmin: true,
		},
	})

	handler := srv.Handler()

	// Step 1: Create tenant (platform admin)
	body := `{"name": "Chelsea FC", "slug": "chelsea-fc"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer dev")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code, "create tenant: %s", w.Body.String())

	var tenantResp tenant.Tenant
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &tenantResp))
	tenantID := tenantResp.ID

	// For remaining requests, we need a token with the real tenant ID
	devIdentity := &auth.Identity{
		UserID:   "e2e-admin",
		TenantID: tenantID,
		Roles:    []string{"org_admin"},
	}
	accessToken, err := tokenSvc.CreateAccessToken(devIdentity)
	require.NoError(t, err)

	// Step 2: Create departments
	for _, deptName := range []string{"Scouting", "First Team", "Academy"} {
		body = `{"name": "` + deptName + `"}`
		req = httptest.NewRequest(http.MethodPost, "/api/v1/departments", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+accessToken)
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusCreated, w.Code, "create dept %s: %s", deptName, w.Body.String())
	}

	// Step 3: List departments
	req = httptest.NewRequest(http.MethodGet, "/api/v1/departments", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var departments []tenant.Department
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &departments))
	assert.Len(t, departments, 3)

	scoutingDeptID := departments[0].ID // "Scouting" — first created

	// Step 4: Create user
	body = `{"email": "scout-a@chelsea.com", "display_name": "Scout A"}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code, "create user: %s", w.Body.String())

	var userResp tenant.User
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &userResp))
	userID := userResp.ID

	// Step 5: Add user to Scouting department
	body = `{"department_id": "` + scoutingDeptID + `"}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/users/"+userID+"/departments", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "add to dept: %s", w.Body.String())

	// Step 6: Create role
	body = `{"name": "scout", "permissions": ["agents:read", "agents:message"]}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/roles", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code, "create role: %s", w.Body.String())

	var roleResp tenant.Role
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &roleResp))
	roleID := roleResp.ID

	// Step 7: Assign role to user (scoped to department)
	body = `{"role_id": "` + roleID + `", "scope_type": "department", "scope_id": "` + scoutingDeptID + `"}`
	req = httptest.NewRequest(http.MethodPost, "/api/v1/users/"+userID+"/roles", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "assign role: %s", w.Body.String())

	// Step 8: Verify user's roles
	req = httptest.NewRequest(http.MethodGet, "/api/v1/users/"+userID+"/roles", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var userRoles []tenant.UserRole
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &userRoles))
	assert.Len(t, userRoles, 1)
	assert.Equal(t, "scout", userRoles[0].RoleName)
	assert.Equal(t, "department", userRoles[0].ScopeType)
	assert.Equal(t, scoutingDeptID, userRoles[0].ScopeID)
}
```

**Step 2: Run the integration test**

Run: `go test ./internal/tenant/ -run TestEndToEnd -v -count=1`
Expected: PASS

**Step 3: Run ALL tests to verify nothing is broken**

Run: `go test ./... -count=1`
Expected: All PASS (skip integration tests without DB by default; with DB: all pass)

**Step 4: Commit**

```bash
git add internal/tenant/integration_test.go
git commit -m "feat: add end-to-end integration test for tenant org setup flow"
```

---

## Post-Implementation Notes

### What this plan does NOT include (deferred):

1. **Rate limiting** (Phase 3 backlog P2 item #5) — deferred to Phase 6 (Security + Audit)
2. **Audit logging** (Phase 3 backlog P2 item #6) — deferred to Phase 6
3. **Department UPDATE/DELETE** — not in MVP API surface; add when admin dashboard needs it
4. **User UPDATE/DELETE** — same rationale
5. **Custom role UPDATE/DELETE** — same rationale
6. **Pagination** on list endpoints — add when data volumes require it

### Patterns established for future modules:

- **RLS-scoped store pattern**: Store methods accept `database.Querier`, handlers call `WithTenantConnection`
- **Tenant-scoped INSERT**: Use `current_setting('app.current_tenant_id', true)::UUID` for `tenant_id`
- **Cross-tenant FK safety**: Validate references via GetByID (RLS-filtered) before INSERT
- **Handler test pattern**: `withTenantIdentity()` + `wrapWithTenantCtx()` + httptest
