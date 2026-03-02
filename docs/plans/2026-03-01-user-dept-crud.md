# User & Department CRUD Completion — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add update and delete operations for users and departments across all layers in a single PR.

**Architecture:** Store → Handler → Route → Query hook → UI. Users soft-delete via existing `status` column. Departments hard-delete with CASCADE to `user_departments`. Inline edit on detail pages (no new routes).

**Tech Stack:** Go 1.25, pgx v5, Next.js 16, TanStack Query v5, Tailwind CSS v4, shadcn/ui

**Design doc:** `docs/plans/2026-03-01-user-dept-crud-design.md`

**Frontend skills:** Before writing any dashboard code, invoke: `vercel-react-best-practices`, `design-taste-frontend`, `next-best-practices` (per CLAUDE.md).

---

### Task 1: User store — Update and SoftDelete

**Files:**
- Modify: `internal/tenant/user_store.go` (append after `ListDepartments` method, ~line 129)
- Test: `internal/tenant/user_store_test.go` (append new subtests)

**Step 1: Write the failing tests**

Append to `internal/tenant/user_store_test.go`, inside a new test or after the existing `TestUserStore` function:

```go
func TestUserStore_Update(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ownerPool, rlsPool, cleanup := setupTestDBWithRLS(t)
	defer cleanup()

	ctx := context.Background()
	tenantStore := tenant.NewStore(ownerPool)
	ten, err := tenantStore.Create(ctx, "Update Org", "update-org")
	require.NoError(t, err)

	userStore := tenant.NewUserStore()

	t.Run("Update_DisplayName", func(t *testing.T) {
		err := database.WithTenantConnection(ctx, rlsPool, ten.ID, func(ctx context.Context, q database.Querier) error {
			user, createErr := userStore.Create(ctx, q, "update@example.com", "Original")
			require.NoError(t, createErr)

			updated, updateErr := userStore.Update(ctx, q, user.ID, "Updated Name", "")
			require.NoError(t, updateErr)
			assert.Equal(t, "Updated Name", updated.DisplayName)
			assert.Equal(t, "active", updated.Status)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("Update_Status", func(t *testing.T) {
		err := database.WithTenantConnection(ctx, rlsPool, ten.ID, func(ctx context.Context, q database.Querier) error {
			user, createErr := userStore.Create(ctx, q, "suspend@example.com", "Suspend Me")
			require.NoError(t, createErr)

			updated, updateErr := userStore.Update(ctx, q, user.ID, "", "suspended")
			require.NoError(t, updateErr)
			assert.Equal(t, "suspended", updated.Status)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("Update_NotFound", func(t *testing.T) {
		err := database.WithTenantConnection(ctx, rlsPool, ten.ID, func(ctx context.Context, q database.Querier) error {
			_, updateErr := userStore.Update(ctx, q, "00000000-0000-0000-0000-000000000000", "Name", "")
			assert.ErrorIs(t, updateErr, tenant.ErrUserNotFound)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("SoftDelete", func(t *testing.T) {
		err := database.WithTenantConnection(ctx, rlsPool, ten.ID, func(ctx context.Context, q database.Querier) error {
			user, createErr := userStore.Create(ctx, q, "delete@example.com", "Delete Me")
			require.NoError(t, createErr)

			deleteErr := userStore.SoftDelete(ctx, q, user.ID)
			require.NoError(t, deleteErr)

			got, getErr := userStore.GetByID(ctx, q, user.ID)
			require.NoError(t, getErr)
			assert.Equal(t, "suspended", got.Status)
			return nil
		})
		require.NoError(t, err)
	})
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/tenant/ -run TestUserStore_Update -v -count=1`
Expected: Compile error — `Update` and `SoftDelete` methods don't exist yet.

**Step 3: Implement Update and SoftDelete**

Append to `internal/tenant/user_store.go` after `ListDepartments`:

```go
// Update modifies a user's display_name and/or status. Empty string values
// are ignored (the existing value is preserved). RLS ensures tenant isolation.
func (s *UserStore) Update(ctx context.Context, q database.Querier, id, displayName, status string) (*User, error) {
	var user User
	err := q.QueryRow(ctx,
		`UPDATE users
		 SET display_name = CASE WHEN $2 = '' THEN display_name ELSE $2 END,
		     status       = CASE WHEN $3 = '' THEN status ELSE $3 END
		 WHERE id = $1
		 RETURNING id, tenant_id, email, COALESCE(display_name, ''), status, created_at`,
		id, displayName, status,
	).Scan(&user.ID, &user.TenantID, &user.Email, &user.DisplayName, &user.Status, &user.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("updating user: %w", err)
	}
	return &user, nil
}

// SoftDelete sets a user's status to "suspended".
func (s *UserStore) SoftDelete(ctx context.Context, q database.Querier, id string) error {
	tag, err := q.Exec(ctx,
		`UPDATE users SET status = 'suspended' WHERE id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("soft-deleting user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrUserNotFound
	}
	return nil
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/tenant/ -run TestUserStore_Update -v -count=1`
Expected: All 4 subtests PASS.

**Step 5: Commit**

```bash
git add internal/tenant/user_store.go internal/tenant/user_store_test.go
git commit -m "feat(users): add Update and SoftDelete store methods"
```

---

### Task 2: Department store — Update and Delete

**Files:**
- Modify: `internal/tenant/department_store.go` (append after `List` method, ~line 85)
- Test: `internal/tenant/department_store_test.go` (append new subtests)

**Step 1: Write the failing tests**

Append to `internal/tenant/department_store_test.go`:

```go
func TestDepartmentStore_Update(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ownerPool, rlsPool, cleanup := setupTestDBWithRLS(t)
	defer cleanup()

	ctx := context.Background()
	tenantStore := tenant.NewStore(ownerPool)
	ten, err := tenantStore.Create(ctx, "Dept Update Org", "dept-update-org")
	require.NoError(t, err)

	store := tenant.NewDepartmentStore()

	t.Run("Update_Name", func(t *testing.T) {
		err := database.WithTenantConnection(ctx, rlsPool, ten.ID, func(ctx context.Context, q database.Querier) error {
			dept, createErr := store.Create(ctx, q, "Old Name", nil)
			require.NoError(t, createErr)

			updated, updateErr := store.Update(ctx, q, dept.ID, "New Name", nil)
			require.NoError(t, updateErr)
			assert.Equal(t, "New Name", updated.Name)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("Update_Parent", func(t *testing.T) {
		err := database.WithTenantConnection(ctx, rlsPool, ten.ID, func(ctx context.Context, q database.Querier) error {
			parent, createErr := store.Create(ctx, q, "Parent Dept", nil)
			require.NoError(t, createErr)
			child, createErr := store.Create(ctx, q, "Child Dept", nil)
			require.NoError(t, createErr)

			updated, updateErr := store.Update(ctx, q, child.ID, "", &parent.ID)
			require.NoError(t, updateErr)
			assert.Equal(t, &parent.ID, updated.ParentID)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("Update_NotFound", func(t *testing.T) {
		err := database.WithTenantConnection(ctx, rlsPool, ten.ID, func(ctx context.Context, q database.Querier) error {
			_, updateErr := store.Update(ctx, q, "00000000-0000-0000-0000-000000000000", "Name", nil)
			assert.ErrorIs(t, updateErr, tenant.ErrDepartmentNotFound)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("Delete", func(t *testing.T) {
		err := database.WithTenantConnection(ctx, rlsPool, ten.ID, func(ctx context.Context, q database.Querier) error {
			dept, createErr := store.Create(ctx, q, "To Delete", nil)
			require.NoError(t, createErr)

			deleteErr := store.Delete(ctx, q, dept.ID)
			require.NoError(t, deleteErr)

			_, getErr := store.GetByID(ctx, q, dept.ID)
			assert.ErrorIs(t, getErr, tenant.ErrDepartmentNotFound)
			return nil
		})
		require.NoError(t, err)
	})

	t.Run("Delete_NotFound", func(t *testing.T) {
		err := database.WithTenantConnection(ctx, rlsPool, ten.ID, func(ctx context.Context, q database.Querier) error {
			deleteErr := store.Delete(ctx, q, "00000000-0000-0000-0000-000000000000")
			assert.ErrorIs(t, deleteErr, tenant.ErrDepartmentNotFound)
			return nil
		})
		require.NoError(t, err)
	})
}
```

**Step 2: Run tests to verify they fail**

Run: `go test ./internal/tenant/ -run TestDepartmentStore_Update -v -count=1`
Expected: Compile error — `Update` and `Delete` methods don't exist yet.

**Step 3: Implement Update and Delete**

Append to `internal/tenant/department_store.go` after `List`:

```go
// Update modifies a department's name and/or parent. An empty name preserves
// the current value. Pass a non-nil parentID to change parent, or nil to keep it.
// To clear the parent (make top-level), pass a pointer to an empty string.
func (s *DepartmentStore) Update(ctx context.Context, q database.Querier, id, name string, parentID *string) (*Department, error) {
	// Use current name if empty string provided
	query := `UPDATE departments
		SET name      = CASE WHEN $2 = '' THEN name ELSE $2 END,
		    parent_id = CASE WHEN $3::BOOLEAN THEN $4::UUID ELSE parent_id END
		WHERE id = $1
		RETURNING id, tenant_id, name, parent_id, created_at`

	updateParent := parentID != nil
	var parentVal *string
	if parentID != nil && *parentID != "" {
		parentVal = parentID
	}

	var dept Department
	err := q.QueryRow(ctx, query, id, name, updateParent, parentVal).
		Scan(&dept.ID, &dept.TenantID, &dept.Name, &dept.ParentID, &dept.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrDepartmentNotFound
		}
		return nil, fmt.Errorf("updating department: %w", err)
	}
	return &dept, nil
}

// Delete removes a department. CASCADE on user_departments removes memberships.
func (s *DepartmentStore) Delete(ctx context.Context, q database.Querier, id string) error {
	tag, err := q.Exec(ctx, `DELETE FROM departments WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("deleting department: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrDepartmentNotFound
	}
	return nil
}
```

**Step 4: Run tests to verify they pass**

Run: `go test ./internal/tenant/ -run TestDepartmentStore_Update -v -count=1`
Expected: All 5 subtests PASS.

**Step 5: Commit**

```bash
git add internal/tenant/department_store.go internal/tenant/department_store_test.go
git commit -m "feat(departments): add Update and Delete store methods"
```

---

### Task 3: User handler — HandleUpdate and HandleDelete

**Files:**
- Modify: `internal/tenant/user_handler.go` (append after `HandleRemoveFromDepartment`, ~line 281)

**Step 1: Write HandleUpdate and HandleDelete**

Append to `internal/tenant/user_handler.go`:

```go
// HandleUpdate modifies a user's display_name and/or status.
func (h *UserHandler) HandleUpdate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 10<<10)

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

	var req struct {
		DisplayName string `json:"display_name"`
		Status      string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	// Validate status if provided
	if req.Status != "" && req.Status != "active" && req.Status != "suspended" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "status must be 'active' or 'suspended'"})
		return
	}

	var user *User
	err := database.WithTenantConnection(r.Context(), h.pool, tenantID, func(ctx context.Context, q database.Querier) error {
		var updateErr error
		user, updateErr = h.store.Update(ctx, q, id, req.DisplayName, req.Status)
		return updateErr
	})
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "updating user failed"})
		return
	}

	if h.auditLog != nil {
		tenantUUID, _ := uuid.Parse(tenantID)
		userUUID, _ := uuid.Parse(user.ID)
		h.auditLog.Log(r.Context(), audit.Event{
			TenantID:     tenantUUID,
			UserID:       audit.ActorIDFromContext(r.Context()),
			Action:       audit.ActionUserUpdated,
			ResourceType: "user",
			ResourceID:   &userUUID,
			Metadata:     map[string]any{"display_name": user.DisplayName, "status": user.Status},
			Source:       "api",
		})
	}

	writeJSON(w, http.StatusOK, user)
}

// HandleDelete soft-deletes a user by setting status to "suspended".
func (h *UserHandler) HandleDelete(w http.ResponseWriter, r *http.Request) {
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

	err := database.WithTenantConnection(r.Context(), h.pool, tenantID, func(ctx context.Context, q database.Querier) error {
		return h.store.SoftDelete(ctx, q, id)
	})
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "deleting user failed"})
		return
	}

	if h.auditLog != nil {
		tenantUUID, _ := uuid.Parse(tenantID)
		userUUID, _ := uuid.Parse(id)
		h.auditLog.Log(r.Context(), audit.Event{
			TenantID:     tenantUUID,
			UserID:       audit.ActorIDFromContext(r.Context()),
			Action:       audit.ActionUserSuspended,
			ResourceType: "user",
			ResourceID:   &userUUID,
			Source:       "api",
		})
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
```

**Step 2: Verify build**

Run: `go build ./cmd/valinor`
Expected: Clean build.

**Step 3: Commit**

```bash
git add internal/tenant/user_handler.go
git commit -m "feat(users): add HandleUpdate and HandleDelete handlers"
```

---

### Task 4: Department handler — HandleUpdate and HandleDelete

**Files:**
- Modify: `internal/tenant/department_handler.go` (append after `HandleList`, ~line 139)

**Step 1: Write HandleUpdate and HandleDelete**

Append to `internal/tenant/department_handler.go`:

```go
// HandleUpdate modifies a department's name and/or parent.
func (h *DepartmentHandler) HandleUpdate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 10<<10)

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

	var req struct {
		Name     string  `json:"name"`
		ParentID *string `json:"parent_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	var dept *Department
	err := database.WithTenantConnection(r.Context(), h.pool, tenantID, func(ctx context.Context, q database.Querier) error {
		var updateErr error
		dept, updateErr = h.store.Update(ctx, q, id, req.Name, req.ParentID)
		return updateErr
	})
	if err != nil {
		if errors.Is(err, ErrDepartmentNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "department not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "updating department failed"})
		return
	}

	if h.auditLog != nil {
		tenantUUID, _ := uuid.Parse(tenantID)
		deptUUID, _ := uuid.Parse(dept.ID)
		h.auditLog.Log(r.Context(), audit.Event{
			TenantID:     tenantUUID,
			UserID:       audit.ActorIDFromContext(r.Context()),
			Action:       audit.ActionDepartmentUpdated,
			ResourceType: "department",
			ResourceID:   &deptUUID,
			Metadata:     map[string]any{"name": dept.Name},
			Source:       "api",
		})
	}

	writeJSON(w, http.StatusOK, dept)
}

// HandleDelete hard-deletes a department. Cascading FK removes user_departments rows.
func (h *DepartmentHandler) HandleDelete(w http.ResponseWriter, r *http.Request) {
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

	err := database.WithTenantConnection(r.Context(), h.pool, tenantID, func(ctx context.Context, q database.Querier) error {
		return h.store.Delete(ctx, q, id)
	})
	if err != nil {
		if errors.Is(err, ErrDepartmentNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "department not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "deleting department failed"})
		return
	}

	if h.auditLog != nil {
		tenantUUID, _ := uuid.Parse(tenantID)
		deptUUID, _ := uuid.Parse(id)
		h.auditLog.Log(r.Context(), audit.Event{
			TenantID:     tenantUUID,
			UserID:       audit.ActorIDFromContext(r.Context()),
			Action:       audit.ActionDepartmentDeleted,
			ResourceType: "department",
			ResourceID:   &deptUUID,
			Source:       "api",
		})
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
```

**Step 2: Verify build**

Run: `go build ./cmd/valinor`
Expected: Clean build.

**Step 3: Commit**

```bash
git add internal/tenant/department_handler.go
git commit -m "feat(departments): add HandleUpdate and HandleDelete handlers"
```

---

### Task 5: Register routes

**Files:**
- Modify: `internal/platform/server/server.go` (~lines 170-221, within the department and user route blocks)

**Step 1: Add PUT and DELETE routes**

Inside the `if deps.DepartmentHandler != nil && deps.RBAC != nil` block (after the GET /api/v1/departments route, ~line 186), add:

```go
		protectedMux.Handle("PUT /api/v1/departments/{id}",
			rbac.RequirePermission(deps.RBAC, "departments:write", rbacOpts...)(
				http.HandlerFunc(deps.DepartmentHandler.HandleUpdate),
			),
		)
		protectedMux.Handle("DELETE /api/v1/departments/{id}",
			rbac.RequirePermission(deps.RBAC, "departments:write", rbacOpts...)(
				http.HandlerFunc(deps.DepartmentHandler.HandleDelete),
			),
		)
```

Inside the `if deps.UserHandler != nil && deps.RBAC != nil` block (after the DELETE /api/v1/users/{id}/departments/{deptId} route, ~line 220), add:

```go
		protectedMux.Handle("PUT /api/v1/users/{id}",
			rbac.RequirePermission(deps.RBAC, "users:write", rbacOpts...)(
				http.HandlerFunc(deps.UserHandler.HandleUpdate),
			),
		)
		protectedMux.Handle("DELETE /api/v1/users/{id}",
			rbac.RequirePermission(deps.RBAC, "users:write", rbacOpts...)(
				http.HandlerFunc(deps.UserHandler.HandleDelete),
			),
		)
```

**Step 2: Verify build + all backend tests**

Run: `go build ./cmd/valinor && go test ./internal/tenant/ -v -count=1`
Expected: Clean build, all tests pass (existing + new).

**Step 3: Commit**

```bash
git add internal/platform/server/server.go
git commit -m "feat: register PUT/DELETE routes for users and departments"
```

---

### Task 6: Frontend types

**Files:**
- Modify: `dashboard/src/lib/types.ts`

**Step 1: Add request interfaces**

After the `CreateUserRequest` interface, add:

```typescript
export interface UpdateUserRequest {
  display_name?: string
  status?: "active" | "suspended"
}
```

After the `CreateDepartmentRequest` interface, add:

```typescript
export interface UpdateDepartmentRequest {
  name?: string
  parent_id?: string | null
}
```

**Step 2: Verify types**

Run: `cd dashboard && npx tsc --noEmit`
Expected: No errors.

**Step 3: Commit**

```bash
git add dashboard/src/lib/types.ts
git commit -m "feat(dashboard): add UpdateUserRequest and UpdateDepartmentRequest types"
```

---

### Task 7: Frontend query hooks — users

**Files:**
- Modify: `dashboard/src/lib/queries/users.ts`

**Step 1: Add fetch functions and hooks**

After the `removeUserFromDepartment` function (~line 65), add:

```typescript
export async function updateUser(
  accessToken: string,
  id: string,
  data: UpdateUserRequest,
): Promise<User> {
  return apiClient<User>(`/api/v1/users/${id}`, accessToken, {
    method: "PUT",
    body: JSON.stringify(data),
  })
}

export async function deleteUser(
  accessToken: string,
  id: string,
): Promise<{ status: string }> {
  return apiClient<{ status: string }>(`/api/v1/users/${id}`, accessToken, {
    method: "DELETE",
  })
}
```

Update the import at the top to include `UpdateUserRequest`:

```typescript
import type { User, CreateUserRequest, UpdateUserRequest, Department } from "@/lib/types"
```

After `useRemoveUserFromDepartmentMutation` (~line 129), add:

```typescript
export function useUpdateUserMutation(id: string) {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: UpdateUserRequest) =>
      updateUser(session!.accessToken, id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: userKeys.detail(id) })
      queryClient.invalidateQueries({ queryKey: userKeys.list() })
    },
  })
}

export function useDeleteUserMutation(id: string) {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: () => deleteUser(session!.accessToken, id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: userKeys.all })
    },
  })
}
```

**Step 2: Verify types**

Run: `cd dashboard && npx tsc --noEmit`
Expected: No errors.

**Step 3: Commit**

```bash
git add dashboard/src/lib/queries/users.ts
git commit -m "feat(dashboard): add updateUser and deleteUser query hooks"
```

---

### Task 8: Frontend query hooks — departments

**Files:**
- Modify: `dashboard/src/lib/queries/departments.ts`

**Step 1: Add fetch functions and hooks**

After `createDepartment` (~line 35), add:

```typescript
export async function updateDepartment(
  accessToken: string,
  id: string,
  data: UpdateDepartmentRequest,
): Promise<Department> {
  return apiClient<Department>(`/api/v1/departments/${id}`, accessToken, {
    method: "PUT",
    body: JSON.stringify(data),
  })
}

export async function deleteDepartment(
  accessToken: string,
  id: string,
): Promise<{ status: string }> {
  return apiClient<{ status: string }>(`/api/v1/departments/${id}`, accessToken, {
    method: "DELETE",
  })
}
```

Update the import at the top:

```typescript
import type { Department, CreateDepartmentRequest, UpdateDepartmentRequest } from "@/lib/types"
```

After `useCreateDepartmentMutation` (~line 66), add:

```typescript
export function useUpdateDepartmentMutation(id: string) {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: UpdateDepartmentRequest) =>
      updateDepartment(session!.accessToken, id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: departmentKeys.detail(id) })
      queryClient.invalidateQueries({ queryKey: departmentKeys.list() })
    },
  })
}

export function useDeleteDepartmentMutation(id: string) {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: () => deleteDepartment(session!.accessToken, id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: departmentKeys.all })
    },
  })
}
```

**Step 2: Verify types**

Run: `cd dashboard && npx tsc --noEmit`
Expected: No errors.

**Step 3: Commit**

```bash
git add dashboard/src/lib/queries/departments.ts
git commit -m "feat(dashboard): add updateDepartment and deleteDepartment query hooks"
```

---

### Task 9: User detail — inline edit + delete UI

**Files:**
- Modify: `dashboard/src/components/users/user-detail.tsx`

**Step 1: Rewrite with inline edit mode**

Reference: existing `user-detail.tsx` (62 lines). Replace the entire component with an inline-edit version. The component needs:

- `editing` state boolean
- `displayName` and `status` local state for edit mode
- Edit/Save/Cancel buttons gated by `useCan("users:write")`
- Delete button with confirmation
- `useUpdateUserMutation` and `useDeleteUserMutation` hooks
- After successful delete, `router.push("/users")`

Use the same UI patterns as the existing detail pages (zinc color scheme, rounded-xl borders, text-sm). The edit mode replaces the display name text with an `<input>` and adds a status `<select>`.

Import `useCan` from `@/lib/permissions` (check if this hook exists — if not, check how `canWrite` is used in other components like `agent-detail.tsx` and follow that pattern).

**Step 2: Verify types + visual check**

Run: `cd dashboard && npx tsc --noEmit`
Expected: No errors.

Start dev server, navigate to `/users/{id}`, verify:
- Edit button appears (for org_admin)
- Clicking Edit shows input fields and Save/Cancel
- Cancel reverts to display mode
- Delete button shows confirmation dialog

**Step 3: Commit**

```bash
git add dashboard/src/components/users/user-detail.tsx
git commit -m "feat(dashboard): add inline edit and delete to user detail page"
```

---

### Task 10: Department detail — inline edit + delete UI

**Files:**
- Modify: `dashboard/src/components/departments/department-detail.tsx`

**Step 1: Rewrite with inline edit mode**

Same pattern as Task 9 but for departments:

- `editing` state boolean
- `name` local state, `parentId` state with department dropdown
- Edit/Save/Cancel buttons gated by `departments:write` permission
- Delete button with confirmation warning about cascading membership removal
- `useUpdateDepartmentMutation` and `useDeleteDepartmentMutation` hooks
- After successful delete, `router.push("/departments")`

Use `useDepartmentsQuery()` (already imported) to populate the parent dropdown.

**Step 2: Verify types + visual check**

Run: `cd dashboard && npx tsc --noEmit`
Expected: No errors.

Start dev server, navigate to `/departments/{id}`, verify:
- Edit button appears for users with write permission
- Name and parent are editable
- Delete shows confirmation about member removal
- Delete redirects to department list

**Step 3: Commit**

```bash
git add dashboard/src/components/departments/department-detail.tsx
git commit -m "feat(dashboard): add inline edit and delete to department detail page"
```

---

### Task 11: Verification + final commit

**Step 1: Run all backend tests**

Run: `go test ./internal/tenant/ -v -count=1`
Expected: All tests pass (existing + new store tests).

**Step 2: Build backend**

Run: `go build ./cmd/valinor`
Expected: Clean build.

**Step 3: Check frontend types**

Run: `cd dashboard && npx tsc --noEmit`
Expected: No errors.

**Step 4: Run frontend tests**

Run: `cd dashboard && npx vitest run`
Expected: No new failures (pre-existing failures from missing tenant/user query modules are acceptable).

**Step 5: Manual smoke test**

1. Start backend: `go run ./cmd/valinor`
2. Start dashboard: `cd dashboard && npm run dev`
3. Login as `turgon@gondolin.fc` (org_admin)
4. Navigate to Users → click a user → click Edit → change display name → Save
5. Navigate to Users → click a user → click Delete → confirm → verify redirect to list
6. Navigate to Departments → click a department → click Edit → change name → Save
7. Navigate to Departments → click a department → click Delete → confirm → verify redirect
8. Check Audit page → verify `user.updated`, `user.suspended`, `department.updated`, `department.deleted` events appear
