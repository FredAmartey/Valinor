package tenant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/valinor-ai/valinor/internal/platform/database"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
)

// RBACReloader is called after role mutations to refresh the evaluator.
type RBACReloader interface {
	ReloadRoles(ctx context.Context) error
}

// RoleHandler handles role HTTP endpoints within a tenant.
type RoleHandler struct {
	pool      *pgxpool.Pool
	store     *RoleStore
	userStore *UserStore
	deptStore *DepartmentStore
	evaluator RBACReloader
}

// NewRoleHandler creates a new role handler.
func NewRoleHandler(pool *pgxpool.Pool, store *RoleStore, userStore *UserStore, deptStore *DepartmentStore, evaluator RBACReloader) *RoleHandler {
	return &RoleHandler{pool: pool, store: store, userStore: userStore, deptStore: deptStore, evaluator: evaluator}
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

	if h.evaluator != nil {
		if err := h.evaluator.ReloadRoles(r.Context()); err != nil {
			slog.Error("failed to reload RBAC roles after create", "error", err)
		}
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

	if h.evaluator != nil {
		if err := h.evaluator.ReloadRoles(r.Context()); err != nil {
			slog.Error("failed to reload RBAC roles after update", "error", err)
		}
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

	if h.evaluator != nil {
		if err := h.evaluator.ReloadRoles(r.Context()); err != nil {
			slog.Error("failed to reload RBAC roles after delete", "error", err)
		}
	}

	w.WriteHeader(http.StatusNoContent)
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
		// Verify role exists in this tenant (RLS enforced)
		if _, getErr := h.store.GetByID(ctx, q, req.RoleID); getErr != nil {
			return getErr
		}
		// Verify scope_id references a valid entity in this tenant
		if req.ScopeType == "department" {
			if _, getErr := h.deptStore.GetByID(ctx, q, req.ScopeID); getErr != nil {
				return fmt.Errorf("invalid scope: %w", getErr)
			}
		}
		return h.store.AssignToUser(ctx, q, userID, req.RoleID, req.ScopeType, req.ScopeID)
	})
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}
		if errors.Is(err, ErrRoleNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "role not found"})
			return
		}
		if errors.Is(err, ErrDepartmentNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "department not found"})
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
