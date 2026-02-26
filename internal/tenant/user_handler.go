package tenant

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/valinor-ai/valinor/internal/audit"
	"github.com/valinor-ai/valinor/internal/platform/database"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
)

// UserHandler handles user HTTP endpoints within a tenant.
type UserHandler struct {
	pool      *pgxpool.Pool
	store     *UserStore
	deptStore *DepartmentStore
	auditLog  audit.Logger
}

// NewUserHandler creates a new user handler.
func NewUserHandler(pool *pgxpool.Pool, store *UserStore, deptStore *DepartmentStore, auditLog audit.Logger) *UserHandler {
	return &UserHandler{pool: pool, store: store, deptStore: deptStore, auditLog: auditLog}
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
