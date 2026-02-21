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
