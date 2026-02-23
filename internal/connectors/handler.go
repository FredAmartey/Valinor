package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/valinor-ai/valinor/internal/platform/database"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
)

var (
	errTenantContextRequired = errors.New("tenant context required")
	errTenantPathMismatch    = errors.New("tenant path does not match authenticated tenant")
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
// POST /api/v1/connectors
func (h *Handler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 10<<10)

	tenantID, err := resolveTenantID(r)
	if err != nil {
		writeTenantError(w, err)
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
	if decodeErr := json.NewDecoder(r.Body).Decode(&req); decodeErr != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	var connector *Connector
	err = database.WithTenantConnection(r.Context(), h.pool, tenantID, func(ctx context.Context, q database.Querier) error {
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

// HandleList returns all connectors for the tenant.
// GET /api/v1/connectors
func (h *Handler) HandleList(w http.ResponseWriter, r *http.Request) {
	tenantID, err := resolveTenantID(r)
	if err != nil {
		writeTenantError(w, err)
		return
	}

	var list []Connector
	err = database.WithTenantConnection(r.Context(), h.pool, tenantID, func(ctx context.Context, q database.Querier) error {
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

	tenantID, err := resolveTenantID(r)
	if err != nil {
		writeTenantError(w, err)
		return
	}

	err = database.WithTenantConnection(r.Context(), h.pool, tenantID, func(ctx context.Context, q database.Querier) error {
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

func resolveTenantID(r *http.Request) (string, error) {
	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		return "", errTenantContextRequired
	}

	pathTenantID := r.PathValue("tenantID")
	if pathTenantID != "" && pathTenantID != tenantID {
		return "", errTenantPathMismatch
	}

	return tenantID, nil
}

func writeTenantError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errTenantContextRequired):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	case errors.Is(err, errTenantPathMismatch):
		writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
