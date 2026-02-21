package tenant

import (
	"encoding/json"
	"errors"
	"net/http"
)

// Handler handles tenant HTTP endpoints.
type Handler struct {
	store *Store
}

// NewHandler creates a new tenant handler.
func NewHandler(store *Store) *Handler {
	return &Handler{store: store}
}

// RegisterRoutes registers tenant routes on the given mux.
// All routes require platform admin auth (applied externally via middleware).
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/tenants", h.HandleCreate)
	mux.HandleFunc("GET /api/v1/tenants/{id}", h.HandleGet)
	mux.HandleFunc("GET /api/v1/tenants", h.HandleList)
}

// HandleCreate creates a new tenant.
func (h *Handler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 10<<10)

	var req struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if req.Name == "" || req.Slug == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name and slug are required"})
		return
	}

	t, err := h.store.Create(r.Context(), req.Name, req.Slug)
	if err != nil {
		if errors.Is(err, ErrInvalidSlug) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if errors.Is(err, ErrSlugTaken) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "tenant creation failed"})
		return
	}

	writeJSON(w, http.StatusCreated, t)
}

// HandleGet returns a tenant by ID.
func (h *Handler) HandleGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing tenant id"})
		return
	}

	t, err := h.store.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrTenantNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "tenant not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "fetching tenant failed"})
		return
	}

	writeJSON(w, http.StatusOK, t)
}

// HandleList returns all tenants.
func (h *Handler) HandleList(w http.ResponseWriter, r *http.Request) {
	tenants, err := h.store.List(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "listing tenants failed"})
		return
	}

	if tenants == nil {
		tenants = []Tenant{}
	}

	writeJSON(w, http.StatusOK, tenants)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
