package orchestrator

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
)

// Handler handles HTTP requests for agent lifecycle.
type Handler struct {
	manager *Manager
}

// NewHandler creates a new orchestrator Handler.
func NewHandler(manager *Manager) *Handler {
	return &Handler{manager: manager}
}

// HandleProvision creates a new agent for the caller's tenant.
// POST /api/v1/agents
func (h *Handler) HandleProvision(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 10<<10)

	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant context required"})
		return
	}

	var req struct {
		DepartmentID *string        `json:"department_id,omitempty"`
		Config       map[string]any `json:"config,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err.Error() != "EOF" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	inst, err := h.manager.Provision(r.Context(), tenantID, ProvisionOpts{
		DepartmentID: req.DepartmentID,
		Config:       req.Config,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "provisioning failed"})
		return
	}

	writeJSON(w, http.StatusCreated, inst)
}

// HandleGetAgent returns agent details.
// GET /api/v1/agents/{id}
func (h *Handler) HandleGetAgent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id is required"})
		return
	}

	inst, err := h.manager.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrVMNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "lookup failed"})
		return
	}

	// Verify tenant ownership (or platform admin)
	identity := auth.GetIdentity(r.Context())
	if identity != nil && !identity.IsPlatformAdmin {
		tenantID := middleware.GetTenantID(r.Context())
		if inst.TenantID == nil || *inst.TenantID != tenantID {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
			return
		}
	}

	writeJSON(w, http.StatusOK, inst)
}

// HandleListAgents returns all agents for the caller's tenant.
// GET /api/v1/agents
func (h *Handler) HandleListAgents(w http.ResponseWriter, r *http.Request) {
	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant context required"})
		return
	}

	agents, err := h.manager.ListByTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list agents"})
		return
	}

	if agents == nil {
		agents = []AgentInstance{}
	}

	writeJSON(w, http.StatusOK, map[string]any{"agents": agents})
}

// HandleDestroyAgent destroys an agent and its VM.
// DELETE /api/v1/agents/{id}
func (h *Handler) HandleDestroyAgent(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id is required"})
		return
	}

	// Verify tenant ownership
	inst, err := h.manager.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrVMNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "lookup failed"})
		return
	}

	identity := auth.GetIdentity(r.Context())
	if identity != nil && !identity.IsPlatformAdmin {
		tenantID := middleware.GetTenantID(r.Context())
		if inst.TenantID == nil || *inst.TenantID != tenantID {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
			return
		}
	}

	if err := h.manager.Destroy(r.Context(), id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "destroy failed"})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// HandleConfigure updates an agent's config and tool allow-list.
// POST /api/v1/agents/{id}/configure
func (h *Handler) HandleConfigure(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 10<<10)

	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id is required"})
		return
	}

	// Verify tenant ownership
	inst, err := h.manager.GetByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, ErrVMNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "lookup failed"})
		return
	}

	identity := auth.GetIdentity(r.Context())
	if identity != nil && !identity.IsPlatformAdmin {
		tenantID := middleware.GetTenantID(r.Context())
		if inst.TenantID == nil || *inst.TenantID != tenantID {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
			return
		}
	}

	var req struct {
		Config        map[string]any `json:"config"`
		ToolAllowlist []string       `json:"tool_allowlist"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	configJSON, _ := json.Marshal(req.Config)
	allowlistJSON, _ := json.Marshal(req.ToolAllowlist)

	if err := h.manager.UpdateConfig(r.Context(), id, string(configJSON), string(allowlistJSON)); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "update failed"})
		return
	}

	// Return updated instance
	updated, err := h.manager.GetByID(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "lookup failed"})
		return
	}

	writeJSON(w, http.StatusOK, updated)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
