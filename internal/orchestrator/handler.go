package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
)

// ConfigPusher pushes config to a running agent over vsock.
type ConfigPusher interface {
	PushConfig(ctx context.Context, agentID string, cid uint32, config map[string]any, toolAllowlist []string, toolPolicies map[string]any, canaryTokens []string) error
}

// Handler handles HTTP requests for agent lifecycle.
type Handler struct {
	manager      *Manager
	configPusher ConfigPusher // optional, nil = no vsock push
}

// NewHandler creates a new orchestrator Handler.
func NewHandler(manager *Manager, pusher ConfigPusher) *Handler {
	return &Handler{manager: manager, configPusher: pusher}
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
		UserID       *string        `json:"user_id,omitempty"`
		DepartmentID *string        `json:"department_id,omitempty"`
		Config       map[string]any `json:"config,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err.Error() != "EOF" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	// Validate department_id is a valid UUID if provided.
	if req.DepartmentID != nil {
		if _, err := uuid.Parse(*req.DepartmentID); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "department_id must be a valid UUID"})
			return
		}
	}

	identity := auth.GetIdentity(r.Context())
	if identity == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}
	if identity.IsPlatformAdmin {
		if req.UserID != nil {
			userID := strings.TrimSpace(*req.UserID)
			if userID == "" {
				req.UserID = nil
			} else {
				req.UserID = &userID
			}
		}
	} else {
		callerUserID := strings.TrimSpace(identity.UserID)
		if callerUserID == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "user identity required"})
			return
		}
		if req.UserID != nil {
			requestedUserID := strings.TrimSpace(*req.UserID)
			if requestedUserID != "" && requestedUserID != callerUserID {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "user_id must match authenticated user"})
				return
			}
		}
		req.UserID = &callerUserID
	}

	inst, err := h.manager.Provision(r.Context(), tenantID, ProvisionOpts{
		UserID:       req.UserID,
		DepartmentID: req.DepartmentID,
		Config:       req.Config,
	})
	if err != nil {
		slog.Error("provision failed", "tenant", tenantID, "error", err)
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

	// Verify tenant ownership (or platform admin). Fail closed if identity missing.
	identity := auth.GetIdentity(r.Context())
	if identity == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}
	if !identity.IsPlatformAdmin {
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

	writeJSON(w, http.StatusOK, struct {
		Agents []AgentInstance `json:"agents"`
	}{Agents: agents})
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
	if identity == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}
	if !identity.IsPlatformAdmin {
		tenantID := middleware.GetTenantID(r.Context())
		if inst.TenantID == nil || *inst.TenantID != tenantID {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
			return
		}
	}

	if err := h.manager.Destroy(r.Context(), id); err != nil {
		slog.Error("destroy failed", "id", id, "error", err)
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
	if identity == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}
	if !identity.IsPlatformAdmin {
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
	if decodeErr := json.NewDecoder(r.Body).Decode(&req); decodeErr != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	normalizedConfig, policyErr := enforceOpenClawRuntimePolicy(req.Config)
	if policyErr != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": policyErr.Error()})
		return
	}
	req.Config = normalizedConfig

	configJSON, err := json.Marshal(req.Config)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid config"})
		return
	}
	allowlistJSON, err := json.Marshal(req.ToolAllowlist)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid tool_allowlist"})
		return
	}

	if updateErr := h.manager.UpdateConfig(r.Context(), id, string(configJSON), string(allowlistJSON)); updateErr != nil {
		slog.Error("configure failed", "id", id, "error", updateErr)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "update failed"})
		return
	}

	// Best-effort push to running agent via vsock
	if h.configPusher != nil && inst.Status == StatusRunning && inst.VsockCID != nil {
		if pushErr := h.configPusher.PushConfig(r.Context(), id, *inst.VsockCID, req.Config, req.ToolAllowlist, nil, nil); pushErr != nil {
			slog.Warn("config push to agent failed", "id", id, "error", pushErr)
		}
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
