package tenant

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
)

// allowedInviteRoles is the set of roles that can be assigned via invite.
var allowedInviteRoles = map[string]bool{
	"org_admin":     true,
	"dept_head":     true,
	"standard_user": true,
	"read_only":     true,
}

type InviteHandler struct {
	store *InviteStore
}

func NewInviteHandler(store *InviteStore) *InviteHandler {
	return &InviteHandler{store: store}
}

func (h *InviteHandler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	identity := auth.GetIdentity(r.Context())
	if identity == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}
	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant context required"})
		return
	}

	var req struct {
		Role string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.Role == "" {
		req.Role = "standard_user"
	}
	if !allowedInviteRoles[req.Role] {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid role"})
		return
	}

	inv, err := h.store.Create(r.Context(), tenantID, identity.UserID, req.Role, 7*24*time.Hour)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create invite"})
		return
	}
	writeJSON(w, http.StatusCreated, inv)
}

func (h *InviteHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	identity := auth.GetIdentity(r.Context())
	if identity == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}
	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant context required"})
		return
	}

	invites, err := h.store.ListByTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list invites"})
		return
	}
	if invites == nil {
		invites = []Invite{}
	}
	writeJSON(w, http.StatusOK, invites)
}

func (h *InviteHandler) HandleDelete(w http.ResponseWriter, r *http.Request) {
	identity := auth.GetIdentity(r.Context())
	if identity == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}
	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "tenant context required"})
		return
	}

	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invite id required"})
		return
	}

	err := h.store.Delete(r.Context(), id, tenantID)
	if errors.Is(err, ErrInviteNotFound) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "invite not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to delete invite"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
