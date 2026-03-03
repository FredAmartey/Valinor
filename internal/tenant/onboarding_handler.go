package tenant

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/valinor-ai/valinor/internal/auth"
)

// OnboardingHandler handles tenant self-service creation for new users.
// Separated from Handler to avoid coupling tenant management with auth concerns.
type OnboardingHandler struct {
	tenantStore *Store
	authStore   *auth.Store
}

func NewOnboardingHandler(tenantStore *Store, authStore *auth.Store) *OnboardingHandler {
	return &OnboardingHandler{tenantStore: tenantStore, authStore: authStore}
}

func (h *OnboardingHandler) HandleSelfServiceCreate(w http.ResponseWriter, r *http.Request) {
	identity := auth.GetIdentity(r.Context())
	if identity == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}
	if identity.TenantID != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user already belongs to a tenant"})
		return
	}

	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "team name is required"})
		return
	}

	slug := GenerateSlug(req.Name)
	t, err := h.tenantStore.Create(r.Context(), req.Name, slug)
	if err != nil {
		if errors.Is(err, ErrSlugTaken) {
			slug = slug + "-" + fmt.Sprintf("%d", time.Now().UnixMilli()%10000)
			t, err = h.tenantStore.Create(r.Context(), req.Name, slug)
		}
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to create team"})
			return
		}
	}

	// Seed default roles so AssignRole("org_admin") finds a matching role row.
	if err := h.tenantStore.SeedDefaultRoles(r.Context(), t.ID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to initialize team roles"})
		return
	}

	if err := h.authStore.UpdateUserTenant(r.Context(), identity.UserID, t.ID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to assign user to team"})
		return
	}

	if err := h.authStore.AssignRole(r.Context(), identity.UserID, t.ID, "org_admin"); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to assign admin role"})
		return
	}

	writeJSON(w, http.StatusCreated, t)
}
