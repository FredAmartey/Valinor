package admin

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/valinor-ai/valinor/internal/auth"
)

// ImpersonateHandler handles emergency impersonation requests.
// Platform admins can impersonate a tenant to gain temporary access.
type ImpersonateHandler struct {
	TokenSvc *auth.TokenService
	Pool     *pgxpool.Pool
}

// NewImpersonateHandler creates a new impersonation handler.
func NewImpersonateHandler(tokenSvc *auth.TokenService, pool *pgxpool.Pool) *ImpersonateHandler {
	return &ImpersonateHandler{TokenSvc: tokenSvc, Pool: pool}
}

// Handle processes POST /api/v1/tenants/{id}/impersonate.
func (h *ImpersonateHandler) Handle(w http.ResponseWriter, r *http.Request) {
	identity := auth.GetIdentity(r.Context())
	if identity == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}
	if !identity.IsPlatformAdmin {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "platform admin required"})
		return
	}

	tenantID := r.PathValue("id")
	if _, err := uuid.Parse(tenantID); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid tenant ID"})
		return
	}

	// TODO: validate tenant exists via pool query
	// TODO: generate short-lived JWT with tenantID, org_admin roles, 30min TTL
	// TODO: audit log the impersonation event

	slog.Warn("platform admin impersonation",
		"impersonator_id", identity.UserID,
		"target_tenant_id", tenantID,
	)

	// Placeholder — full implementation depends on TokenService.GenerateImpersonationToken
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error": fmt.Sprintf("impersonation for tenant %s not yet wired", tenantID),
	})
}
