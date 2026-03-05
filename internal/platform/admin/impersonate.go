package admin

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/valinor-ai/valinor/internal/audit"
	"github.com/valinor-ai/valinor/internal/auth"
)

// ImpersonateHandler handles emergency impersonation requests.
// Platform admins can impersonate a tenant to gain temporary access.
type ImpersonateHandler struct {
	tokenSvc *auth.TokenService
	pool     *pgxpool.Pool
	auditLog audit.Logger
}

// NewImpersonateHandler creates a new impersonation handler.
func NewImpersonateHandler(tokenSvc *auth.TokenService, pool *pgxpool.Pool, auditLog audit.Logger) *ImpersonateHandler {
	return &ImpersonateHandler{tokenSvc: tokenSvc, pool: pool, auditLog: auditLog}
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
	parsedTenantID, err := uuid.Parse(tenantID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid tenant ID"})
		return
	}

	// Log the impersonation attempt to the audit trail
	actorID := audit.ActorIDFromContext(r.Context())
	if h.auditLog != nil {
		h.auditLog.Log(r.Context(), audit.Event{
			TenantID:     parsedTenantID,
			UserID:       actorID,
			Action:       "admin.impersonation.attempted",
			ResourceType: "tenant",
			ResourceID:   &parsedTenantID,
			Metadata: map[string]any{
				"impersonator_id": identity.UserID,
			},
			Source: "api",
		})
	}

	slog.Warn("platform admin impersonation",
		"impersonator_id", identity.UserID,
		"target_tenant_id", tenantID,
	)

	// TODO: validate tenant exists via pool query
	// TODO: generate short-lived JWT with tenantID, org_admin roles, 30min TTL

	// Placeholder — full implementation depends on TokenService.GenerateImpersonationToken
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error": fmt.Sprintf("impersonation for tenant %s not yet wired", tenantID),
	})
}
