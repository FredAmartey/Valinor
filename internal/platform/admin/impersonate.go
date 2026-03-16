package admin

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/FredAmartey/heimdall/internal/audit"
	"github.com/FredAmartey/heimdall/internal/auth"
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

	// Validate tenant exists and fetch name before logging or generating tokens
	var tenantName string
	if h.pool != nil {
		name, existsErr := tenantNameByID(r.Context(), h.pool, tenantID)
		if existsErr != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": fmt.Sprintf("tenant %s not found", tenantID)})
			return
		}
		tenantName = name
	}

	// Log the impersonation to the audit trail (after tenant validation)
	actorID := audit.ActorIDFromContext(r.Context())
	if h.auditLog != nil {
		h.auditLog.Log(r.Context(), audit.Event{
			TenantID:     parsedTenantID,
			UserID:       actorID,
			Action:       "admin.impersonation.started",
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

	// Generate short-lived impersonation token
	token, err := h.tokenSvc.CreateImpersonationToken(identity, tenantID)
	if err != nil {
		slog.Error("failed to create impersonation token", "error", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to generate token"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"token":       token,
		"expires_in":  1800,
		"tenant_name": tenantName,
	})
}
