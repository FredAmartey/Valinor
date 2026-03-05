package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
)

// TenantProxy wraps handlers to extract tenant ID from the URL path
// and set tenant context. Only accessible to platform admins.
type TenantProxy struct {
	pool *pgxpool.Pool
}

func NewTenantProxy(pool *pgxpool.Pool) *TenantProxy {
	return &TenantProxy{pool: pool}
}

// Wrap returns a handler that extracts {id} from /api/v1/tenants/{id}/...
// validates the caller is a platform admin, and sets tenant context.
func (p *TenantProxy) Wrap(inner http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		if p.pool != nil {
			exists, err := tenantExists(r.Context(), p.pool, tenantID)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to validate tenant"})
				return
			}
			if !exists {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": fmt.Sprintf("tenant %s not found", tenantID)})
				return
			}
		}

		ctx := middleware.WithTenantID(r.Context(), tenantID)
		inner.ServeHTTP(w, r.WithContext(ctx))
	})
}

func tenantExists(ctx context.Context, pool *pgxpool.Pool, tenantID string) (bool, error) {
	var exists bool
	err := pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1)", tenantID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check tenant exists: %w", err)
	}
	return exists, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
