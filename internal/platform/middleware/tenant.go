package middleware

import (
	"context"
	"net/http"

	"github.com/valinor-ai/valinor/internal/auth"
)

type tenantContextKey struct{}

// TenantContext extracts the tenant ID from the authenticated identity
// and sets it in the request context for downstream use.
//
// NOTE: This middleware only sets the Go context value. To activate
// Postgres Row Level Security, business handlers must call
// database.WithTenantConnection() which runs
// SET app.current_tenant_id on the database connection.
func TenantContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity := auth.GetIdentity(r.Context())
		if identity != nil && identity.TenantID != "" {
			ctx := context.WithValue(r.Context(), tenantContextKey{}, identity.TenantID)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		next.ServeHTTP(w, r)
	})
}

// GetTenantID retrieves the tenant ID from the request context.
func GetTenantID(ctx context.Context) string {
	if id, ok := ctx.Value(tenantContextKey{}).(string); ok {
		return id
	}
	return ""
}
