package rbac

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/valinor-ai/valinor/internal/auth"
)

// AuditLogger is the audit interface for RBAC denial logging.
type AuditLogger interface {
	Log(ctx context.Context, event AuditEvent)
}

// AuditEvent captures an auditable action.
type AuditEvent struct {
	TenantID     uuid.UUID
	UserID       *uuid.UUID
	Action       string
	ResourceType string
	ResourceID   *uuid.UUID
	Metadata     map[string]any
	Source       string
}

// MiddlewareOption configures RBAC middleware behavior.
type MiddlewareOption func(*middlewareConfig)

type middlewareConfig struct {
	audit AuditLogger
}

// WithAuditLogger attaches an audit logger to log RBAC denials.
func WithAuditLogger(logger AuditLogger) MiddlewareOption {
	return func(c *middlewareConfig) {
		c.audit = logger
	}
}

// RequirePermission returns middleware that checks if the authenticated user
// has the specified permission.
func RequirePermission(engine *Evaluator, permission string, opts ...MiddlewareOption) func(http.Handler) http.Handler {
	var mc middlewareConfig
	for _, opt := range opts {
		opt(&mc)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity := auth.GetIdentity(r.Context())
			if identity == nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error": "authentication required",
				})
				return
			}

			decision, err := engine.Authorize(r.Context(), identity, permission, "", "")
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error": "authorization check failed",
				})
				return
			}

			if !decision.Allowed {
				if mc.audit != nil {
					identity := auth.GetIdentity(r.Context())
					var evt AuditEvent
					evt.Action = "access.denied"
					evt.Metadata = map[string]any{
						"permission": permission,
						"reason":     decision.Reason,
					}
					evt.Source = "api"
					if identity != nil {
						if tid, parseErr := uuid.Parse(identity.TenantID); parseErr == nil {
							evt.TenantID = tid
						}
						if uid, parseErr := uuid.Parse(identity.UserID); parseErr == nil {
							evt.UserID = &uid
						}
					}
					mc.audit.Log(r.Context(), evt)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"error":  "forbidden",
					"reason": decision.Reason,
				})
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
