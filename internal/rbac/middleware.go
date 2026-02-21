package rbac

import (
	"encoding/json"
	"net/http"

	"github.com/valinor-ai/valinor/internal/auth"
)

// RequirePermission returns middleware that checks if the authenticated user
// has the specified permission.
func RequirePermission(engine *Evaluator, permission string) func(http.Handler) http.Handler {
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
