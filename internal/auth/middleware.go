package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type identityContextKey struct{}

// IdentityContextKey returns the context key used to store the identity.
// Exported so other packages can set identity in context for testing.
func IdentityContextKey() identityContextKey {
	return identityContextKey{}
}

// Middleware returns HTTP middleware that validates JWT access tokens.
func Middleware(tokenSvc *TokenService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := extractBearerToken(r)
			if err != nil {
				writeAuthError(w, http.StatusUnauthorized, err.Error())
				return
			}

			identity, err := tokenSvc.ValidateToken(token)
			if err != nil {
				writeAuthError(w, http.StatusUnauthorized, "invalid token")
				return
			}

			// Reject refresh tokens on non-refresh endpoints
			if identity.TokenType != "access" {
				writeAuthError(w, http.StatusUnauthorized, "access token required")
				return
			}

			ctx := context.WithValue(r.Context(), identityContextKey{}, identity)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// MiddlewareWithDevMode returns auth middleware that also accepts "Bearer dev" in dev mode.
func MiddlewareWithDevMode(tokenSvc *TokenService, devIdentity *Identity) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := extractBearerToken(r)
			if err != nil {
				writeAuthError(w, http.StatusUnauthorized, err.Error())
				return
			}

			// Dev mode: accept "dev" as token
			if token == "dev" && devIdentity != nil {
				ctx := context.WithValue(r.Context(), identityContextKey{}, devIdentity)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			identity, err := tokenSvc.ValidateToken(token)
			if err != nil {
				writeAuthError(w, http.StatusUnauthorized, "invalid token")
				return
			}

			if identity.TokenType != "access" {
				writeAuthError(w, http.StatusUnauthorized, "access token required")
				return
			}

			ctx := context.WithValue(r.Context(), identityContextKey{}, identity)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetIdentity retrieves the authenticated identity from the request context.
func GetIdentity(ctx context.Context) *Identity {
	identity, _ := ctx.Value(identityContextKey{}).(*Identity)
	return identity
}

func extractBearerToken(r *http.Request) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("missing authorization header")
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", fmt.Errorf("invalid authorization header format")
	}

	return parts[1], nil
}

func writeAuthError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}
