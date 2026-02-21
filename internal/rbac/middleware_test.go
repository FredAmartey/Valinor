package rbac_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/rbac"
)

func setIdentity(r *http.Request, identity *auth.Identity) *http.Request {
	ctx := context.WithValue(r.Context(), auth.IdentityContextKey(), identity)
	return r.WithContext(ctx)
}

func TestRBACMiddleware_Allowed(t *testing.T) {
	eval := rbac.NewEvaluator(nil)
	eval.RegisterRole("standard_user", []string{"agents:read"})

	handler := rbac.RequirePermission(eval, "agents:read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = setIdentity(req, &auth.Identity{
		UserID:   "user-123",
		TenantID: "tenant-456",
		Roles:    []string{"standard_user"},
	})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRBACMiddleware_Denied(t *testing.T) {
	eval := rbac.NewEvaluator(nil)
	eval.RegisterRole("standard_user", []string{"agents:read"})

	handler := rbac.RequirePermission(eval, "users:manage")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach handler")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = setIdentity(req, &auth.Identity{
		UserID:   "user-123",
		TenantID: "tenant-456",
		Roles:    []string{"standard_user"},
	})
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)

	var body map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &body)
	require.NoError(t, err)
	assert.Contains(t, body["error"], "forbidden")
}

func TestRBACMiddleware_NoIdentity(t *testing.T) {
	eval := rbac.NewEvaluator(nil)

	handler := rbac.RequirePermission(eval, "agents:read")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach handler")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// No identity in context
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
