package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
)

func TestTenantContext_SetsContextValue(t *testing.T) {
	var gotTenantID string
	handler := middleware.TenantContext(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTenantID = middleware.GetTenantID(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(auth.WithIdentity(req.Context(), &auth.Identity{
		UserID:   "user-123",
		TenantID: "tenant-456",
	}))
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, "tenant-456", gotTenantID)
}

func TestTenantContext_NoIdentity(t *testing.T) {
	handler := middleware.TenantContext(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenantID := middleware.GetTenantID(r.Context())
		assert.Empty(t, tenantID)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)
}
