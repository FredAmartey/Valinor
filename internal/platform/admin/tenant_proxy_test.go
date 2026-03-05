package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
)

func TestTenantProxy_NoPlatformAdmin(t *testing.T) {
	proxy := NewTenantProxy(nil)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := proxy.Wrap(inner)
	req := httptest.NewRequest("GET", "/api/v1/tenants/abc-123/users", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestTenantProxy_NonPlatformAdmin(t *testing.T) {
	proxy := NewTenantProxy(nil)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := proxy.Wrap(inner)
	req := httptest.NewRequest("GET", "/api/v1/tenants/abc-123/users", nil)
	identity := &auth.Identity{UserID: "user-1", IsPlatformAdmin: false}
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestTenantProxy_InvalidTenantID(t *testing.T) {
	proxy := NewTenantProxy(nil)
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Use ServeMux to populate PathValue
	mux := http.NewServeMux()
	mux.Handle("GET /api/v1/tenants/{id}/users", proxy.Wrap(inner))

	req := httptest.NewRequest("GET", "/api/v1/tenants/not-a-uuid/users", nil)
	identity := &auth.Identity{UserID: "user-1", IsPlatformAdmin: true}
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestTenantProxy_SetsTenantContext(t *testing.T) {
	proxy := NewTenantProxy(nil)
	var gotTenantID string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTenantID = middleware.GetTenantID(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	// Use ServeMux to populate PathValue
	mux := http.NewServeMux()
	mux.Handle("GET /api/v1/tenants/{id}/users", proxy.Wrap(inner))

	tenantID := "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
	req := httptest.NewRequest("GET", "/api/v1/tenants/"+tenantID+"/users", nil)
	identity := &auth.Identity{UserID: "user-1", IsPlatformAdmin: true}
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, tenantID, gotTenantID)
}
