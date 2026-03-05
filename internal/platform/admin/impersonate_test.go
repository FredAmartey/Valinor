package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/valinor-ai/valinor/internal/auth"
)

func TestHandleImpersonate_NotPlatformAdmin(t *testing.T) {
	h := NewImpersonateHandler(nil, nil, nil)

	mux := http.NewServeMux()
	mux.Handle("POST /api/v1/tenants/{id}/impersonate", http.HandlerFunc(h.Handle))

	req := httptest.NewRequest("POST", "/api/v1/tenants/a1b2c3d4-0001-4000-8000-000000000001/impersonate", nil)
	identity := &auth.Identity{UserID: "user-1", IsPlatformAdmin: false}
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestHandleImpersonate_InvalidTenantID(t *testing.T) {
	h := NewImpersonateHandler(nil, nil, nil)

	mux := http.NewServeMux()
	mux.Handle("POST /api/v1/tenants/{id}/impersonate", http.HandlerFunc(h.Handle))

	req := httptest.NewRequest("POST", "/api/v1/tenants/not-a-uuid/impersonate", nil)
	identity := &auth.Identity{UserID: "user-1", IsPlatformAdmin: true}
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleImpersonate_Scaffold(t *testing.T) {
	h := NewImpersonateHandler(nil, nil, nil)

	mux := http.NewServeMux()
	mux.Handle("POST /api/v1/tenants/{id}/impersonate", http.HandlerFunc(h.Handle))

	req := httptest.NewRequest("POST", "/api/v1/tenants/a1b2c3d4-0001-4000-8000-000000000001/impersonate", nil)
	identity := &auth.Identity{UserID: "admin-1", IsPlatformAdmin: true}
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	// Scaffold returns 501 until JWT generation is wired
	assert.Equal(t, http.StatusNotImplemented, w.Code)
}
