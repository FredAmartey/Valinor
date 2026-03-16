package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/FredAmartey/heimdall/internal/auth"
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

func TestHandleImpersonate_NoIdentity(t *testing.T) {
	h := NewImpersonateHandler(nil, nil, nil)
	req := httptest.NewRequest("POST", "/api/v1/tenants/a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11/impersonate", nil)
	// No identity in context
	w := httptest.NewRecorder()
	h.Handle(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandleImpersonate_Success(t *testing.T) {
	tokenSvc := auth.NewTokenService("test-secret-key-32-bytes-long!!", "heimdall", 1, 24)
	// pool is nil — tenant existence check is skipped when pool is nil
	h := NewImpersonateHandler(tokenSvc, nil, nil)

	mux := http.NewServeMux()
	mux.Handle("POST /api/v1/tenants/{id}/impersonate", http.HandlerFunc(h.Handle))

	req := httptest.NewRequest("POST", "/api/v1/tenants/a1b2c3d4-0001-4000-8000-000000000001/impersonate", nil)
	identity := &auth.Identity{UserID: "admin-1", IsPlatformAdmin: true, Email: "admin@test.com"}
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	w := httptest.NewRecorder()

	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp["token"])
	assert.Equal(t, float64(1800), resp["expires_in"])

	// Validate the returned token
	tokenStr, ok := resp["token"].(string)
	require.True(t, ok, "token should be a string")
	parsed, err := tokenSvc.ValidateToken(tokenStr)
	require.NoError(t, err)
	assert.Equal(t, "a1b2c3d4-0001-4000-8000-000000000001", parsed.TenantID)
	assert.Equal(t, []string{"org_admin"}, parsed.Roles)
	assert.Equal(t, "admin-1", parsed.ImpersonatorID)
}
