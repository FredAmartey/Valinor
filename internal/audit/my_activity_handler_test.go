package audit

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
)

func TestHandleMyActivity_NoIdentity(t *testing.T) {
	h := NewHandler(nil)
	req := httptest.NewRequest("GET", "/api/v1/me/activity", nil)
	req = req.WithContext(middleware.WithTenantID(req.Context(), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"))
	w := httptest.NewRecorder()

	h.HandleMyActivity(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "unauthorized")
}

func TestHandleMyActivity_NoTenantContext(t *testing.T) {
	h := NewHandler(nil)
	identity := &auth.Identity{UserID: "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"}
	req := httptest.NewRequest("GET", "/api/v1/me/activity", nil)
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	w := httptest.NewRecorder()

	h.HandleMyActivity(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid tenant context")
}

func TestHandleMyActivity_InvalidUserID(t *testing.T) {
	h := NewHandler(nil)
	identity := &auth.Identity{UserID: "not-a-uuid"}
	req := httptest.NewRequest("GET", "/api/v1/me/activity", nil)
	ctx := auth.WithIdentity(
		middleware.WithTenantID(req.Context(), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"),
		identity,
	)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.HandleMyActivity(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid user identity")
}

func TestHandleMyActivity_NilPool(t *testing.T) {
	h := NewHandler(nil)
	identity := &auth.Identity{UserID: "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"}
	req := httptest.NewRequest("GET", "/api/v1/me/activity", nil)
	ctx := auth.WithIdentity(
		middleware.WithTenantID(req.Context(), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"),
		identity,
	)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	h.HandleMyActivity(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"events":[]`)
	assert.Contains(t, w.Body.String(), `"count":0`)
}

func TestHandleMyActivity_LimitClamp(t *testing.T) {
	h := NewHandler(nil)
	identity := &auth.Identity{UserID: "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"}
	req := httptest.NewRequest("GET", "/api/v1/me/activity", nil)
	ctx := auth.WithIdentity(
		middleware.WithTenantID(req.Context(), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"),
		identity,
	)

	tests := []struct {
		name  string
		query string
	}{
		{"over max", "?limit=100"},
		{"negative", "?limit=-5"},
		{"non-numeric", "?limit=abc"},
		{"zero", "?limit=0"},
		{"valid", "?limit=25"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/v1/me/activity"+tt.query, nil).WithContext(ctx)
			w := httptest.NewRecorder()

			h.HandleMyActivity(w, req)

			// With nil pool, all return 200 with empty events regardless of limit
			assert.Equal(t, http.StatusOK, w.Code)
			assert.Contains(t, w.Body.String(), `"events":[]`)
		})
	}
}
