package audit

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
)

func TestHandleListEvents_NilPool(t *testing.T) {
	h := NewHandler(nil)
	req := httptest.NewRequest("GET", "/api/v1/audit/events", nil)
	req = req.WithContext(middleware.WithTenantID(req.Context(), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"))
	w := httptest.NewRecorder()

	h.HandleListEvents(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"count":0`)
}

func TestHandleListEvents_InvalidTenant(t *testing.T) {
	h := NewHandler(nil)
	req := httptest.NewRequest("GET", "/api/v1/audit/events", nil)
	// No tenant ID in context — should return 400
	w := httptest.NewRecorder()

	h.HandleListEvents(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleListEvents_WithLimit(t *testing.T) {
	h := NewHandler(nil)
	req := httptest.NewRequest("GET", "/api/v1/audit/events?limit=10", nil)
	req = req.WithContext(middleware.WithTenantID(req.Context(), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"))
	w := httptest.NewRecorder()

	h.HandleListEvents(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"events":[]`)
}

func TestHandleListEvents_WithActionFilter(t *testing.T) {
	h := NewHandler(nil)
	req := httptest.NewRequest("GET", "/api/v1/audit/events?action=user.created", nil)
	req = req.WithContext(middleware.WithTenantID(req.Context(), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"))
	w := httptest.NewRecorder()

	h.HandleListEvents(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"count":0`)
}

func TestHandleListEvents_WithResourceTypeFilter(t *testing.T) {
	h := NewHandler(nil)
	req := httptest.NewRequest("GET", "/api/v1/audit/events?resource_type=agent", nil)
	req = req.WithContext(middleware.WithTenantID(req.Context(), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"))
	w := httptest.NewRecorder()

	h.HandleListEvents(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"count":0`)
}

func TestHandleListEvents_WithSourceFilter(t *testing.T) {
	h := NewHandler(nil)
	req := httptest.NewRequest("GET", "/api/v1/audit/events?source=api", nil)
	req = req.WithContext(middleware.WithTenantID(req.Context(), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"))
	w := httptest.NewRecorder()

	h.HandleListEvents(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"count":0`)
}

func TestHandleListEvents_WithBeforeFilter(t *testing.T) {
	h := NewHandler(nil)
	req := httptest.NewRequest("GET", "/api/v1/audit/events?before=2026-02-26T00:00:00Z", nil)
	req = req.WithContext(middleware.WithTenantID(req.Context(), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"))
	w := httptest.NewRecorder()

	h.HandleListEvents(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"count":0`)
}

func TestHandleListEvents_WithUserIDFilter(t *testing.T) {
	h := NewHandler(nil)
	req := httptest.NewRequest("GET", "/api/v1/audit/events?user_id=a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11", nil)
	req = req.WithContext(middleware.WithTenantID(req.Context(), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"))
	w := httptest.NewRecorder()

	h.HandleListEvents(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"count":0`)
}

func TestHandleListEvents_InvalidUserIDFilter(t *testing.T) {
	h := NewHandler(nil)
	req := httptest.NewRequest("GET", "/api/v1/audit/events?user_id=not-a-uuid", nil)
	req = req.WithContext(middleware.WithTenantID(req.Context(), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"))
	w := httptest.NewRecorder()

	h.HandleListEvents(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleListEvents_ComposedFilters(t *testing.T) {
	h := NewHandler(nil)
	req := httptest.NewRequest("GET",
		"/api/v1/audit/events?action=user.created&resource_type=user&source=api&limit=25",
		nil,
	)
	req = req.WithContext(middleware.WithTenantID(req.Context(), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"))
	w := httptest.NewRecorder()

	h.HandleListEvents(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"count":0`)
	assert.Contains(t, w.Body.String(), `"events":[]`)
}
