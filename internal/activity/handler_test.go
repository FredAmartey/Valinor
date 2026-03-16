package activity

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/FredAmartey/heimdall/internal/platform/middleware"
)

func TestHandleListActivity_NilPool(t *testing.T) {
	h := NewHandler(nil)
	req := httptest.NewRequest("GET", "/api/v1/activity", nil)
	req = req.WithContext(middleware.WithTenantID(req.Context(), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"))
	w := httptest.NewRecorder()

	h.HandleListActivity(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"events":[]`)
}

func TestHandleListActivity_InvalidAgentFilter(t *testing.T) {
	h := NewHandler(nil)
	req := httptest.NewRequest("GET", "/api/v1/activity?agent_id=not-a-uuid", nil)
	req = req.WithContext(middleware.WithTenantID(req.Context(), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"))
	w := httptest.NewRecorder()

	h.HandleListActivity(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid agent_id")
}

func TestHandleListAgentActivity_InvalidAgentID(t *testing.T) {
	h := NewHandler(nil)
	req := httptest.NewRequest("GET", "/api/v1/agents/not-a-uuid/activity", nil)
	req.SetPathValue("id", "not-a-uuid")
	req = req.WithContext(middleware.WithTenantID(req.Context(), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"))
	w := httptest.NewRecorder()

	h.HandleListAgentActivity(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "agent id must be a valid UUID")
}

func TestHandleListSecurityEvents_InvalidTenant(t *testing.T) {
	h := NewHandler(nil)
	req := httptest.NewRequest("GET", "/api/v1/security/events", nil)
	w := httptest.NewRecorder()

	h.HandleListSecurityEvents(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid tenant context")
}

func TestHandleListSecurityEvents_NilPool(t *testing.T) {
	h := NewHandler(nil)
	req := httptest.NewRequest("GET", "/api/v1/security/events?limit=15", nil)
	req = req.WithContext(middleware.WithTenantID(req.Context(), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"))
	w := httptest.NewRecorder()

	h.HandleListSecurityEvents(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"count":0`)
}
