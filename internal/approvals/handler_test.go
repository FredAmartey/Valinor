package approvals

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
)

func TestHandleList_NilPool(t *testing.T) {
	h := NewHandler(nil, nil)
	req := httptest.NewRequest("GET", "/api/v1/approvals", nil)
	req = req.WithContext(middleware.WithTenantID(req.Context(), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"))
	w := httptest.NewRecorder()

	h.HandleList(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"approvals":[]`)
}

func TestHandleApprove_NoIdentity(t *testing.T) {
	h := NewHandler(nil, nil)
	req := httptest.NewRequest("POST", "/api/v1/approvals/190f3a21-3b2c-42ce-b26e-2f448a58ec14/approve", nil)
	req.SetPathValue("id", "190f3a21-3b2c-42ce-b26e-2f448a58ec14")
	req = req.WithContext(middleware.WithTenantID(req.Context(), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"))
	w := httptest.NewRecorder()

	h.HandleApprove(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "unauthorized")
}

func TestHandleDeny_InvalidApprovalID(t *testing.T) {
	h := NewHandler(&pgxpool.Pool{}, nil)
	req := httptest.NewRequest("POST", "/api/v1/approvals/not-a-uuid/deny", nil)
	req.SetPathValue("id", "not-a-uuid")
	req = req.WithContext(auth.WithIdentity(
		middleware.WithTenantID(req.Context(), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"),
		&auth.Identity{UserID: "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"},
	))
	w := httptest.NewRecorder()

	h.HandleDeny(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "approval id must be a valid UUID")
}

func TestHandleApprove_ServiceUnavailableAfterValidation(t *testing.T) {
	h := NewHandler(nil, nil)
	req := httptest.NewRequest("POST", "/api/v1/approvals/190f3a21-3b2c-42ce-b26e-2f448a58ec14/approve", nil)
	req.SetPathValue("id", "190f3a21-3b2c-42ce-b26e-2f448a58ec14")
	req = req.WithContext(auth.WithIdentity(
		middleware.WithTenantID(req.Context(), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"),
		&auth.Identity{UserID: "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"},
	))
	w := httptest.NewRecorder()

	h.HandleApprove(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "approval store unavailable")
}

func TestResolveErrorResponse_MapsApprovalErrors(t *testing.T) {
	t.Parallel()

	status, body := resolveErrorResponse(ErrApprovalNotFound)
	assert.Equal(t, http.StatusNotFound, status)
	assert.Equal(t, map[string]string{"error": "approval request not found"}, body)

	status, body = resolveErrorResponse(ErrApprovalSelfReview)
	assert.Equal(t, http.StatusForbidden, status)
	assert.Equal(t, map[string]string{"error": "approval requester cannot review their own approval"}, body)

	status, body = resolveErrorResponse(ErrApprovalNotPending)
	assert.Equal(t, http.StatusConflict, status)
	assert.Equal(t, map[string]string{"error": "approval request is not pending"}, body)
}

func TestResolveErrorResponse_FallsBackToInternalServerError(t *testing.T) {
	t.Parallel()

	status, body := resolveErrorResponse(errors.New("boom"))
	assert.Equal(t, http.StatusInternalServerError, status)
	assert.Equal(t, map[string]string{"error": "resolution failed"}, body)
}
