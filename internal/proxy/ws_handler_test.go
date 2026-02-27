package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/valinor-ai/valinor/internal/auth"
)

// mockTokenValidator implements TokenValidator for WS auth testing.
type mockTokenValidator struct {
	identity *auth.Identity
	err      error
}

func (m *mockTokenValidator) ValidateToken(token string) (*auth.Identity, error) {
	return m.identity, m.err
}

func TestHandleWebSocket_RejectsNoToken(t *testing.T) {
	h := &Handler{}
	h.tokenValidator = &mockTokenValidator{err: auth.ErrTokenInvalid}

	req := httptest.NewRequest("GET", "/api/v1/agents/agent-1/ws", nil)
	req.SetPathValue("id", "agent-1")
	rec := httptest.NewRecorder()

	h.HandleWebSocket(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandleWebSocket_RejectsExpiredToken(t *testing.T) {
	h := &Handler{}
	h.tokenValidator = &mockTokenValidator{err: auth.ErrTokenExpired}

	req := httptest.NewRequest("GET", "/api/v1/agents/agent-1/ws?access_token=expired", nil)
	req.SetPathValue("id", "agent-1")
	rec := httptest.NewRecorder()

	h.HandleWebSocket(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestHandleWebSocket_RejectsRefreshToken(t *testing.T) {
	h := &Handler{}
	h.tokenValidator = &mockTokenValidator{identity: &auth.Identity{
		UserID:    "u-1",
		TenantID:  "t-1",
		TokenType: "refresh",
	}}

	req := httptest.NewRequest("GET", "/api/v1/agents/agent-1/ws?access_token=refresh-tok", nil)
	req.SetPathValue("id", "agent-1")
	rec := httptest.NewRecorder()

	h.HandleWebSocket(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}
