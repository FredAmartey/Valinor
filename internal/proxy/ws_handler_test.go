package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/orchestrator"
	"github.com/valinor-ai/valinor/internal/rbac"
)

// mockTokenValidator implements TokenValidator for WS auth testing.
type mockTokenValidator struct {
	identity *auth.Identity
	err      error
}

func (m *mockTokenValidator) ValidateToken(token string) (*auth.Identity, error) {
	return m.identity, m.err
}

// wsTestAgentStore implements AgentLookup for WS handler tests.
type wsTestAgentStore struct {
	agents map[string]*orchestrator.AgentInstance
}

func (m *wsTestAgentStore) GetByID(_ context.Context, id string) (*orchestrator.AgentInstance, error) {
	inst, ok := m.agents[id]
	if !ok {
		return nil, orchestrator.ErrVMNotFound
	}
	return inst, nil
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

func stringPtr(s string) *string { return &s }
func uint32Ptr(v uint32) *uint32 { return &v }

func TestHandleWebSocket_RejectsInsufficientRBAC(t *testing.T) {
	tenantID := "a1b2c3d4-0001-4000-8000-000000000001"
	agentID := "00000000-0000-0000-0000-000000000001"

	// Set up RBAC evaluator with read_only role (no agents:write)
	eval := rbac.NewEvaluator(nil)
	eval.RegisterRole(tenantID, "read_only", []string{"agents:read"})

	h := &Handler{}
	h.tokenValidator = &mockTokenValidator{identity: &auth.Identity{
		UserID:    "u-1",
		TenantID:  tenantID,
		TokenType: "access",
		Roles:     []string{"read_only"},
	}}
	h.rbacEval = eval
	h.agents = &wsTestAgentStore{agents: map[string]*orchestrator.AgentInstance{
		agentID: {
			ID:       agentID,
			TenantID: stringPtr(tenantID),
			Status:   orchestrator.StatusRunning,
			VsockCID: uint32Ptr(100),
		},
	}}

	req := httptest.NewRequest("GET", "/api/v1/agents/"+agentID+"/ws?access_token=valid", nil)
	req.SetPathValue("id", agentID)
	rec := httptest.NewRecorder()

	h.HandleWebSocket(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestHandleWebSocket_AllowsOrgAdmin(t *testing.T) {
	tenantID := "a1b2c3d4-0001-4000-8000-000000000001"
	agentID := "00000000-0000-0000-0000-000000000001"

	eval := rbac.NewEvaluator(nil)
	eval.RegisterRole(tenantID, "org_admin", []string{"*"})

	h := &Handler{}
	h.tokenValidator = &mockTokenValidator{identity: &auth.Identity{
		UserID:    "u-1",
		TenantID:  tenantID,
		TokenType: "access",
		Roles:     []string{"org_admin"},
	}}
	h.rbacEval = eval
	h.agents = &wsTestAgentStore{agents: map[string]*orchestrator.AgentInstance{
		agentID: {
			ID:       agentID,
			TenantID: stringPtr(tenantID),
			Status:   orchestrator.StatusRunning,
			VsockCID: uint32Ptr(100),
		},
	}}

	req := httptest.NewRequest("GET", "/api/v1/agents/"+agentID+"/ws?access_token=valid", nil)
	req.SetPathValue("id", agentID)
	rec := httptest.NewRecorder()

	h.HandleWebSocket(rec, req)

	// Should pass RBAC but fail at WebSocket upgrade (not a real WS connection)
	// httptest.ResponseRecorder doesn't support WebSocket upgrade — this returns 200
	// (websocket.Accept writes its own status). The key assertion is it does NOT return 403.
	assert.NotEqual(t, http.StatusForbidden, rec.Code)
	assert.NotEqual(t, http.StatusUnauthorized, rec.Code)
}
