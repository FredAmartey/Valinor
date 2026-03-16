package policies

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/FredAmartey/heimdall/internal/activity"
	"github.com/FredAmartey/heimdall/internal/platform/middleware"
)

func TestEvaluate(t *testing.T) {
	defaults := DefaultPolicySet()
	overrides := PolicySet{
		"sensitive_data_access": DecisionRequireApproval,
	}

	assert.Equal(t, DecisionAllow, Evaluate(defaults, nil, "channel_sends"))
	assert.Equal(t, DecisionRequireApproval, Evaluate(defaults, overrides, "sensitive_data_access"))
	assert.Equal(t, DecisionBlock, Evaluate(defaults, nil, "unknown"))
}

func TestHandleGetDefaults_NilPool(t *testing.T) {
	h := NewHandler(nil, nil)
	req := httptest.NewRequest("GET", "/api/v1/policies/defaults", nil)
	req = req.WithContext(middleware.WithTenantID(req.Context(), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"))
	w := httptest.NewRecorder()

	h.HandleGetDefaults(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"policies"`)
}

func TestHandlePutDefaults_InvalidBody(t *testing.T) {
	h := NewHandler(nil, nil)
	req := httptest.NewRequest("PUT", "/api/v1/policies/defaults", strings.NewReader(`nope`))
	req = req.WithContext(middleware.WithTenantID(req.Context(), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"))
	w := httptest.NewRecorder()

	h.HandlePutDefaults(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestHandleGetAgentOverrides_InvalidAgentID(t *testing.T) {
	h := NewHandler(nil, nil)
	req := httptest.NewRequest("GET", "/api/v1/agents/not-a-uuid/policy-overrides", nil)
	req.SetPathValue("id", "not-a-uuid")
	req = req.WithContext(middleware.WithTenantID(req.Context(), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"))
	w := httptest.NewRecorder()

	h.HandleGetAgentOverrides(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandlePutDefaults_RejectsOversizedBody(t *testing.T) {
	h := NewHandler(&pgxpool.Pool{}, nil)
	req := httptest.NewRequest("PUT", "/api/v1/policies/defaults", bytes.NewReader(bytes.Repeat([]byte("a"), int(maxPolicyBodyBytes)+1)))
	req = req.WithContext(middleware.WithTenantID(req.Context(), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"))
	w := httptest.NewRecorder()

	h.HandlePutDefaults(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid request body")
}

func TestHandlePutAgentOverrides_RejectsOversizedBody(t *testing.T) {
	h := NewHandler(&pgxpool.Pool{}, nil)
	req := httptest.NewRequest("PUT", "/api/v1/agents/190f3a21-3b2c-42ce-b26e-2f448a58ec14/policy-overrides", bytes.NewReader(bytes.Repeat([]byte("a"), int(maxPolicyBodyBytes)+1)))
	req.SetPathValue("id", "190f3a21-3b2c-42ce-b26e-2f448a58ec14")
	req = req.WithContext(middleware.WithTenantID(req.Context(), "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"))
	w := httptest.NewRecorder()

	h.HandlePutAgentOverrides(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid request body")
}

type recordingQuerier struct {
	sql  string
	args []any
}

func (q *recordingQuerier) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, assert.AnError
}

func (q *recordingQuerier) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	q.sql = sql
	q.args = args
	return pgconn.CommandTag{}, nil
}

func (q *recordingQuerier) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	q.sql = sql
	q.args = args
	return errorRow{err: pgx.ErrNoRows}
}

type errorRow struct {
	err error
}

func (r errorRow) Scan(...any) error {
	return r.err
}

func TestGetAgentOverrides_ScopesToTenant(t *testing.T) {
	store := NewStore()
	q := &recordingQuerier{}
	tenantID := uuid.New()
	agentID := uuid.New()

	_, err := store.GetAgentOverrides(context.Background(), q, tenantID, agentID)
	require.Error(t, err)
	assert.Contains(t, q.sql, "tenant_id = $2")
	require.Len(t, q.args, 2)
	assert.Equal(t, agentID, q.args[0])
	assert.Equal(t, tenantID, q.args[1])
}

func TestPutAgentOverrides_ScopesToTenant(t *testing.T) {
	store := NewStore()
	q := &recordingQuerier{}
	tenantID := uuid.New()
	agentID := uuid.New()

	err := store.PutAgentOverrides(context.Background(), q, tenantID, agentID, PolicySet{
		activity.RiskClassChannelSends: DecisionAllow,
	})
	require.NoError(t, err)
	assert.Contains(t, q.sql, "tenant_id = $3")
	require.Len(t, q.args, 3)
	assert.Equal(t, agentID, q.args[0])
	assert.Equal(t, tenantID, q.args[2])
}
