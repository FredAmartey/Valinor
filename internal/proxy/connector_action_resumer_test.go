package proxy_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/FredAmartey/heimdall/internal/approvals"
	"github.com/FredAmartey/heimdall/internal/audit"
	"github.com/FredAmartey/heimdall/internal/connectors"
	"github.com/FredAmartey/heimdall/internal/orchestrator"
	"github.com/FredAmartey/heimdall/internal/platform/database"
	"github.com/FredAmartey/heimdall/internal/proxy"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

type captureConnectorAuditLogger struct {
	events []proxy.AuditEvent
}

func (l *captureConnectorAuditLogger) Log(_ context.Context, event proxy.AuditEvent) {
	l.events = append(l.events, event)
}

func (l *captureConnectorAuditLogger) Close() error { return nil }

func setupResolverTestDB(t *testing.T) (*database.Pool, func()) {
	t.Helper()

	ctx := context.Background()
	container, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("heimdall_test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").WithOccurrence(2),
		),
	)
	require.NoError(t, err)

	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	require.NoError(t, database.RunMigrations(connStr, "file://../../migrations"))
	pool, err := database.Connect(ctx, connStr, 5)
	require.NoError(t, err)

	cleanup := func() {
		pool.Close()
		_ = container.Terminate(ctx)
	}
	return pool, cleanup
}

func seedResolverAction(t *testing.T, ctx context.Context, pool *database.Pool, tenantSlug string, cid uint32) (string, uuid.UUID, uuid.UUID, *connectors.GovernedAction, *approvals.Request) {
	t.Helper()

	var tenantID string
	err := pool.QueryRow(ctx, "INSERT INTO tenants (name, slug) VALUES ($1, $2) RETURNING id", "Tenant "+tenantSlug, "tenant-"+tenantSlug).Scan(&tenantID)
	require.NoError(t, err)

	var agentID uuid.UUID
	err = pool.QueryRow(ctx,
		"INSERT INTO agent_instances (tenant_id, status, vsock_cid) VALUES ($1, 'running', $2) RETURNING id",
		tenantID,
		int64(cid),
	).Scan(&agentID)
	require.NoError(t, err)

	connectorStore := connectors.NewStore()
	actionStore := connectors.NewGovernedActionStore()

	var (
		connectorID uuid.UUID
		action      *connectors.GovernedAction
	)
	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		connector, createErr := connectorStore.Create(
			ctx,
			q,
			"crm-"+tenantSlug,
			"mcp",
			"https://example.com/"+tenantSlug,
			json.RawMessage(`{}`),
			json.RawMessage(`[{"name":"update_contact","action_type":"write","risk_class":"external_writes"}]`),
			json.RawMessage(`[]`),
		)
		if createErr != nil {
			return createErr
		}
		connectorID = connector.ID

		var approvalID uuid.UUID
		if scanErr := q.QueryRow(ctx,
			`INSERT INTO approval_requests (
				tenant_id, agent_id, risk_class, status, target_type, target_label, action_summary, metadata
			) VALUES ($1, $2, 'external_writes', 'pending', 'crm_record', 'Contact 123', 'Update CRM contact', $3)
			RETURNING id`,
			tenantID,
			agentID,
			json.RawMessage(`{}`),
		).Scan(&approvalID); scanErr != nil {
			return scanErr
		}

		action, createErr = actionStore.Create(ctx, q, connectors.CreateGovernedActionParams{
			TenantID:      mustUUID(t, tenantID),
			AgentID:       &agentID,
			ConnectorID:   connectorID,
			SessionID:     "session-123",
			CorrelationID: "corr-123",
			ToolName:      "update_contact",
			RiskClass:     "external_writes",
			TargetType:    "crm_record",
			TargetLabel:   "Contact 123",
			ActionSummary: "Update CRM contact",
			Arguments:     json.RawMessage(`{"id":"123"}`),
			Status:        connectors.GovernedActionStatusPending,
		})
		if createErr != nil {
			return createErr
		}
		_, markErr := actionStore.MarkAwaitingApproval(ctx, q, action.ID, approvalID)
		return markErr
	})
	require.NoError(t, err)

	request := &approvals.Request{
		ID:       uuid.New(),
		TenantID: mustUUID(t, tenantID),
		AgentID:  &agentID,
		Metadata: map[string]any{"governed_action_id": action.ID.String()},
	}

	return tenantID, agentID, connectorID, action, request
}

func TestConnectorActionResolver_ApproveExecutesGovernedAction(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupResolverTestDB(t)
	defer cleanup()

	ctx := context.Background()
	cid := uint32(21)
	tenantID, agentID, _, action, request := seedResolverAction(t, ctx, pool, "resolver-approve", cid)
	actionStore := connectors.NewGovernedActionStore()

	transport := proxy.NewTCPTransport(9891)
	connPool := proxy.NewConnPool(transport)
	defer connPool.Close()

	ln, err := transport.Listen(ctx, cid)
	require.NoError(t, err)
	defer ln.Close()

	resumePayloads := make(chan proxy.ConnectorActionResumePayload, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()

		ac := proxy.NewAgentConn(conn)
		frame, recvErr := ac.Recv(ctx)
		if recvErr != nil {
			return
		}

		var payload proxy.ConnectorActionResumePayload
		if decodeErr := json.Unmarshal(frame.Payload, &payload); decodeErr != nil {
			return
		}
		resumePayloads <- payload

		_ = ac.Send(ctx, proxy.Frame{
			Type: proxy.TypeRuntimeEvent,
			ID:   frame.ID,
			Payload: json.RawMessage(`{
				"event_type":"connector.resume_completed",
				"kind":"connector.called",
				"status":"completed"
			}`),
		})
		_ = ac.Send(ctx, proxy.Frame{
			Type:    proxy.TypeToolExecuted,
			ID:      frame.ID,
			Payload: json.RawMessage(`{"tool_name":"update_contact","connector_name":"crm-api"}`),
		})
	}()

	agents := &mockAgentStore{
		agents: map[string]*orchestrator.AgentInstance{
			agentID.String(): {
				ID:       agentID.String(),
				TenantID: &tenantID,
				VsockCID: &cid,
				Status:   orchestrator.StatusRunning,
			},
		},
	}

	auditLogger := &captureConnectorAuditLogger{}
	resolver := proxy.NewConnectorActionResolver(pool, connPool, agents, actionStore).WithAuditLogger(auditLogger)
	require.NoError(t, resolver.ResolveConnectorAction(ctx, tenantID, request, true))

	resumePayload := <-resumePayloads
	assert.Equal(t, action.ID.String(), resumePayload.ActionID)
	assert.Equal(t, "update_contact", resumePayload.ToolName)

	var stored *connectors.GovernedAction
	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		var getErr error
		stored, getErr = actionStore.GetByID(ctx, q, action.ID)
		return getErr
	})
	require.NoError(t, err)
	assert.Equal(t, connectors.GovernedActionStatusExecuted, stored.Status)
	require.Len(t, auditLogger.events, 2)
	assert.Equal(t, audit.ActionConnectorWriteApproved, auditLogger.events[0].Action)
	assert.Equal(t, audit.ActionConnectorWriteExecuted, auditLogger.events[1].Action)
}

func TestConnectorActionResolver_DenyMarksGovernedActionDenied(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupResolverTestDB(t)
	defer cleanup()

	ctx := context.Background()
	cid := uint32(22)
	tenantID, agentID, _, action, request := seedResolverAction(t, ctx, pool, "resolver-deny", cid)
	actionStore := connectors.NewGovernedActionStore()

	agents := &mockAgentStore{
		agents: map[string]*orchestrator.AgentInstance{
			agentID.String(): {
				ID:       agentID.String(),
				TenantID: &tenantID,
				VsockCID: &cid,
				Status:   orchestrator.StatusRunning,
			},
		},
	}

	auditLogger := &captureConnectorAuditLogger{}
	resolver := proxy.NewConnectorActionResolver(pool, proxy.NewConnPool(proxy.NewTCPTransport(9892)), agents, actionStore).WithAuditLogger(auditLogger)
	require.NoError(t, resolver.ResolveConnectorAction(ctx, tenantID, request, false))

	var stored *connectors.GovernedAction
	err := database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		var getErr error
		stored, getErr = actionStore.GetByID(ctx, q, action.ID)
		return getErr
	})
	require.NoError(t, err)
	assert.Equal(t, connectors.GovernedActionStatusDenied, stored.Status)
	require.Len(t, auditLogger.events, 1)
	assert.Equal(t, audit.ActionConnectorWriteDenied, auditLogger.events[0].Action)
}

func TestConnectorActionResolver_ApproveWithStoppedAgentMarksGovernedActionFailed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupResolverTestDB(t)
	defer cleanup()

	ctx := context.Background()
	cid := uint32(23)
	tenantID, agentID, _, action, request := seedResolverAction(t, ctx, pool, "resolver-stopped", cid)
	actionStore := connectors.NewGovernedActionStore()

	agents := &mockAgentStore{
		agents: map[string]*orchestrator.AgentInstance{
			agentID.String(): {
				ID:       agentID.String(),
				TenantID: &tenantID,
				VsockCID: &cid,
				Status:   orchestrator.StatusProvisioning,
			},
		},
	}

	auditLogger := &captureConnectorAuditLogger{}
	resolver := proxy.NewConnectorActionResolver(pool, proxy.NewConnPool(proxy.NewTCPTransport(9893)), agents, actionStore).WithAuditLogger(auditLogger)

	err := resolver.ResolveConnectorAction(ctx, tenantID, request, true)
	require.Error(t, err)

	var stored *connectors.GovernedAction
	getErr := database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		var readErr error
		stored, readErr = actionStore.GetByID(ctx, q, action.ID)
		return readErr
	})
	require.NoError(t, getErr)
	assert.Equal(t, connectors.GovernedActionStatusFailed, stored.Status)
	require.Len(t, auditLogger.events, 2)
	assert.Equal(t, audit.ActionConnectorWriteApproved, auditLogger.events[0].Action)
	assert.Equal(t, audit.ActionConnectorWriteFailed, auditLogger.events[1].Action)
}

func TestConnectorActionResolver_ReturnsErrorWhenDependenciesMissing(t *testing.T) {
	t.Parallel()

	request := &approvals.Request{
		ID:       uuid.New(),
		TenantID: uuid.New(),
		Metadata: map[string]any{"governed_action_id": uuid.NewString()},
	}

	var resolver *proxy.ConnectorActionResolver
	err := resolver.ResolveConnectorAction(context.Background(), uuid.NewString(), request, true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connector action resolver unavailable")
}

func mustUUID(t *testing.T, value string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(value)
	require.NoError(t, err)
	return id
}
