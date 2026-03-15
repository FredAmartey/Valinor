package connectors_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/valinor-ai/valinor/internal/connectors"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

func setupActionsTestDB(t *testing.T) (*database.Pool, func()) {
	t.Helper()
	ctx := context.Background()

	container, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("valinor_test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").WithOccurrence(2),
		),
	)
	require.NoError(t, err)

	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	err = database.RunMigrations(connStr, "file://../../migrations")
	require.NoError(t, err)

	pool, err := database.Connect(ctx, connStr, 5)
	require.NoError(t, err)

	cleanup := func() {
		pool.Close()
		_ = container.Terminate(ctx)
	}

	return pool, cleanup
}

func seedTenantConnectorAndAgent(t *testing.T, ctx context.Context, pool *database.Pool, slug string) (string, uuid.UUID, uuid.UUID) {
	t.Helper()

	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ($1, $2) RETURNING id",
		"Tenant "+slug,
		tenantSlug(slug),
	).Scan(&tenantID)
	require.NoError(t, err)

	var agentID uuid.UUID
	err = pool.QueryRow(ctx,
		"INSERT INTO agent_instances (tenant_id, status) VALUES ($1, 'running') RETURNING id",
		tenantID,
	).Scan(&agentID)
	require.NoError(t, err)

	connectorStore := connectors.NewStore()
	var connectorID uuid.UUID
	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		connector, createErr := connectorStore.Create(
			ctx,
			q,
			"salesforce-"+slug,
			"mcp",
			"https://example.com/"+slug,
			json.RawMessage(`{}`),
			json.RawMessage(`[]`),
			json.RawMessage(`[]`),
		)
		if createErr != nil {
			return createErr
		}
		connectorID = connector.ID
		return nil
	})
	require.NoError(t, err)

	return tenantID, connectorID, agentID
}

func tenantSlug(input string) string {
	id := strings.NewReplacer("_", "-", " ", "-").Replace(input)
	return "tenant-" + id
}

func TestGovernedActionStore_CreateGetAndTransition(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupActionsTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := connectors.NewGovernedActionStore()

	tenantID, connectorID, agentID := seedTenantConnectorAndAgent(t, ctx, pool, "primary")
	sessionID := "session-123"
	correlationID := "corr-123"

	var created *connectors.GovernedAction
	err := database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		var createErr error
		created, createErr = store.Create(ctx, q, connectors.CreateGovernedActionParams{
			TenantID:      mustUUID(t, tenantID),
			AgentID:       &agentID,
			SessionID:     sessionID,
			CorrelationID: correlationID,
			ConnectorID:   connectorID,
			ToolName:      "salesforce.update_contact",
			RiskClass:     "external_writes",
			TargetType:    "crm_record",
			TargetLabel:   "salesforce:contact/123",
			ActionSummary: "Update Salesforce contact 123.",
			Arguments:     json.RawMessage(`{"id":"123","email":"updated@example.com"}`),
			Status:        connectors.GovernedActionStatusPending,
		})
		return createErr
	})
	require.NoError(t, err)
	require.NotNil(t, created)
	assert.Equal(t, mustUUID(t, tenantID), created.TenantID)
	require.NotNil(t, created.AgentID)
	assert.Equal(t, agentID, *created.AgentID)
	assert.Equal(t, sessionID, created.SessionID)
	assert.Equal(t, correlationID, created.CorrelationID)
	assert.Equal(t, connectorID, created.ConnectorID)
	assert.Equal(t, "salesforce.update_contact", created.ToolName)
	assert.Equal(t, "external_writes", created.RiskClass)
	assert.Equal(t, connectors.GovernedActionStatusPending, created.Status)

	var fetched *connectors.GovernedAction
	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		var getErr error
		fetched, getErr = store.GetByID(ctx, q, created.ID)
		return getErr
	})
	require.NoError(t, err)
	require.NotNil(t, fetched)
	assert.Equal(t, created.ID, fetched.ID)
	assert.JSONEq(t, string(created.Arguments), string(fetched.Arguments))

	var approvalID uuid.UUID
	err = pool.QueryRow(ctx,
		`INSERT INTO approval_requests (
			tenant_id, risk_class, status, target_type, target_label, action_summary
		) VALUES ($1, 'external_writes', 'pending', 'crm_record', 'salesforce:contact/123', 'Review Salesforce update')
		RETURNING id`,
		tenantID,
	).Scan(&approvalID)
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		if _, updateErr := store.MarkAwaitingApproval(ctx, q, created.ID, approvalID); updateErr != nil {
			return updateErr
		}
		if _, updateErr := store.MarkApproved(ctx, q, created.ID); updateErr != nil {
			return updateErr
		}
		if _, updateErr := store.MarkExecuted(ctx, q, created.ID); updateErr != nil {
			return updateErr
		}
		return nil
	})
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		var getErr error
		fetched, getErr = store.GetByID(ctx, q, created.ID)
		return getErr
	})
	require.NoError(t, err)
	require.NotNil(t, fetched)
	assert.Equal(t, connectors.GovernedActionStatusExecuted, fetched.Status)
	require.NotNil(t, fetched.ApprovalRequestID)
	assert.Equal(t, approvalID, *fetched.ApprovalRequestID)
}

func TestGovernedActionStore_DeniedAndFailedTransitions(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupActionsTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := connectors.NewGovernedActionStore()

	tenantID, connectorID, _ := seedTenantConnectorAndAgent(t, ctx, pool, "secondary")

	var created *connectors.GovernedAction
	err := database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		var createErr error
		created, createErr = store.Create(ctx, q, connectors.CreateGovernedActionParams{
			TenantID:      mustUUID(t, tenantID),
			ConnectorID:   connectorID,
			ToolName:      "hubspot.create_note",
			RiskClass:     "external_writes",
			TargetType:    "crm_record",
			TargetLabel:   "hubspot:note/456",
			ActionSummary: "Create HubSpot note 456.",
			Arguments:     json.RawMessage(`{"note":"hello"}`),
			Status:        connectors.GovernedActionStatusPending,
		})
		return createErr
	})
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		if _, updateErr := store.MarkDenied(ctx, q, created.ID); updateErr != nil {
			return updateErr
		}
		if _, updateErr := store.MarkFailed(ctx, q, created.ID); updateErr == nil {
			t.Fatal("expected failed transition from denied state to be rejected")
		}
		return nil
	})
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		var getErr error
		created, getErr = store.GetByID(ctx, q, created.ID)
		return getErr
	})
	require.NoError(t, err)
	assert.Equal(t, connectors.GovernedActionStatusDenied, created.Status)
}

func TestGovernedActionStore_TenantIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupActionsTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := connectors.NewGovernedActionStore()

	tenantA, connectorA, _ := seedTenantConnectorAndAgent(t, ctx, pool, "tenant_a")
	tenantB, _, _ := seedTenantConnectorAndAgent(t, ctx, pool, "tenant_b")

	var created *connectors.GovernedAction
	err := database.WithTenantConnection(ctx, pool, tenantA, func(ctx context.Context, q database.Querier) error {
		var createErr error
		created, createErr = store.Create(ctx, q, connectors.CreateGovernedActionParams{
			TenantID:      mustUUID(t, tenantA),
			ConnectorID:   connectorA,
			ToolName:      "salesforce.delete_contact",
			RiskClass:     "destructive_actions",
			TargetType:    "crm_record",
			TargetLabel:   "salesforce:contact/999",
			ActionSummary: "Delete Salesforce contact 999.",
			Arguments:     json.RawMessage(`{"id":"999"}`),
			Status:        connectors.GovernedActionStatusPending,
		})
		return createErr
	})
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantB, func(ctx context.Context, q database.Querier) error {
		_, getErr := store.GetByID(ctx, q, created.ID)
		return getErr
	})
	require.ErrorIs(t, err, connectors.ErrGovernedActionNotFound)
}

func mustUUID(t *testing.T, value string) uuid.UUID {
	t.Helper()
	id, err := uuid.Parse(value)
	require.NoError(t, err)
	return id
}
