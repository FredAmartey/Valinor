package connectors_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/FredAmartey/heimdall/internal/connectors"
	"github.com/FredAmartey/heimdall/internal/platform/database"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewStore(t *testing.T) {
	store := connectors.NewStore()
	if store == nil {
		t.Fatal("NewStore returned nil")
	}
}

func TestCreateValidation(t *testing.T) {
	store := connectors.NewStore()

	t.Run("empty name returns error", func(t *testing.T) {
		_, err := store.Create(context.Background(), nil, "", "mcp", "https://example.com", nil, nil, nil)
		if !errors.Is(err, connectors.ErrNameEmpty) {
			t.Fatalf("expected ErrNameEmpty, got %v", err)
		}
	})

	t.Run("empty endpoint returns error", func(t *testing.T) {
		_, err := store.Create(context.Background(), nil, "test", "mcp", "", nil, nil, nil)
		if !errors.Is(err, connectors.ErrEndpointEmpty) {
			t.Fatalf("expected ErrEndpointEmpty, got %v", err)
		}
	})

	t.Run("write tool without risk class returns error", func(t *testing.T) {
		tools := json.RawMessage(`[
			{"name":"salesforce.update_contact","action_type":"write"}
		]`)
		_, err := store.Create(context.Background(), nil, "test", "mcp", "https://example.com", nil, tools, nil)
		if !errors.Is(err, connectors.ErrConnectorToolRiskClassNeeded) {
			t.Fatalf("expected ErrConnectorToolRiskClassNeeded, got %v", err)
		}
	})

	t.Run("invalid action type returns error", func(t *testing.T) {
		tools := json.RawMessage(`[
			{"name":"salesforce.update_contact","action_type":"mutate","risk_class":"external_writes"}
		]`)
		_, err := store.Create(context.Background(), nil, "test", "mcp", "https://example.com", nil, tools, nil)
		if !errors.Is(err, connectors.ErrConnectorToolActionType) {
			t.Fatalf("expected ErrConnectorToolActionType, got %v", err)
		}
	})
}

func TestCreateStoresStructuredToolMetadata(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupActionsTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := connectors.NewStore()

	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Connector Meta', 'connector-meta') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	tools := connectors.EncodeTools([]connectors.ConnectorTool{
		{
			Name:                    "salesforce.update_contact",
			ActionType:              "write",
			RiskClass:               "external_writes",
			TargetType:              "crm_record",
			TargetLabelTemplate:     "salesforce:contact/{{id}}",
			ApprovalSummaryTemplate: "Update Salesforce contact {{id}}.",
		},
	})

	var connector *connectors.Connector
	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		var createErr error
		connector, createErr = store.Create(ctx, q, "salesforce", "mcp", "https://example.com/salesforce", nil, tools, nil)
		return createErr
	})
	require.NoError(t, err)
	require.NotNil(t, connector)
	assert.JSONEq(t, string(tools), string(connector.Tools))
}
