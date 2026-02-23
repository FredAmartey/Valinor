package connectors

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

// Store handles connector database operations.
// Methods accept database.Querier so they can run inside WithTenantConnection.
type Store struct{}

// NewStore creates a new connector store.
func NewStore() *Store {
	return &Store{}
}

// Create inserts a new connector. The tenant_id is read from the RLS session variable.
func (s *Store) Create(ctx context.Context, q database.Querier, name, connectorType, endpoint string, authConfig, tools, resources json.RawMessage) (*Connector, error) {
	if name == "" {
		return nil, ErrNameEmpty
	}
	if endpoint == "" {
		return nil, ErrEndpointEmpty
	}
	if connectorType == "" {
		connectorType = "mcp"
	}
	if authConfig == nil {
		authConfig = json.RawMessage(`{}`)
	}
	if tools == nil {
		tools = json.RawMessage(`[]`)
	}
	if resources == nil {
		resources = json.RawMessage(`[]`)
	}

	var c Connector
	err := q.QueryRow(ctx,
		`INSERT INTO connectors (tenant_id, name, connector_type, endpoint, auth_config, tools, resources)
		 VALUES (current_setting('app.current_tenant_id', true)::UUID, $1, $2, $3, $4, $5, $6)
		 RETURNING id, tenant_id, name, connector_type, endpoint, auth_config, resources, tools, status, created_at`,
		name, connectorType, endpoint, authConfig, tools, resources,
	).Scan(&c.ID, &c.TenantID, &c.Name, &c.ConnectorType, &c.Endpoint, &c.AuthConfig, &c.Resources, &c.Tools, &c.Status, &c.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("creating connector: %w", err)
	}
	return &c, nil
}

// List returns all connectors visible through RLS (current tenant).
func (s *Store) List(ctx context.Context, q database.Querier) ([]Connector, error) {
	rows, err := q.Query(ctx,
		`SELECT id, tenant_id, name, connector_type, endpoint, auth_config, resources, tools, status, created_at
		 FROM connectors ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("listing connectors: %w", err)
	}
	defer rows.Close()

	var result []Connector
	for rows.Next() {
		var c Connector
		if err := rows.Scan(&c.ID, &c.TenantID, &c.Name, &c.ConnectorType, &c.Endpoint, &c.AuthConfig, &c.Resources, &c.Tools, &c.Status, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning connector: %w", err)
		}
		result = append(result, c)
	}
	return result, rows.Err()
}

// GetByID retrieves a connector by ID. RLS ensures tenant isolation.
func (s *Store) GetByID(ctx context.Context, q database.Querier, id string) (*Connector, error) {
	var c Connector
	err := q.QueryRow(ctx,
		`SELECT id, tenant_id, name, connector_type, endpoint, auth_config, resources, tools, status, created_at
		 FROM connectors WHERE id = $1`,
		id,
	).Scan(&c.ID, &c.TenantID, &c.Name, &c.ConnectorType, &c.Endpoint, &c.AuthConfig, &c.Resources, &c.Tools, &c.Status, &c.CreatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("getting connector: %w", err)
	}
	return &c, nil
}

// Delete removes a connector by ID. Returns ErrNotFound if no rows affected.
func (s *Store) Delete(ctx context.Context, q database.Querier, id string) error {
	tag, err := q.Exec(ctx, `DELETE FROM connectors WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("deleting connector: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListForAgent returns connectors as simplified config maps for agent injection.
func (s *Store) ListForAgent(ctx context.Context, q database.Querier) ([]map[string]any, error) {
	rows, err := q.Query(ctx,
		`SELECT name, connector_type, endpoint, auth_config, tools
		 FROM connectors WHERE status = 'active' ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("listing connectors for agent: %w", err)
	}
	defer rows.Close()

	var result []map[string]any
	for rows.Next() {
		var name, connType, endpoint string
		var authConfig, tools json.RawMessage
		if err := rows.Scan(&name, &connType, &endpoint, &authConfig, &tools); err != nil {
			return nil, fmt.Errorf("scanning connector for agent: %w", err)
		}
		result = append(result, map[string]any{
			"name":     name,
			"type":     connType,
			"endpoint": endpoint,
			"auth":     json.RawMessage(authConfig),
			"tools":    json.RawMessage(tools),
		})
	}
	return result, rows.Err()
}
