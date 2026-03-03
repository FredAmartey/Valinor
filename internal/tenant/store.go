package tenant

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store handles tenant database operations.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore creates a new tenant store.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// Create inserts a new tenant with the given name and slug.
func (s *Store) Create(ctx context.Context, name, slug string) (*Tenant, error) {
	if err := ValidateSlug(slug); err != nil {
		return nil, err
	}

	var t Tenant
	err := s.pool.QueryRow(ctx,
		`INSERT INTO tenants (name, slug) VALUES ($1, $2)
		 RETURNING id, name, slug, status, created_at, updated_at`,
		name, slug,
	).Scan(&t.ID, &t.Name, &t.Slug, &t.Status, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "unique constraint") {
			return nil, fmt.Errorf("%w: %s", ErrSlugTaken, slug)
		}
		return nil, fmt.Errorf("creating tenant: %w", err)
	}
	return &t, nil
}

// GetByID retrieves a tenant by its UUID.
func (s *Store) GetByID(ctx context.Context, id string) (*Tenant, error) {
	var t Tenant
	err := s.pool.QueryRow(ctx,
		`SELECT id, name, slug, status, created_at, updated_at
		 FROM tenants WHERE id = $1`,
		id,
	).Scan(&t.ID, &t.Name, &t.Slug, &t.Status, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrTenantNotFound
		}
		return nil, fmt.Errorf("getting tenant: %w", err)
	}
	return &t, nil
}

// GetStats returns aggregate resource counts for a tenant.
func (s *Store) GetStats(ctx context.Context, tenantID string) (*Stats, error) {
	var stats Stats
	err := s.pool.QueryRow(ctx,
		`SELECT
			(SELECT COUNT(*) FROM users WHERE tenant_id = $1),
			(SELECT COUNT(*) FROM departments WHERE tenant_id = $1),
			(SELECT COUNT(*) FROM agent_instances WHERE tenant_id = $1),
			(SELECT COUNT(*) FROM connectors WHERE tenant_id = $1)`,
		tenantID,
	).Scan(&stats.Users, &stats.Departments, &stats.Agents, &stats.Connectors)
	if err != nil {
		return nil, fmt.Errorf("getting tenant stats: %w", err)
	}
	return &stats, nil
}

// SeedDefaultRoles inserts the standard system roles for a new tenant.
// Idempotent via ON CONFLICT DO NOTHING.
func (s *Store) SeedDefaultRoles(ctx context.Context, tenantID string) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO roles (tenant_id, name, permissions, is_system) VALUES
			($1, 'org_admin',     '["*"]', true),
			($1, 'dept_head',     '["users:read","users:write","departments:read","departments:write","agents:read","agents:write","connectors:read","audit:read","invites:read","invites:write"]', true),
			($1, 'standard_user', '["agents:read","agents:write","connectors:read","channels:read"]', true),
			($1, 'read_only',     '["agents:read","connectors:read","channels:read","audit:read"]', true)
		 ON CONFLICT (tenant_id, name) DO NOTHING`,
		tenantID,
	)
	if err != nil {
		return fmt.Errorf("seeding default roles: %w", err)
	}
	return nil
}

// List returns all tenants.
func (s *Store) List(ctx context.Context) ([]Tenant, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, slug, status, created_at, updated_at
		 FROM tenants ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("listing tenants: %w", err)
	}
	defer rows.Close()

	var tenants []Tenant
	for rows.Next() {
		var t Tenant
		if err := rows.Scan(&t.ID, &t.Name, &t.Slug, &t.Status, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scanning tenant: %w", err)
		}
		tenants = append(tenants, t)
	}
	return tenants, rows.Err()
}
