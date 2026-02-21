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
