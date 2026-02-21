package tenant

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

// DepartmentStore handles department database operations.
// Methods accept database.Querier so they can run inside WithTenantConnection.
type DepartmentStore struct{}

// NewDepartmentStore creates a new department store.
func NewDepartmentStore() *DepartmentStore {
	return &DepartmentStore{}
}

// Create inserts a new department. The tenant_id is read from the RLS session variable.
// If parentID is provided, it must reference a department visible through RLS (same tenant).
func (s *DepartmentStore) Create(ctx context.Context, q database.Querier, name string, parentID *string) (*Department, error) {
	if err := ValidateDepartmentName(name); err != nil {
		return nil, err
	}

	// Validate parent exists in this tenant (FK checks bypass RLS, so we verify manually)
	if parentID != nil {
		_, err := s.GetByID(ctx, q, *parentID)
		if err != nil {
			return nil, fmt.Errorf("invalid parent department: %w", err)
		}
	}

	var dept Department
	err := q.QueryRow(ctx,
		`INSERT INTO departments (tenant_id, name, parent_id)
		 VALUES (current_setting('app.current_tenant_id', true)::UUID, $1, $2)
		 RETURNING id, tenant_id, name, parent_id, created_at`,
		name, parentID,
	).Scan(&dept.ID, &dept.TenantID, &dept.Name, &dept.ParentID, &dept.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("creating department: %w", err)
	}
	return &dept, nil
}

// GetByID retrieves a department by ID. RLS ensures tenant isolation.
func (s *DepartmentStore) GetByID(ctx context.Context, q database.Querier, id string) (*Department, error) {
	var dept Department
	err := q.QueryRow(ctx,
		`SELECT id, tenant_id, name, parent_id, created_at
		 FROM departments WHERE id = $1`,
		id,
	).Scan(&dept.ID, &dept.TenantID, &dept.Name, &dept.ParentID, &dept.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrDepartmentNotFound
		}
		return nil, fmt.Errorf("getting department: %w", err)
	}
	return &dept, nil
}

// List returns all departments visible through RLS (current tenant).
func (s *DepartmentStore) List(ctx context.Context, q database.Querier) ([]Department, error) {
	rows, err := q.Query(ctx,
		`SELECT id, tenant_id, name, parent_id, created_at
		 FROM departments ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("listing departments: %w", err)
	}
	defer rows.Close()

	var departments []Department
	for rows.Next() {
		var d Department
		if err := rows.Scan(&d.ID, &d.TenantID, &d.Name, &d.ParentID, &d.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning department: %w", err)
		}
		departments = append(departments, d)
	}
	return departments, rows.Err()
}
