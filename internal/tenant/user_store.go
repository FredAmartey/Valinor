package tenant

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

// UserStore handles user database operations within a tenant.
type UserStore struct{}

// NewUserStore creates a new user store.
func NewUserStore() *UserStore {
	return &UserStore{}
}

// Create inserts a new user. The tenant_id is read from the RLS session variable.
func (s *UserStore) Create(ctx context.Context, q database.Querier, email, displayName string) (*User, error) {
	if err := ValidateEmail(email); err != nil {
		return nil, err
	}

	var user User
	err := q.QueryRow(ctx,
		`INSERT INTO users (tenant_id, email, display_name)
		 VALUES (current_setting('app.current_tenant_id', true)::UUID, $1, $2)
		 RETURNING id, tenant_id, email, COALESCE(display_name, ''), status, created_at`,
		email, displayName,
	).Scan(&user.ID, &user.TenantID, &user.Email, &user.DisplayName, &user.Status, &user.CreatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "unique constraint") {
			return nil, fmt.Errorf("%w: %s", ErrEmailDuplicate, email)
		}
		return nil, fmt.Errorf("creating user: %w", err)
	}
	return &user, nil
}

// GetByID retrieves a user by ID. RLS ensures tenant isolation.
func (s *UserStore) GetByID(ctx context.Context, q database.Querier, id string) (*User, error) {
	var user User
	err := q.QueryRow(ctx,
		`SELECT id, tenant_id, email, COALESCE(display_name, ''), status, created_at
		 FROM users WHERE id = $1`,
		id,
	).Scan(&user.ID, &user.TenantID, &user.Email, &user.DisplayName, &user.Status, &user.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("getting user: %w", err)
	}
	return &user, nil
}

// List returns all users visible through RLS (current tenant).
func (s *UserStore) List(ctx context.Context, q database.Querier) ([]User, error) {
	rows, err := q.Query(ctx,
		`SELECT id, tenant_id, email, COALESCE(display_name, ''), status, created_at
		 FROM users ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("listing users: %w", err)
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.TenantID, &u.Email, &u.DisplayName, &u.Status, &u.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning user: %w", err)
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// AddToDepartment adds a user to a department.
func (s *UserStore) AddToDepartment(ctx context.Context, q database.Querier, userID, departmentID string) error {
	_, err := q.Exec(ctx,
		"INSERT INTO user_departments (user_id, department_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
		userID, departmentID,
	)
	if err != nil {
		return fmt.Errorf("adding user to department: %w", err)
	}
	return nil
}

// RemoveFromDepartment removes a user from a department.
func (s *UserStore) RemoveFromDepartment(ctx context.Context, q database.Querier, userID, departmentID string) error {
	_, err := q.Exec(ctx,
		"DELETE FROM user_departments WHERE user_id = $1 AND department_id = $2",
		userID, departmentID,
	)
	if err != nil {
		return fmt.Errorf("removing user from department: %w", err)
	}
	return nil
}

// ListDepartments returns all departments a user belongs to.
func (s *UserStore) ListDepartments(ctx context.Context, q database.Querier, userID string) ([]Department, error) {
	rows, err := q.Query(ctx,
		`SELECT d.id, d.tenant_id, d.name, d.parent_id, d.created_at
		 FROM departments d
		 JOIN user_departments ud ON ud.department_id = d.id
		 WHERE ud.user_id = $1
		 ORDER BY d.name`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("listing user departments: %w", err)
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
