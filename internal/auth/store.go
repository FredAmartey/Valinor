package auth

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// OIDCUserInfo represents user info returned from an OIDC provider.
type OIDCUserInfo struct {
	Issuer  string
	Subject string
	Email   string
	Name    string
}

// Store handles user-related database operations for authentication.
type Store struct {
	pool *pgxpool.Pool
}

func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// FindOrCreateByOIDC finds a user by OIDC credentials or creates a new one.
// Returns the identity, whether the user was created, and any error.
func (s *Store) FindOrCreateByOIDC(ctx context.Context, info OIDCUserInfo, defaultTenantID string) (*Identity, bool, error) {
	// Try to find existing user
	var userID, tenantID, email, displayName string
	err := s.pool.QueryRow(ctx,
		"SELECT id, tenant_id, email, COALESCE(display_name, '') FROM users WHERE oidc_issuer = $1 AND oidc_subject = $2",
		info.Issuer, info.Subject,
	).Scan(&userID, &tenantID, &email, &displayName)

	if err == nil {
		// User exists, fetch full identity
		identity, err := s.GetIdentityWithRoles(ctx, userID)
		if err != nil {
			return nil, false, fmt.Errorf("getting identity: %w", err)
		}
		return identity, false, nil
	}

	if err != pgx.ErrNoRows {
		return nil, false, fmt.Errorf("querying user: %w", err)
	}

	// User doesn't exist, create one
	err = s.pool.QueryRow(ctx,
		`INSERT INTO users (tenant_id, email, display_name, oidc_issuer, oidc_subject)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id`,
		defaultTenantID, info.Email, info.Name, info.Issuer, info.Subject,
	).Scan(&userID)
	if err != nil {
		return nil, false, fmt.Errorf("creating user: %w", err)
	}

	return &Identity{
		UserID:      userID,
		TenantID:    defaultTenantID,
		Email:       info.Email,
		DisplayName: info.Name,
	}, true, nil
}

// GetIdentityWithRoles fetches a user's full identity including roles and departments.
func (s *Store) GetIdentityWithRoles(ctx context.Context, userID string) (*Identity, error) {
	// Get user base info
	var tenantID, email, displayName string
	err := s.pool.QueryRow(ctx,
		"SELECT tenant_id, email, COALESCE(display_name, '') FROM users WHERE id = $1",
		userID,
	).Scan(&tenantID, &email, &displayName)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("querying user: %w", err)
	}

	// Get role names
	rows, err := s.pool.Query(ctx,
		`SELECT r.name FROM roles r
		 JOIN user_roles ur ON ur.role_id = r.id
		 WHERE ur.user_id = $1`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("querying roles: %w", err)
	}
	defer rows.Close()

	var roles []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("scanning role: %w", err)
		}
		roles = append(roles, name)
	}

	// Get department IDs
	deptRows, err := s.pool.Query(ctx,
		"SELECT department_id FROM user_departments WHERE user_id = $1",
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("querying departments: %w", err)
	}
	defer deptRows.Close()

	var departments []string
	for deptRows.Next() {
		var deptID string
		if err := deptRows.Scan(&deptID); err != nil {
			return nil, fmt.Errorf("scanning department: %w", err)
		}
		departments = append(departments, deptID)
	}

	return &Identity{
		UserID:      userID,
		TenantID:    tenantID,
		Email:       email,
		DisplayName: displayName,
		Roles:       roles,
		Departments: departments,
		TokenType:   "access",
	}, nil
}
