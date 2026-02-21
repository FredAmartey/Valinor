package auth

import (
	"context"
	"errors"
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

// FindOrCreateByOIDC atomically finds or creates a user by OIDC credentials.
// Uses INSERT ... ON CONFLICT to avoid TOCTOU race conditions.
// Returns the identity, whether the user was created, and any error.
func (s *Store) FindOrCreateByOIDC(ctx context.Context, info OIDCUserInfo, defaultTenantID string) (*Identity, bool, error) {
	// Attempt atomic upsert — ON CONFLICT DO NOTHING means RETURNING is empty on conflict
	var userID string
	created := false
	err := s.pool.QueryRow(ctx,
		`INSERT INTO users (tenant_id, email, display_name, oidc_issuer, oidc_subject)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (oidc_issuer, oidc_subject) DO NOTHING
		 RETURNING id`,
		defaultTenantID, info.Email, info.Name, info.Issuer, info.Subject,
	).Scan(&userID)

	if err == nil {
		created = true
	} else if errors.Is(err, pgx.ErrNoRows) {
		// Conflict fired — user already exists, look them up
		err = s.pool.QueryRow(ctx,
			"SELECT id FROM users WHERE oidc_issuer = $1 AND oidc_subject = $2",
			info.Issuer, info.Subject,
		).Scan(&userID)
		if err != nil {
			return nil, false, fmt.Errorf("querying existing user: %w", err)
		}
	} else {
		return nil, false, fmt.Errorf("upserting user: %w", err)
	}

	identity, err := s.GetIdentityWithRoles(ctx, userID)
	if err != nil {
		return nil, false, fmt.Errorf("getting identity: %w", err)
	}
	return identity, created, nil
}

// LookupPlatformAdminByOIDC looks up a platform admin by OIDC credentials.
// Returns nil, nil if the user exists but is not a platform admin.
// Returns nil, ErrUserNotFound if no matching user exists.
func (s *Store) LookupPlatformAdminByOIDC(ctx context.Context, issuer, subject string) (*Identity, error) {
	var userID string
	var isPlatformAdmin bool
	err := s.pool.QueryRow(ctx,
		"SELECT id, is_platform_admin FROM users WHERE oidc_issuer = $1 AND oidc_subject = $2",
		issuer, subject,
	).Scan(&userID, &isPlatformAdmin)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("looking up platform admin: %w", err)
	}

	if !isPlatformAdmin {
		return nil, nil
	}

	return s.GetIdentityWithRoles(ctx, userID)
}

// GetIdentityWithRoles fetches a user's full identity including roles and departments.
func (s *Store) GetIdentityWithRoles(ctx context.Context, userID string) (*Identity, error) {
	// Get user base info
	var tenantID, email, displayName string
	var isPlatformAdmin bool
	err := s.pool.QueryRow(ctx,
		"SELECT tenant_id, email, COALESCE(display_name, ''), is_platform_admin FROM users WHERE id = $1",
		userID,
	).Scan(&tenantID, &email, &displayName, &isPlatformAdmin)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
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
		if scanErr := rows.Scan(&name); scanErr != nil {
			return nil, fmt.Errorf("scanning role: %w", scanErr)
		}
		roles = append(roles, name)
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, fmt.Errorf("iterating roles: %w", rowsErr)
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
		if scanErr := deptRows.Scan(&deptID); scanErr != nil {
			return nil, fmt.Errorf("scanning department: %w", scanErr)
		}
		departments = append(departments, deptID)
	}
	if deptRowsErr := deptRows.Err(); deptRowsErr != nil {
		return nil, fmt.Errorf("iterating departments: %w", deptRowsErr)
	}

	return &Identity{
		UserID:          userID,
		TenantID:        tenantID,
		Email:           email,
		DisplayName:     displayName,
		Roles:           roles,
		Departments:     departments,
		TokenType:       "access",
		IsPlatformAdmin: isPlatformAdmin,
	}, nil
}
