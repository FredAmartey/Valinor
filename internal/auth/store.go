package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// isUniqueViolation checks if err is a PostgreSQL unique_violation (23505).
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

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
// Handles two unique constraints: (oidc_issuer, oidc_subject) and (tenant_id, email).
// Returns the identity, whether the user was created, and any error.
func (s *Store) FindOrCreateByOIDC(ctx context.Context, info OIDCUserInfo, defaultTenantID string) (*Identity, bool, error) {
	var userID string
	created := false

	// Attempt atomic insert — ON CONFLICT handles the OIDC uniqueness constraint.
	err := s.pool.QueryRow(ctx,
		`INSERT INTO users (tenant_id, email, display_name, oidc_issuer, oidc_subject)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (oidc_issuer, oidc_subject) DO NOTHING
		 RETURNING id`,
		defaultTenantID, info.Email, info.Name, info.Issuer, info.Subject,
	).Scan(&userID)

	if err == nil {
		// Insert succeeded — new user created.
		created = true
	} else if errors.Is(err, pgx.ErrNoRows) {
		// OIDC conflict — user already exists with these OIDC credentials.
		err = s.pool.QueryRow(ctx,
			"SELECT id FROM users WHERE oidc_issuer = $1 AND oidc_subject = $2",
			info.Issuer, info.Subject,
		).Scan(&userID)
		if err != nil {
			return nil, false, fmt.Errorf("querying existing OIDC user: %w", err)
		}
	} else if isUniqueViolation(err) {
		// Hit the (tenant_id, email) constraint. Two possible causes:
		//   a) Race condition: concurrent INSERT with same OIDC subject already won.
		//   b) Existing user with this email but no OIDC credentials (e.g. dev-seeded).
		resolved, resolveErr := s.resolveEmailConflict(ctx, info, defaultTenantID)
		if resolveErr != nil {
			return nil, false, fmt.Errorf("resolving email conflict: %w", resolveErr)
		}
		userID = resolved
	} else {
		return nil, false, fmt.Errorf("upserting user: %w", err)
	}

	identity, err := s.GetIdentityWithRoles(ctx, userID)
	if err != nil {
		return nil, false, fmt.Errorf("getting identity: %w", err)
	}
	return identity, created, nil
}

// resolveEmailConflict handles the (tenant_id, email) unique violation.
// First checks if the OIDC user was created by a concurrent request (race condition).
// Otherwise, links OIDC credentials to the existing email-matched user.
func (s *Store) resolveEmailConflict(ctx context.Context, info OIDCUserInfo, tenantID string) (string, error) {
	// Check for race condition: another request already inserted with these OIDC creds.
	var userID string
	err := s.pool.QueryRow(ctx,
		"SELECT id FROM users WHERE oidc_issuer = $1 AND oidc_subject = $2",
		info.Issuer, info.Subject,
	).Scan(&userID)
	if err == nil {
		return userID, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("checking for race condition: %w", err)
	}

	// No race — existing user with same (tenant_id, email) but no OIDC creds.
	// Link OIDC credentials to that user.
	err = s.pool.QueryRow(ctx,
		`UPDATE users
		 SET oidc_issuer = $1, oidc_subject = $2, display_name = COALESCE(NULLIF(display_name, ''), $3)
		 WHERE tenant_id = $4 AND email = $5 AND (oidc_issuer = '' OR oidc_issuer IS NULL)
		 RETURNING id`,
		info.Issuer, info.Subject, info.Name, tenantID, info.Email,
	).Scan(&userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", fmt.Errorf("email conflict but user already has different OIDC credentials")
		}
		return "", fmt.Errorf("linking OIDC to existing user: %w", err)
	}
	return userID, nil
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

// FindUserIDByEmail looks up a user by email address.
// Returns the user ID or ErrUserNotFound if no user matches.
func (s *Store) FindUserIDByEmail(ctx context.Context, email string) (string, error) {
	// NOTE: Not tenant-scoped. Dev login must find users across tenants
	// because platform admins may not have a tenant. Acceptable because
	// this code path only executes when devmode is enabled.
	// ORDER BY created_at ensures deterministic results when the same
	// email exists across multiple tenants.
	var userID string
	err := s.pool.QueryRow(ctx,
		"SELECT id FROM users WHERE email = $1 ORDER BY created_at ASC LIMIT 1",
		email,
	).Scan(&userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrUserNotFound
		}
		return "", fmt.Errorf("querying user by email: %w", err)
	}
	return userID, nil
}

// UpdateUserTenant assigns a tenant to a tenantless user (post-signup).
func (s *Store) UpdateUserTenant(ctx context.Context, userID, tenantID string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE users SET tenant_id = $1 WHERE id = $2 AND tenant_id IS NULL`,
		tenantID, userID,
	)
	if err != nil {
		return fmt.Errorf("updating user tenant: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user not found or already has a tenant")
	}
	return nil
}

// AssignRole inserts a role assignment for a user in a tenant.
func (s *Store) AssignRole(ctx context.Context, userID, tenantID, roleName string) error {
	tag, err := s.pool.Exec(ctx,
		`INSERT INTO user_roles (user_id, role_id, scope_type, scope_id)
		 SELECT $1, r.id, 'org', $2
		 FROM roles r WHERE r.tenant_id = $2 AND r.name = $3
		 ON CONFLICT DO NOTHING`,
		userID, tenantID, roleName,
	)
	if err != nil {
		return fmt.Errorf("assigning role: %w", err)
	}
	if tag.RowsAffected() == 0 {
		slog.Warn("role assignment had no effect — role may not exist for tenant",
			"role", roleName, "tenant_id", tenantID, "user_id", userID)
	}
	return nil
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
