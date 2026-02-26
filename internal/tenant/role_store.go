package tenant

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/valinor-ai/valinor/internal/platform/database"
	"github.com/valinor-ai/valinor/internal/rbac"
)

// RoleStore handles role database operations within a tenant.
type RoleStore struct{}

// NewRoleStore creates a new role store.
func NewRoleStore() *RoleStore {
	return &RoleStore{}
}

// Create inserts a new role. The tenant_id is read from the RLS session variable.
func (s *RoleStore) Create(ctx context.Context, q database.Querier, name string, permissions []string) (*Role, error) {
	if strings.TrimSpace(name) == "" {
		return nil, ErrRoleNameEmpty
	}

	permJSON, err := json.Marshal(permissions)
	if err != nil {
		return nil, fmt.Errorf("marshaling permissions: %w", err)
	}

	var role Role
	var permBytes []byte
	err = q.QueryRow(ctx,
		`INSERT INTO roles (tenant_id, name, permissions)
		 VALUES (current_setting('app.current_tenant_id', true)::UUID, $1, $2)
		 RETURNING id, tenant_id, name, permissions, is_system, created_at`,
		name, permJSON,
	).Scan(&role.ID, &role.TenantID, &role.Name, &permBytes, &role.IsSystem, &role.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, fmt.Errorf("%w: %s", ErrRoleDuplicate, name)
		}
		return nil, fmt.Errorf("creating role: %w", err)
	}

	if err := json.Unmarshal(permBytes, &role.Permissions); err != nil {
		return nil, fmt.Errorf("unmarshaling permissions: %w", err)
	}

	return &role, nil
}

// GetByID retrieves a role by ID. RLS ensures tenant isolation.
func (s *RoleStore) GetByID(ctx context.Context, q database.Querier, id string) (*Role, error) {
	var role Role
	var permBytes []byte
	err := q.QueryRow(ctx,
		`SELECT id, tenant_id, name, permissions, is_system, created_at
		 FROM roles WHERE id = $1`,
		id,
	).Scan(&role.ID, &role.TenantID, &role.Name, &permBytes, &role.IsSystem, &role.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrRoleNotFound
		}
		return nil, fmt.Errorf("getting role: %w", err)
	}
	if err := json.Unmarshal(permBytes, &role.Permissions); err != nil {
		return nil, fmt.Errorf("unmarshaling permissions: %w", err)
	}
	return &role, nil
}

// List returns all roles visible through RLS (current tenant).
func (s *RoleStore) List(ctx context.Context, q database.Querier) ([]Role, error) {
	rows, err := q.Query(ctx,
		`SELECT id, tenant_id, name, permissions, is_system, created_at
		 FROM roles ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("listing roles: %w", err)
	}
	defer rows.Close()

	var roles []Role
	for rows.Next() {
		var r Role
		var permBytes []byte
		if err := rows.Scan(&r.ID, &r.TenantID, &r.Name, &permBytes, &r.IsSystem, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning role: %w", err)
		}
		if err := json.Unmarshal(permBytes, &r.Permissions); err != nil {
			return nil, fmt.Errorf("unmarshaling permissions: %w", err)
		}
		roles = append(roles, r)
	}
	return roles, rows.Err()
}

// LoadRoles loads all role definitions across all tenants.
// Used by the RBAC evaluator at startup and after mutations.
// This queries the pool directly (no RLS context) because the evaluator
// needs a global view of all tenants' roles keyed by (tenant_id, name).
func (s *RoleStore) LoadRoles(ctx context.Context, pool *pgxpool.Pool) ([]rbac.RoleDef, error) {
	rows, err := pool.Query(ctx,
		`SELECT tenant_id, name, permissions
		 FROM roles
		 ORDER BY tenant_id, name`)
	if err != nil {
		return nil, fmt.Errorf("loading roles: %w", err)
	}
	defer rows.Close()

	var defs []rbac.RoleDef
	for rows.Next() {
		var tenantID, name string
		var permBytes []byte
		if err := rows.Scan(&tenantID, &name, &permBytes); err != nil {
			return nil, fmt.Errorf("scanning role: %w", err)
		}
		var perms []string
		if err := json.Unmarshal(permBytes, &perms); err != nil {
			return nil, fmt.Errorf("unmarshaling permissions for %s: %w", name, err)
		}
		defs = append(defs, rbac.RoleDef{TenantID: tenantID, Name: name, Permissions: perms})
	}
	return defs, rows.Err()
}

// Update modifies a custom role's name and permissions. Returns ErrRoleIsSystem for system roles.
// The is_system check and update are combined in a single statement to avoid TOCTOU races.
func (s *RoleStore) Update(ctx context.Context, q database.Querier, id string, name string, permissions []string) (*Role, error) {
	if strings.TrimSpace(name) == "" {
		return nil, ErrRoleNameEmpty
	}

	permJSON, err := json.Marshal(permissions)
	if err != nil {
		return nil, fmt.Errorf("marshaling permissions: %w", err)
	}

	var role Role
	var permBytes []byte
	err = q.QueryRow(ctx,
		`UPDATE roles SET name = $1, permissions = $2
		 WHERE id = $3 AND NOT is_system
		 RETURNING id, tenant_id, name, permissions, is_system, created_at`,
		name, permJSON, id,
	).Scan(&role.ID, &role.TenantID, &role.Name, &permBytes, &role.IsSystem, &role.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Distinguish "not found" from "is system role"
			var isSystem bool
			if checkErr := q.QueryRow(ctx, `SELECT is_system FROM roles WHERE id = $1`, id).Scan(&isSystem); checkErr != nil {
				return nil, ErrRoleNotFound
			}
			if isSystem {
				return nil, ErrRoleIsSystem
			}
			return nil, ErrRoleNotFound
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, fmt.Errorf("%w: %s", ErrRoleDuplicate, name)
		}
		return nil, fmt.Errorf("updating role: %w", err)
	}
	if err := json.Unmarshal(permBytes, &role.Permissions); err != nil {
		return nil, fmt.Errorf("unmarshaling permissions: %w", err)
	}
	return &role, nil
}

// Delete removes a custom role. Returns ErrRoleIsSystem for system roles,
// ErrRoleHasUsers if the role is assigned to any users.
// The delete and checks are combined to avoid TOCTOU races.
func (s *RoleStore) Delete(ctx context.Context, q database.Querier, id string) error {
	var deleted bool
	err := q.QueryRow(ctx,
		`DELETE FROM roles
		 WHERE id = $1
		   AND NOT is_system
		   AND NOT EXISTS (SELECT 1 FROM user_roles WHERE role_id = $1)
		 RETURNING true`,
		id,
	).Scan(&deleted)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Distinguish: not found vs system role vs has users
			var isSystem bool
			if checkErr := q.QueryRow(ctx, `SELECT is_system FROM roles WHERE id = $1`, id).Scan(&isSystem); checkErr != nil {
				return ErrRoleNotFound
			}
			if isSystem {
				return ErrRoleIsSystem
			}
			return ErrRoleHasUsers
		}
		return fmt.Errorf("deleting role: %w", err)
	}
	return nil
}

// RoleLoaderAdapter adapts RoleStore to the rbac.RoleLoader interface.
type RoleLoaderAdapter struct {
	store *RoleStore
	pool  *pgxpool.Pool
}

// NewRoleLoaderAdapter creates a RoleLoader backed by the roles table.
func NewRoleLoaderAdapter(store *RoleStore, pool *pgxpool.Pool) *RoleLoaderAdapter {
	return &RoleLoaderAdapter{store: store, pool: pool}
}

// LoadRoles implements rbac.RoleLoader.
func (a *RoleLoaderAdapter) LoadRoles(ctx context.Context) ([]rbac.RoleDef, error) {
	return a.store.LoadRoles(ctx, a.pool)
}

// AssignToUser assigns a role to a user with a scope (org or department).
func (s *RoleStore) AssignToUser(ctx context.Context, q database.Querier, userID, roleID, scopeType, scopeID string) error {
	_, err := q.Exec(ctx,
		`INSERT INTO user_roles (user_id, role_id, scope_type, scope_id)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT DO NOTHING`,
		userID, roleID, scopeType, scopeID,
	)
	if err != nil {
		return fmt.Errorf("assigning role: %w", err)
	}
	return nil
}

// RemoveFromUser removes a role assignment from a user.
func (s *RoleStore) RemoveFromUser(ctx context.Context, q database.Querier, userID, roleID, scopeType, scopeID string) error {
	_, err := q.Exec(ctx,
		`DELETE FROM user_roles
		 WHERE user_id = $1 AND role_id = $2 AND scope_type = $3 AND scope_id = $4`,
		userID, roleID, scopeType, scopeID,
	)
	if err != nil {
		return fmt.Errorf("removing role: %w", err)
	}
	return nil
}

// ListForUser returns all role assignments for a user.
func (s *RoleStore) ListForUser(ctx context.Context, q database.Querier, userID string) ([]UserRole, error) {
	rows, err := q.Query(ctx,
		`SELECT ur.user_id, ur.role_id, r.name, ur.scope_type, ur.scope_id
		 FROM user_roles ur
		 JOIN roles r ON r.id = ur.role_id
		 WHERE ur.user_id = $1
		 ORDER BY r.name`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("listing user roles: %w", err)
	}
	defer rows.Close()

	var roles []UserRole
	for rows.Next() {
		var ur UserRole
		if err := rows.Scan(&ur.UserID, &ur.RoleID, &ur.RoleName, &ur.ScopeType, &ur.ScopeID); err != nil {
			return nil, fmt.Errorf("scanning user role: %w", err)
		}
		roles = append(roles, ur)
	}
	return roles, rows.Err()
}
