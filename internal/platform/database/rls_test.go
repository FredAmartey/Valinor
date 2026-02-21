package database_test

import (
	"context"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

// setupRLSTestDB creates a test database with migrations run as superuser,
// then returns a non-superuser pool (RLS enforced) and the superuser connStr
// for seeding. RLS policies are only enforced for non-superuser connections.
func setupRLSTestDB(t *testing.T) (rlsPool *database.Pool, superConnStr string, cleanup func()) {
	t.Helper()
	ctx := context.Background()

	connStr, containerCleanup := setupPostgres(t)

	// Run migrations as superuser
	err := database.RunMigrations(connStr, "file://../../../migrations")
	require.NoError(t, err)

	// Create a non-superuser role that respects RLS
	superPool, err := database.Connect(ctx, connStr, 2)
	require.NoError(t, err)

	_, err = superPool.Exec(ctx, `
		CREATE ROLE rls_user LOGIN PASSWORD 'rls_pass';
		GRANT USAGE ON SCHEMA public TO rls_user;
		GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO rls_user;
	`)
	require.NoError(t, err)
	superPool.Close()

	// Build connection string for rls_user
	rlsConnStr := replaceUserInConnStr(t, connStr, "rls_user", "rls_pass")

	pool, err := database.Connect(ctx, rlsConnStr, 5)
	require.NoError(t, err)

	cleanup = func() {
		pool.Close()
		containerCleanup()
	}

	return pool, connStr, cleanup
}

// replaceUserInConnStr swaps the user and password in a postgres connection string.
func replaceUserInConnStr(t *testing.T, connStr, user, password string) string {
	t.Helper()
	u, err := url.Parse(connStr)
	require.NoError(t, err)
	u.User = url.UserPassword(user, password)
	return u.String()
}

// seedTwoTenants creates two tenants with data in all RLS-protected tables.
// Must be called with superuser connStr (bypasses RLS).
func seedTwoTenants(t *testing.T, superConnStr string) (tenantA, tenantB string) {
	t.Helper()
	ctx := context.Background()

	pool, err := database.Connect(ctx, superConnStr, 2)
	require.NoError(t, err)
	defer pool.Close()

	err = pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Tenant A', 'tenant-a') RETURNING id",
	).Scan(&tenantA)
	require.NoError(t, err)

	err = pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Tenant B', 'tenant-b') RETURNING id",
	).Scan(&tenantB)
	require.NoError(t, err)

	// Users
	_, err = pool.Exec(ctx,
		"INSERT INTO users (tenant_id, email, display_name) VALUES ($1, 'a@a.com', 'User A')", tenantA)
	require.NoError(t, err)
	_, err = pool.Exec(ctx,
		"INSERT INTO users (tenant_id, email, display_name) VALUES ($1, 'b@b.com', 'User B')", tenantB)
	require.NoError(t, err)

	// Departments
	_, err = pool.Exec(ctx,
		"INSERT INTO departments (tenant_id, name) VALUES ($1, 'Dept A')", tenantA)
	require.NoError(t, err)
	_, err = pool.Exec(ctx,
		"INSERT INTO departments (tenant_id, name) VALUES ($1, 'Dept B')", tenantB)
	require.NoError(t, err)

	// Roles
	_, err = pool.Exec(ctx,
		"INSERT INTO roles (tenant_id, name, permissions) VALUES ($1, 'admin', '[\"*\"]')", tenantA)
	require.NoError(t, err)
	_, err = pool.Exec(ctx,
		"INSERT INTO roles (tenant_id, name, permissions) VALUES ($1, 'admin', '[\"*\"]')", tenantB)
	require.NoError(t, err)

	// Agent instances
	_, err = pool.Exec(ctx,
		"INSERT INTO agent_instances (tenant_id, status) VALUES ($1, 'active')", tenantA)
	require.NoError(t, err)
	_, err = pool.Exec(ctx,
		"INSERT INTO agent_instances (tenant_id, status) VALUES ($1, 'active')", tenantB)
	require.NoError(t, err)

	// Connectors
	_, err = pool.Exec(ctx,
		"INSERT INTO connectors (tenant_id, name, endpoint) VALUES ($1, 'Conn A', 'https://a.com')", tenantA)
	require.NoError(t, err)
	_, err = pool.Exec(ctx,
		"INSERT INTO connectors (tenant_id, name, endpoint) VALUES ($1, 'Conn B', 'https://b.com')", tenantB)
	require.NoError(t, err)

	// Resource policies
	_, err = pool.Exec(ctx,
		"INSERT INTO resource_policies (tenant_id, subject_type, subject_id, action, resource_type, effect) VALUES ($1, 'role', $1, 'read', 'agent', 'allow')",
		tenantA)
	require.NoError(t, err)
	_, err = pool.Exec(ctx,
		"INSERT INTO resource_policies (tenant_id, subject_type, subject_id, action, resource_type, effect) VALUES ($1, 'role', $1, 'read', 'agent', 'allow')",
		tenantB)
	require.NoError(t, err)

	// Look up IDs needed for junction tables
	var userAID, userBID string
	err = pool.QueryRow(ctx, "SELECT id FROM users WHERE tenant_id = $1", tenantA).Scan(&userAID)
	require.NoError(t, err)
	err = pool.QueryRow(ctx, "SELECT id FROM users WHERE tenant_id = $1", tenantB).Scan(&userBID)
	require.NoError(t, err)

	var roleAID, roleBID string
	err = pool.QueryRow(ctx, "SELECT id FROM roles WHERE tenant_id = $1", tenantA).Scan(&roleAID)
	require.NoError(t, err)
	err = pool.QueryRow(ctx, "SELECT id FROM roles WHERE tenant_id = $1", tenantB).Scan(&roleBID)
	require.NoError(t, err)

	var deptAID, deptBID string
	err = pool.QueryRow(ctx, "SELECT id FROM departments WHERE tenant_id = $1", tenantA).Scan(&deptAID)
	require.NoError(t, err)
	err = pool.QueryRow(ctx, "SELECT id FROM departments WHERE tenant_id = $1", tenantB).Scan(&deptBID)
	require.NoError(t, err)

	// user_roles
	_, err = pool.Exec(ctx,
		"INSERT INTO user_roles (user_id, role_id, scope_type, scope_id) VALUES ($1, $2, 'org', $3)",
		userAID, roleAID, tenantA)
	require.NoError(t, err)
	_, err = pool.Exec(ctx,
		"INSERT INTO user_roles (user_id, role_id, scope_type, scope_id) VALUES ($1, $2, 'org', $3)",
		userBID, roleBID, tenantB)
	require.NoError(t, err)

	// user_departments
	_, err = pool.Exec(ctx,
		"INSERT INTO user_departments (user_id, department_id) VALUES ($1, $2)",
		userAID, deptAID)
	require.NoError(t, err)
	_, err = pool.Exec(ctx,
		"INSERT INTO user_departments (user_id, department_id) VALUES ($1, $2)",
		userBID, deptBID)
	require.NoError(t, err)

	return tenantA, tenantB
}

func countRows(t *testing.T, ctx context.Context, q database.Querier, table string) int {
	t.Helper()
	var count int
	// Safe: table names are hardcoded constants in test code, not user input.
	err := q.QueryRow(ctx, "SELECT COUNT(*) FROM "+table).Scan(&count)
	require.NoError(t, err)
	return count
}

func TestRLS_TenantIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	rlsPool, superConnStr, cleanup := setupRLSTestDB(t)
	defer cleanup()

	tenantA, tenantB := seedTwoTenants(t, superConnStr)
	ctx := context.Background()

	// Tables with tenant_id-based RLS policies
	tables := []string{"users", "departments", "roles", "agent_instances", "connectors", "resource_policies", "user_roles", "user_departments"}

	for _, table := range tables {
		t.Run(table+"_tenant_a_sees_only_own", func(t *testing.T) {
			err := database.WithTenantConnection(ctx, rlsPool, tenantA, func(ctx context.Context, q database.Querier) error {
				count := countRows(t, ctx, q, table)
				assert.Equal(t, 1, count, "tenant A should see exactly 1 row in %s", table)
				return nil
			})
			require.NoError(t, err)
		})

		t.Run(table+"_tenant_b_sees_only_own", func(t *testing.T) {
			err := database.WithTenantConnection(ctx, rlsPool, tenantB, func(ctx context.Context, q database.Querier) error {
				count := countRows(t, ctx, q, table)
				assert.Equal(t, 1, count, "tenant B should see exactly 1 row in %s", table)
				return nil
			})
			require.NoError(t, err)
		})
	}

	t.Run("no_tenant_set_blocks_access", func(t *testing.T) {
		// Without a valid tenant UUID, RLS should prevent access.
		// The cleanup in WithTenantConnection resets the setting to '' which
		// causes a UUID cast error — this is correct security behavior:
		// queries without proper tenant context are blocked.
		for _, table := range tables {
			var count int
			err := rlsPool.QueryRow(ctx, "SELECT COUNT(*) FROM "+table).Scan(&count)
			if err != nil {
				// UUID cast error from empty/unset tenant — access blocked, correct behavior
				assert.Contains(t, err.Error(), "invalid input syntax for type uuid",
					"expected UUID cast error for %s without tenant context", table)
			} else {
				assert.Equal(t, 0, count,
					"without tenant context, %s should return 0 rows", table)
			}
		}
	})
}
