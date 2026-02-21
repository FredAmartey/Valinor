package auth_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

func setupTestDB(t *testing.T) (*database.Pool, func()) {
	t.Helper()
	ctx := context.Background()

	container, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("valinor_test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2),
		),
	)
	require.NoError(t, err)

	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	// Run migrations
	err = database.RunMigrations(connStr, "file://../../migrations")
	require.NoError(t, err)

	pool, err := database.Connect(ctx, connStr, 5)
	require.NoError(t, err)

	cleanup := func() {
		pool.Close()
		_ = container.Terminate(ctx)
	}

	return pool, cleanup
}

func TestStore_FindOrCreateByOIDC_NewUser(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	store := auth.NewStore(pool)
	ctx := context.Background()

	// First, create a tenant
	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ($1, $2) RETURNING id",
		"Chelsea FC", "chelsea-fc",
	).Scan(&tenantID)
	require.NoError(t, err)

	// Find or create user by OIDC
	identity, created, err := store.FindOrCreateByOIDC(ctx, auth.OIDCUserInfo{
		Issuer:  "https://accounts.google.com",
		Subject: "google-123",
		Email:   "scout@chelsea.com",
		Name:    "Scout A",
	}, tenantID)
	require.NoError(t, err)

	assert.True(t, created)
	assert.NotEmpty(t, identity.UserID)
	assert.Equal(t, tenantID, identity.TenantID)
	assert.Equal(t, "scout@chelsea.com", identity.Email)
	assert.Equal(t, "Scout A", identity.DisplayName)
}

func TestStore_FindOrCreateByOIDC_ExistingUser(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	store := auth.NewStore(pool)
	ctx := context.Background()

	// Create tenant
	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ($1, $2) RETURNING id",
		"Chelsea FC", "chelsea-fc",
	).Scan(&tenantID)
	require.NoError(t, err)

	userInfo := auth.OIDCUserInfo{
		Issuer:  "https://accounts.google.com",
		Subject: "google-123",
		Email:   "scout@chelsea.com",
		Name:    "Scout A",
	}

	// Create user first time
	identity1, created1, err := store.FindOrCreateByOIDC(ctx, userInfo, tenantID)
	require.NoError(t, err)
	assert.True(t, created1)

	// Find same user second time
	identity2, created2, err := store.FindOrCreateByOIDC(ctx, userInfo, tenantID)
	require.NoError(t, err)
	assert.False(t, created2)
	assert.Equal(t, identity1.UserID, identity2.UserID)
}

func TestStore_GetIdentityWithRoles(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	store := auth.NewStore(pool)
	ctx := context.Background()

	// Setup: tenant, user, role, assignment
	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ($1, $2) RETURNING id",
		"Chelsea FC", "chelsea-fc",
	).Scan(&tenantID)
	require.NoError(t, err)

	var userID string
	err = pool.QueryRow(ctx,
		"INSERT INTO users (tenant_id, email, display_name, oidc_subject, oidc_issuer) VALUES ($1, $2, $3, $4, $5) RETURNING id",
		tenantID, "scout@chelsea.com", "Scout A", "google-123", "https://accounts.google.com",
	).Scan(&userID)
	require.NoError(t, err)

	var roleID string
	err = pool.QueryRow(ctx,
		`INSERT INTO roles (tenant_id, name, permissions) VALUES ($1, $2, $3) RETURNING id`,
		tenantID, "standard_user", `["agents:read","agents:message"]`,
	).Scan(&roleID)
	require.NoError(t, err)

	_, err = pool.Exec(ctx,
		"INSERT INTO user_roles (user_id, role_id, scope_type, scope_id) VALUES ($1, $2, $3, $4)",
		userID, roleID, "org", tenantID,
	)
	require.NoError(t, err)

	// Create a department and assign user
	var deptID string
	err = pool.QueryRow(ctx,
		"INSERT INTO departments (tenant_id, name) VALUES ($1, $2) RETURNING id",
		tenantID, "Scouting",
	).Scan(&deptID)
	require.NoError(t, err)

	_, err = pool.Exec(ctx,
		"INSERT INTO user_departments (user_id, department_id) VALUES ($1, $2)",
		userID, deptID,
	)
	require.NoError(t, err)

	// Get full identity
	identity, err := store.GetIdentityWithRoles(ctx, userID)
	require.NoError(t, err)

	assert.Equal(t, userID, identity.UserID)
	assert.Equal(t, tenantID, identity.TenantID)
	assert.Equal(t, "scout@chelsea.com", identity.Email)
	assert.Contains(t, identity.Roles, "standard_user")
	assert.Contains(t, identity.Departments, deptID)
}

func TestStore_GetIdentityWithRoles_PlatformAdmin(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := auth.NewStore(pool)

	// Create tenant and platform admin user
	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ($1, $2) RETURNING id",
		"Platform", "platform",
	).Scan(&tenantID)
	require.NoError(t, err)

	var userID string
	err = pool.QueryRow(ctx,
		`INSERT INTO users (tenant_id, email, display_name, oidc_subject, oidc_issuer, is_platform_admin)
		 VALUES ($1, $2, $3, $4, $5, true) RETURNING id`,
		tenantID, "admin@valinor.com", "Admin", "google-admin", "https://accounts.google.com",
	).Scan(&userID)
	require.NoError(t, err)

	identity, err := store.GetIdentityWithRoles(ctx, userID)
	require.NoError(t, err)
	assert.True(t, identity.IsPlatformAdmin)
}
