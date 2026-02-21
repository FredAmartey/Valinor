package database_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

func TestRunMigrations(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	connStr, cleanup := setupPostgres(t)
	defer cleanup()

	err := database.RunMigrations(connStr, "file:///Users/fred/Documents/Valinor/.worktrees/phase1-foundation/migrations")
	require.NoError(t, err)

	// Verify tables exist by connecting and querying
	pool, err := database.Connect(context.Background(), connStr, 5)
	require.NoError(t, err)
	defer pool.Close()

	// Check that tenants table exists
	var tableName string
	err = pool.QueryRow(context.Background(),
		"SELECT table_name FROM information_schema.tables WHERE table_name = 'tenants'").
		Scan(&tableName)
	require.NoError(t, err)
	assert.Equal(t, "tenants", tableName)

	// Check that RLS is enabled on users table
	var rlsEnabled bool
	err = pool.QueryRow(context.Background(),
		"SELECT relrowsecurity FROM pg_class WHERE relname = 'users'").
		Scan(&rlsEnabled)
	require.NoError(t, err)
	assert.True(t, rlsEnabled)
}
