package orchestrator_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/FredAmartey/heimdall/internal/orchestrator"
	"github.com/FredAmartey/heimdall/internal/platform/database"
)

func requireTestDB(t *testing.T) *database.Pool {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://heimdall:valinor@localhost:5432/heimdall?sslmode=disable"
	}
	pool, err := database.Connect(context.Background(), dsn, 2)
	if err != nil {
		t.Skip("database not available, skipping integration test")
	}
	t.Cleanup(func() { pool.Close() })
	return pool
}

func TestKBStore_GrantsForUser(t *testing.T) {
	pool := requireTestDB(t)
	ctx := context.Background()
	kbStore := orchestrator.NewKBStore()

	// Use known test tenant from seed data
	tenantID := "a1b2c3d4-0001-4000-8000-000000000001" // gondolin-fc

	// With no grants configured, should return empty slice
	grants, err := kbStore.GrantsForUser(ctx, pool, tenantID, "00000000-0000-0000-0000-000000000099", "00000000-0000-0000-0000-000000000099")
	require.NoError(t, err)
	require.Empty(t, grants)
}

func TestKBStore_GrantsForUser_Integration(t *testing.T) {
	pool := requireTestDB(t)
	ctx := context.Background()
	kbStore := orchestrator.NewKBStore()

	tenantID := "a1b2c3d4-0001-4000-8000-000000000001" // gondolin-fc

	// Seed a knowledge base and grants for this test.
	// Use a transaction so we can roll back after the test.
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	// Create a test knowledge base
	var kbID string
	err = tx.QueryRow(ctx,
		`INSERT INTO knowledge_bases (tenant_id, name, description, layer)
		 VALUES ($1, 'Test KB', 'test', 'tenant')
		 RETURNING id`,
		tenantID,
	).Scan(&kbID)
	require.NoError(t, err)

	// Grant to a specific user
	testUserID := "a1b2c3d4-0002-4000-8000-000000000001" // glorfindel
	_, err = tx.Exec(ctx,
		`INSERT INTO knowledge_base_grants (knowledge_base_id, grant_type, grant_target_id)
		 VALUES ($1, 'user', $2)`,
		kbID, testUserID,
	)
	require.NoError(t, err)

	// Query grants for the user — should find the KB
	grants, err := kbStore.GrantsForUser(ctx, tx, tenantID, testUserID, "00000000-0000-0000-0000-000000000000")
	require.NoError(t, err)
	require.Len(t, grants, 1)
	require.Equal(t, kbID, grants[0].ID)
	require.Equal(t, "Test KB", grants[0].Name)

	// Query for a different user — should find nothing
	grants, err = kbStore.GrantsForUser(ctx, tx, tenantID, "00000000-0000-0000-0000-000000000099", "00000000-0000-0000-0000-000000000000")
	require.NoError(t, err)
	require.Empty(t, grants)
}
