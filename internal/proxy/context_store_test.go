package proxy_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/valinor-ai/valinor/internal/platform/database"
	"github.com/valinor-ai/valinor/internal/proxy"
)

func setupContextStoreTestDB(t *testing.T) (*database.Pool, func()) {
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

func TestDBUserContextStore_UpsertAndGet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupContextStoreTestDB(t)
	defer cleanup()

	ctx := context.Background()
	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Context Tenant', 'context-tenant') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	var agentID string
	err = pool.QueryRow(ctx,
		"INSERT INTO agent_instances (tenant_id, status) VALUES ($1, 'running') RETURNING id",
		tenantID,
	).Scan(&agentID)
	require.NoError(t, err)

	store := proxy.NewDBUserContextStore(pool)

	err = store.UpsertUserContext(ctx, tenantID, agentID, "user-1", "first snapshot")
	require.NoError(t, err)

	contextText, err := store.GetUserContext(ctx, tenantID, agentID, "user-1")
	require.NoError(t, err)
	assert.Equal(t, "first snapshot", contextText)

	err = store.UpsertUserContext(ctx, tenantID, agentID, "user-1", "second snapshot")
	require.NoError(t, err)

	contextText, err = store.GetUserContext(ctx, tenantID, agentID, "user-1")
	require.NoError(t, err)
	assert.Equal(t, "second snapshot", contextText)
}

func TestDBUserContextStore_GetNotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupContextStoreTestDB(t)
	defer cleanup()

	ctx := context.Background()
	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Missing Tenant', 'missing-tenant') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	var agentID string
	err = pool.QueryRow(ctx,
		"INSERT INTO agent_instances (tenant_id, status) VALUES ($1, 'running') RETURNING id",
		tenantID,
	).Scan(&agentID)
	require.NoError(t, err)

	store := proxy.NewDBUserContextStore(pool)
	_, err = store.GetUserContext(ctx, tenantID, agentID, "missing-user")
	require.Error(t, err)
	assert.True(t, errors.Is(err, proxy.ErrUserContextNotFound))
}
