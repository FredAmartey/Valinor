package main

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

func setupWorkerTestDB(t *testing.T) (*database.Pool, func()) {
	t.Helper()
	ctx := context.Background()

	container, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("valinor_test"),
		postgres.WithUsername("valinor"),
		postgres.WithPassword("valinor"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").WithOccurrence(2),
		),
	)
	require.NoError(t, err)

	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	require.NoError(t, database.RunMigrations(dsn, "file://../../migrations"))

	pool, err := database.Connect(ctx, dsn, 5)
	require.NoError(t, err)

	cleanup := func() {
		pool.Close()
		_ = container.Terminate(context.Background())
	}
	return pool, cleanup
}

func TestListTenantIDs_Paginates(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupWorkerTestDB(t)
	defer cleanup()

	ctx := context.Background()
	const tenantCount = 7
	for i := 0; i < tenantCount; i++ {
		slug := fmt.Sprintf("scan-tenant-%d-%d", i, time.Now().UnixNano())
		_, err := pool.Exec(ctx,
			`INSERT INTO tenants (name, slug) VALUES ($1, $2)`,
			fmt.Sprintf("Scan Tenant %d", i),
			slug,
		)
		require.NoError(t, err)
	}

	got, err := listTenantIDs(ctx, pool, 2)
	require.NoError(t, err)
	require.Len(t, got, tenantCount)

	expected := append([]string(nil), got...)
	sort.Strings(expected)
	assert.Equal(t, expected, got)
}
