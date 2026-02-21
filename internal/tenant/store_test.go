package tenant_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/valinor-ai/valinor/internal/platform/database"
	"github.com/valinor-ai/valinor/internal/tenant"
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

func TestStore_Create(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	store := tenant.NewStore(pool)
	ctx := context.Background()

	created, err := store.Create(ctx, "Chelsea FC", "chelsea-fc")
	require.NoError(t, err)
	assert.NotEmpty(t, created.ID)
	assert.Equal(t, "Chelsea FC", created.Name)
	assert.Equal(t, "chelsea-fc", created.Slug)
	assert.Equal(t, "active", created.Status)
}

func TestStore_Create_DuplicateSlug(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	store := tenant.NewStore(pool)
	ctx := context.Background()

	_, err := store.Create(ctx, "Chelsea FC", "chelsea-fc")
	require.NoError(t, err)

	_, err = store.Create(ctx, "Chelsea FC 2", "chelsea-fc")
	assert.ErrorIs(t, err, tenant.ErrSlugTaken)
}

func TestStore_GetByID(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	store := tenant.NewStore(pool)
	ctx := context.Background()

	created, err := store.Create(ctx, "Chelsea FC", "chelsea-fc")
	require.NoError(t, err)

	got, err := store.GetByID(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, created.ID, got.ID)
	assert.Equal(t, "Chelsea FC", got.Name)
	assert.Equal(t, "chelsea-fc", got.Slug)
}

func TestStore_GetByID_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	store := tenant.NewStore(pool)
	ctx := context.Background()

	_, err := store.GetByID(ctx, "00000000-0000-0000-0000-000000000000")
	assert.ErrorIs(t, err, tenant.ErrTenantNotFound)
}

func TestStore_List(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	store := tenant.NewStore(pool)
	ctx := context.Background()

	_, err := store.Create(ctx, "Tenant A", "tenant-a")
	require.NoError(t, err)
	_, err = store.Create(ctx, "Tenant B", "tenant-b")
	require.NoError(t, err)

	tenants, err := store.List(ctx)
	require.NoError(t, err)
	assert.Len(t, tenants, 2)
}

func TestValidateSlug(t *testing.T) {
	tests := []struct {
		slug    string
		wantErr bool
	}{
		{"chelsea-fc", false},
		{"abc", false},
		{"a-b", false},
		{"ab", true},    // too short
		{"-abc", true},  // starts with hyphen
		{"abc-", true},  // ends with hyphen
		{"ABC", true},   // uppercase
		{"a b", true},   // space
		{"api", true},   // reserved
		{"www", true},   // reserved
		{"admin", true}, // reserved
	}

	for _, tt := range tests {
		t.Run(tt.slug, func(t *testing.T) {
			err := tenant.ValidateSlug(tt.slug)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
