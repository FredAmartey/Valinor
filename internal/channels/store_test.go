package channels_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/valinor-ai/valinor/internal/channels"
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

func TestChannelLinkStore_GetByIdentity_TenantScoped(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := channels.NewStore()

	var tenantA, tenantB string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Tenant A', 'tenant-a') RETURNING id",
	).Scan(&tenantA)
	require.NoError(t, err)
	err = pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Tenant B', 'tenant-b') RETURNING id",
	).Scan(&tenantB)
	require.NoError(t, err)

	var userAID, userBID string
	err = pool.QueryRow(ctx,
		"INSERT INTO users (tenant_id, email, display_name) VALUES ($1, 'a@tenant.com', 'User A') RETURNING id",
		tenantA,
	).Scan(&userAID)
	require.NoError(t, err)
	err = pool.QueryRow(ctx,
		"INSERT INTO users (tenant_id, email, display_name) VALUES ($1, 'b@tenant.com', 'User B') RETURNING id",
		tenantB,
	).Scan(&userBID)
	require.NoError(t, err)

	_, err = pool.Exec(ctx,
		`INSERT INTO channel_links (tenant_id, user_id, platform, platform_user_id, state, verified)
		 VALUES ($1, $2, 'whatsapp', '+15551230000', 'verified', true)`,
		tenantA, userAID,
	)
	require.NoError(t, err)
	_, err = pool.Exec(ctx,
		`INSERT INTO channel_links (tenant_id, user_id, platform, platform_user_id, state, verified)
		 VALUES ($1, $2, 'whatsapp', '+15551230000', 'verified', true)`,
		tenantB, userBID,
	)
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantA, func(ctx context.Context, q database.Querier) error {
		link, getErr := store.GetLinkByIdentity(ctx, q, "whatsapp", "+15551230000")
		require.NoError(t, getErr)
		assert.Equal(t, tenantA, link.TenantID.String())
		assert.Equal(t, userAID, link.UserID.String())
		return nil
	})
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantB, func(ctx context.Context, q database.Querier) error {
		link, getErr := store.GetLinkByIdentity(ctx, q, "whatsapp", "+15551230000")
		require.NoError(t, getErr)
		assert.Equal(t, tenantB, link.TenantID.String())
		assert.Equal(t, userBID, link.UserID.String())
		return nil
	})
	require.NoError(t, err)
}

func TestChannelLinkStore_VerifiedGate(t *testing.T) {
	verified := channels.ChannelLink{State: channels.LinkStateVerified}
	pending := channels.ChannelLink{State: channels.LinkStatePendingVerification}
	revoked := channels.ChannelLink{State: channels.LinkStateRevoked}

	assert.True(t, verified.IsVerified())
	assert.False(t, pending.IsVerified())
	assert.False(t, revoked.IsVerified())
}

func TestMessageStore_InsertIdempotency_FirstSeen(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := channels.NewStore()

	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Tenant A', 'tenant-a-msg') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		firstSeen, insertErr := store.InsertIdempotency(ctx, q,
			"whatsapp",
			"+15550001111",
			"wamid.abc123",
			"idem-abc123",
			"fingerprint-abc123",
			"corr-abc123",
			time.Now().Add(24*time.Hour),
		)
		require.NoError(t, insertErr)
		assert.True(t, firstSeen)
		return nil
	})
	require.NoError(t, err)
}

func TestMessageStore_InsertIdempotency_Duplicate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := channels.NewStore()

	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Tenant B', 'tenant-b-msg') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		expiresAt := time.Now().Add(24 * time.Hour)

		firstSeen, insertErr := store.InsertIdempotency(ctx, q,
			"whatsapp",
			"+15550002222",
			"wamid.xyz789",
			"idem-xyz789",
			"fingerprint-xyz789",
			"corr-xyz789",
			expiresAt,
		)
		require.NoError(t, insertErr)
		assert.True(t, firstSeen)

		firstSeen, insertErr = store.InsertIdempotency(ctx, q,
			"whatsapp",
			"+15550002222",
			"wamid.xyz789",
			"idem-xyz789",
			"fingerprint-xyz789",
			"corr-xyz789",
			expiresAt,
		)
		require.NoError(t, insertErr)
		assert.False(t, firstSeen)

		var count int
		err = q.QueryRow(ctx,
			`SELECT COUNT(*) FROM channel_messages
			 WHERE platform = 'whatsapp' AND idempotency_key = 'idem-xyz789'`,
		).Scan(&count)
		require.NoError(t, err)
		assert.Equal(t, 1, count)

		return nil
	})
	require.NoError(t, err)
}
