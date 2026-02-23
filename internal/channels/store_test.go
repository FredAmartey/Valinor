package channels_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
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

func TestChannelLinkStore_UpsertLink_CreatesAndUpdatesState(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := channels.NewStore()

	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Tenant Link', 'tenant-link') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	var userID string
	err = pool.QueryRow(ctx,
		"INSERT INTO users (tenant_id, email, display_name) VALUES ($1, 'link@tenant.com', 'Link User') RETURNING id",
		tenantID,
	).Scan(&userID)
	require.NoError(t, err)

	platformIdentity := "+15556667777"
	var createdID uuid.UUID
	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		link, upsertErr := store.UpsertLink(ctx, q, channels.UpsertLinkParams{
			UserID:         userID,
			Platform:       "whatsapp",
			PlatformUserID: platformIdentity,
			State:          channels.LinkStatePendingVerification,
		})
		require.NoError(t, upsertErr)
		require.NotNil(t, link)
		createdID = link.ID
		assert.Equal(t, channels.LinkStatePendingVerification, link.State)
		assert.False(t, link.Verified)
		assert.Nil(t, link.VerifiedAt)
		assert.Nil(t, link.RevokedAt)
		return nil
	})
	require.NoError(t, err)

	meta := json.RawMessage(`{"source":"manual"}`)
	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		link, upsertErr := store.UpsertLink(ctx, q, channels.UpsertLinkParams{
			UserID:               userID,
			Platform:             "whatsapp",
			PlatformUserID:       platformIdentity,
			State:                channels.LinkStateVerified,
			VerificationMethod:   "admin_override",
			VerificationMetadata: meta,
		})
		require.NoError(t, upsertErr)
		require.NotNil(t, link)
		assert.Equal(t, createdID, link.ID)
		assert.Equal(t, channels.LinkStateVerified, link.State)
		assert.True(t, link.Verified)
		require.NotNil(t, link.VerifiedAt)
		assert.Equal(t, "admin_override", link.VerificationMethod)
		assert.JSONEq(t, string(meta), string(link.VerificationMetadata))
		return nil
	})
	require.NoError(t, err)
}

func TestChannelLinkStore_UpsertLink_RejectsCrossTenantUser(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := channels.NewStore()

	var tenantA, tenantB string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Tenant X', 'tenant-x') RETURNING id",
	).Scan(&tenantA)
	require.NoError(t, err)
	err = pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Tenant Y', 'tenant-y') RETURNING id",
	).Scan(&tenantB)
	require.NoError(t, err)

	var userBID string
	err = pool.QueryRow(ctx,
		"INSERT INTO users (tenant_id, email, display_name) VALUES ($1, 'userb@tenant.com', 'User B') RETURNING id",
		tenantB,
	).Scan(&userBID)
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantA, func(ctx context.Context, q database.Querier) error {
		_, upsertErr := store.UpsertLink(ctx, q, channels.UpsertLinkParams{
			UserID:         userBID,
			Platform:       "telegram",
			PlatformUserID: "tg-cross-tenant",
			State:          channels.LinkStateVerified,
		})
		require.ErrorIs(t, upsertErr, channels.ErrUserNotFound)
		return nil
	})
	require.NoError(t, err)
}

func TestChannelLinkStore_ListAndDeleteLink(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := channels.NewStore()

	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Tenant Z', 'tenant-z') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	var userID string
	err = pool.QueryRow(ctx,
		"INSERT INTO users (tenant_id, email, display_name) VALUES ($1, 'userz@tenant.com', 'User Z') RETURNING id",
		tenantID,
	).Scan(&userID)
	require.NoError(t, err)

	var linkID string
	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		link, upsertErr := store.UpsertLink(ctx, q, channels.UpsertLinkParams{
			UserID:         userID,
			Platform:       "slack",
			PlatformUserID: "U-DELETE-ME",
			State:          channels.LinkStateVerified,
		})
		require.NoError(t, upsertErr)
		linkID = link.ID.String()

		list, listErr := store.ListLinks(ctx, q)
		require.NoError(t, listErr)
		require.Len(t, list, 1)
		assert.Equal(t, linkID, list[0].ID.String())
		return nil
	})
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		deleteErr := store.DeleteLink(ctx, q, linkID)
		require.NoError(t, deleteErr)

		list, listErr := store.ListLinks(ctx, q)
		require.NoError(t, listErr)
		assert.Empty(t, list)

		deleteErr = store.DeleteLink(ctx, q, linkID)
		require.ErrorIs(t, deleteErr, channels.ErrLinkNotFound)
		return nil
	})
	require.NoError(t, err)
}

func TestMessageStore_UpdateMessageStatus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := channels.NewStore()

	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Tenant Status', 'tenant-status') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		expiresAt := time.Now().Add(24 * time.Hour)
		firstSeen, insertErr := store.InsertIdempotency(
			ctx,
			q,
			"whatsapp",
			"+15550003333",
			"wamid.status.1",
			"idem-status-1",
			"fp-status-1",
			"corr-status-1",
			expiresAt,
		)
		require.NoError(t, insertErr)
		require.True(t, firstSeen)

		updateErr := store.UpdateMessageStatus(
			ctx,
			q,
			"whatsapp",
			"idem-status-1",
			channels.MessageStatusExecuted,
			json.RawMessage(`{"decision":"executed","agent_id":"agent-1"}`),
		)
		require.NoError(t, updateErr)

		var status string
		var metadata json.RawMessage
		err := q.QueryRow(ctx,
			`SELECT status, metadata
			 FROM channel_messages
			 WHERE platform = 'whatsapp' AND idempotency_key = 'idem-status-1'`,
		).Scan(&status, &metadata)
		require.NoError(t, err)
		assert.Equal(t, channels.MessageStatusExecuted, status)
		assert.JSONEq(t, `{"decision":"executed","agent_id":"agent-1"}`, string(metadata))

		return nil
	})
	require.NoError(t, err)
}

func TestMessageStore_UpdateMessageStatus_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := channels.NewStore()

	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Tenant Status Missing', 'tenant-status-missing') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		updateErr := store.UpdateMessageStatus(
			ctx,
			q,
			"whatsapp",
			"missing-idempotency-key",
			channels.MessageStatusExecuted,
			json.RawMessage(`{"decision":"executed"}`),
		)
		require.ErrorIs(t, updateErr, channels.ErrMessageNotFound)
		return nil
	})
	require.NoError(t, err)
}
