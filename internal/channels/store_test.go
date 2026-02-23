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
		rowErr := q.QueryRow(ctx,
			`SELECT status, metadata
			 FROM channel_messages
			 WHERE platform = 'whatsapp' AND idempotency_key = 'idem-status-1'`,
		).Scan(&status, &metadata)
		require.NoError(t, rowErr)
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

func TestMessageStore_GetMessageIDByIdempotencyKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := channels.NewStore()

	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Tenant Msg Lookup', 'tenant-msg-lookup') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		firstSeen, insertErr := store.InsertIdempotency(
			ctx,
			q,
			"whatsapp",
			"+15550004444",
			"wamid.lookup.1",
			"idem-lookup-1",
			"fp-lookup-1",
			"corr-lookup-1",
			time.Now().Add(24*time.Hour),
		)
		require.NoError(t, insertErr)
		require.True(t, firstSeen)

		messageID, lookupErr := store.GetMessageIDByIdempotencyKey(ctx, q, "whatsapp", "idem-lookup-1")
		require.NoError(t, lookupErr)
		assert.NotEqual(t, uuid.Nil, messageID)
		return nil
	})
	require.NoError(t, err)
}

func TestMessageStore_GetMessageIDByIdempotencyKey_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := channels.NewStore()

	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Tenant Msg Lookup Missing', 'tenant-msg-lookup-missing') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		_, lookupErr := store.GetMessageIDByIdempotencyKey(ctx, q, "whatsapp", "idem-missing")
		require.ErrorIs(t, lookupErr, channels.ErrMessageNotFound)
		return nil
	})
	require.NoError(t, err)
}

func TestMessageStore_GetMessageByIdempotencyKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := channels.NewStore()

	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Tenant Msg Record', 'tenant-msg-record') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		firstSeen, insertErr := store.InsertIdempotency(
			ctx,
			q,
			"whatsapp",
			"+15550006666",
			"wamid.record.1",
			"idem-record-1",
			"fp-record-1",
			"corr-record-1",
			time.Now().Add(24*time.Hour),
		)
		require.NoError(t, insertErr)
		require.True(t, firstSeen)

		updateErr := store.UpdateMessageStatus(
			ctx,
			q,
			"whatsapp",
			"idem-record-1",
			channels.MessageStatusDispatchFailed,
			json.RawMessage(`{"decision":"dispatch_failed","agent_id":"agent-1","response_content":"queued later","outbox_enqueue_failed":true}`),
		)
		require.NoError(t, updateErr)

		record, lookupErr := store.GetMessageByIdempotencyKey(ctx, q, "whatsapp", "idem-record-1")
		require.NoError(t, lookupErr)
		require.NotNil(t, record)
		assert.NotEqual(t, uuid.Nil, record.ID)
		assert.Equal(t, "whatsapp", record.Platform)
		assert.Equal(t, "+15550006666", record.PlatformUserID)
		assert.Equal(t, "wamid.record.1", record.PlatformMessageID)
		assert.Equal(t, "idem-record-1", record.IdempotencyKey)
		assert.Equal(t, "corr-record-1", record.CorrelationID)
		assert.Equal(t, channels.MessageStatusDispatchFailed, record.Status)
		assert.JSONEq(t, `{"decision":"dispatch_failed","agent_id":"agent-1","response_content":"queued later","outbox_enqueue_failed":true}`, string(record.Metadata))
		return nil
	})
	require.NoError(t, err)
}

func TestMessageStore_GetMessageByIdempotencyKey_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := channels.NewStore()

	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Tenant Msg Record Missing', 'tenant-msg-record-missing') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		_, lookupErr := store.GetMessageByIdempotencyKey(ctx, q, "whatsapp", "idem-missing-record")
		require.ErrorIs(t, lookupErr, channels.ErrMessageNotFound)
		return nil
	})
	require.NoError(t, err)
}

func TestMessageStore_DeleteExpiredMessages(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := channels.NewStore()

	var tenantA, tenantB string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Tenant Retention A', 'tenant-retention-a') RETURNING id",
	).Scan(&tenantA)
	require.NoError(t, err)
	err = pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Tenant Retention B', 'tenant-retention-b') RETURNING id",
	).Scan(&tenantB)
	require.NoError(t, err)

	now := time.Now().UTC()

	err = database.WithTenantConnection(ctx, pool, tenantA, func(ctx context.Context, q database.Querier) error {
		_, execErr := q.Exec(ctx,
			`INSERT INTO channel_messages (
				tenant_id, platform, platform_user_id, platform_message_id, idempotency_key,
				payload_fingerprint, correlation_id, status, expires_at
			) VALUES (
				current_setting('app.current_tenant_id', true)::UUID,
				'whatsapp', '+15551110001', 'msg-retention-expired-a', 'idem-retention-expired-a',
				'fp-retention-expired-a', 'corr-retention-expired-a', 'accepted', $1
			), (
				current_setting('app.current_tenant_id', true)::UUID,
				'whatsapp', '+15551110001', 'msg-retention-active-a', 'idem-retention-active-a',
				'fp-retention-active-a', 'corr-retention-active-a', 'accepted', $2
			)`,
			now.Add(-2*time.Hour),
			now.Add(2*time.Hour),
		)
		return execErr
	})
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantB, func(ctx context.Context, q database.Querier) error {
		_, execErr := q.Exec(ctx,
			`INSERT INTO channel_messages (
				tenant_id, platform, platform_user_id, platform_message_id, idempotency_key,
				payload_fingerprint, correlation_id, status, expires_at
			) VALUES (
				current_setting('app.current_tenant_id', true)::UUID,
				'whatsapp', '+15551110002', 'msg-retention-expired-b', 'idem-retention-expired-b',
				'fp-retention-expired-b', 'corr-retention-expired-b', 'accepted', $1
			)`,
			now.Add(-90*time.Minute),
		)
		return execErr
	})
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantA, func(ctx context.Context, q database.Querier) error {
		deleted, cleanupErr := store.DeleteExpiredMessages(ctx, q, now, 100)
		require.NoError(t, cleanupErr)
		assert.Equal(t, 1, deleted)

		var remaining int
		scanErr := q.QueryRow(ctx,
			`SELECT COUNT(*)
			 FROM channel_messages
			 WHERE idempotency_key IN ('idem-retention-expired-a', 'idem-retention-active-a')`,
		).Scan(&remaining)
		require.NoError(t, scanErr)
		assert.Equal(t, 1, remaining)

		var activePresent int
		scanErr = q.QueryRow(ctx,
			`SELECT COUNT(*)
			 FROM channel_messages
			 WHERE idempotency_key = 'idem-retention-active-a'`,
		).Scan(&activePresent)
		require.NoError(t, scanErr)
		assert.Equal(t, 1, activePresent)
		return nil
	})
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantB, func(ctx context.Context, q database.Querier) error {
		var count int
		scanErr := q.QueryRow(ctx,
			`SELECT COUNT(*)
			 FROM channel_messages
			 WHERE idempotency_key = 'idem-retention-expired-b'`,
		).Scan(&count)
		require.NoError(t, scanErr)
		assert.Equal(t, 1, count)
		return nil
	})
	require.NoError(t, err)
}

func TestMessageStore_DeleteExpiredMessages_RespectsLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := channels.NewStore()

	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Tenant Retention Limit', 'tenant-retention-limit') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	now := time.Now().UTC()
	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		_, execErr := q.Exec(ctx,
			`INSERT INTO channel_messages (
				tenant_id, platform, platform_user_id, platform_message_id, idempotency_key,
				payload_fingerprint, correlation_id, status, expires_at
			) VALUES (
				current_setting('app.current_tenant_id', true)::UUID,
				'telegram', '1001', 'msg-retention-1', 'idem-retention-1',
				'fp-retention-1', 'corr-retention-1', 'accepted', $1
			), (
				current_setting('app.current_tenant_id', true)::UUID,
				'telegram', '1002', 'msg-retention-2', 'idem-retention-2',
				'fp-retention-2', 'corr-retention-2', 'accepted', $2
			), (
				current_setting('app.current_tenant_id', true)::UUID,
				'telegram', '1003', 'msg-retention-3', 'idem-retention-3',
				'fp-retention-3', 'corr-retention-3', 'accepted', $3
			)`,
			now.Add(-3*time.Hour),
			now.Add(-2*time.Hour),
			now.Add(-1*time.Hour),
		)
		return execErr
	})
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		firstDeleted, firstErr := store.DeleteExpiredMessages(ctx, q, now, 2)
		require.NoError(t, firstErr)
		assert.Equal(t, 2, firstDeleted)

		secondDeleted, secondErr := store.DeleteExpiredMessages(ctx, q, now, 2)
		require.NoError(t, secondErr)
		assert.Equal(t, 1, secondDeleted)

		var remaining int
		scanErr := q.QueryRow(ctx, `SELECT COUNT(*) FROM channel_messages`).Scan(&remaining)
		require.NoError(t, scanErr)
		assert.Equal(t, 0, remaining)
		return nil
	})
	require.NoError(t, err)
}

func TestOutboxStore_EnqueueAndClaim(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := channels.NewStore()

	var tenantA, tenantB string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Outbox Tenant A', 'outbox-tenant-a') RETURNING id",
	).Scan(&tenantA)
	require.NoError(t, err)
	err = pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Outbox Tenant B', 'outbox-tenant-b') RETURNING id",
	).Scan(&tenantB)
	require.NoError(t, err)

	var messageAID uuid.UUID
	err = database.WithTenantConnection(ctx, pool, tenantA, func(ctx context.Context, q database.Querier) error {
		return q.QueryRow(ctx,
			`INSERT INTO channel_messages (
				tenant_id, platform, platform_user_id, platform_message_id, idempotency_key,
				payload_fingerprint, correlation_id, status, expires_at
			) VALUES (
				current_setting('app.current_tenant_id', true)::UUID,
				'whatsapp', '+15550001111', 'msg-outbox-a', 'idem-outbox-a',
				'fp-outbox-a', 'corr-outbox-a', 'executed', now() + interval '1 day'
			) RETURNING id`,
		).Scan(&messageAID)
	})
	require.NoError(t, err)

	var enqueuedA *channels.ChannelOutbox
	err = database.WithTenantConnection(ctx, pool, tenantA, func(ctx context.Context, q database.Querier) error {
		job, enqueueErr := store.EnqueueOutbound(ctx, q, channels.EnqueueOutboundParams{
			ChannelMessageID: messageAID.String(),
			Provider:         "whatsapp",
			RecipientID:      "+15550001111",
			Payload:          json.RawMessage(`{"text":"hello tenant a"}`),
		})
		require.NoError(t, enqueueErr)
		enqueuedA = job
		assert.Equal(t, channels.OutboxStatusPending, job.Status)
		assert.Equal(t, 0, job.AttemptCount)
		assert.Equal(t, tenantA, job.TenantID.String())
		return nil
	})
	require.NoError(t, err)
	require.NotNil(t, enqueuedA)

	var messageBID uuid.UUID
	err = database.WithTenantConnection(ctx, pool, tenantB, func(ctx context.Context, q database.Querier) error {
		if scanErr := q.QueryRow(ctx,
			`INSERT INTO channel_messages (
				tenant_id, platform, platform_user_id, platform_message_id, idempotency_key,
				payload_fingerprint, correlation_id, status, expires_at
			) VALUES (
				current_setting('app.current_tenant_id', true)::UUID,
				'whatsapp', '+15550002222', 'msg-outbox-b', 'idem-outbox-b',
				'fp-outbox-b', 'corr-outbox-b', 'executed', now() + interval '1 day'
			) RETURNING id`,
		).Scan(&messageBID); scanErr != nil {
			return scanErr
		}

		_, enqueueErr := store.EnqueueOutbound(ctx, q, channels.EnqueueOutboundParams{
			ChannelMessageID: messageBID.String(),
			Provider:         "whatsapp",
			RecipientID:      "+15550002222",
			Payload:          json.RawMessage(`{"text":"hello tenant b"}`),
		})
		return enqueueErr
	})
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantA, func(ctx context.Context, q database.Querier) error {
		claimed, claimErr := store.ClaimPendingOutbox(ctx, q, time.Now().UTC(), 10)
		require.NoError(t, claimErr)
		require.Len(t, claimed, 1)
		assert.Equal(t, enqueuedA.ID, claimed[0].ID)
		assert.Equal(t, channels.OutboxStatusSending, claimed[0].Status)
		assert.Equal(t, 0, claimed[0].AttemptCount)
		assert.Equal(t, tenantA, claimed[0].TenantID.String())

		again, againErr := store.ClaimPendingOutbox(ctx, q, time.Now().UTC(), 10)
		require.NoError(t, againErr)
		assert.Empty(t, again)
		return nil
	})
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantB, func(ctx context.Context, q database.Querier) error {
		claimed, claimErr := store.ClaimPendingOutbox(ctx, q, time.Now().UTC(), 10)
		require.NoError(t, claimErr)
		require.Len(t, claimed, 1)
		assert.Equal(t, channels.OutboxStatusSending, claimed[0].Status)
		assert.Equal(t, tenantB, claimed[0].TenantID.String())
		assert.Equal(t, messageBID, claimed[0].ChannelMessageID)
		return nil
	})
	require.NoError(t, err)
}

func TestOutboxStore_MarkSent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := channels.NewStore()
	tenantID, outboxID := seedAndClaimOutboxJob(t, ctx, pool, store, "outbox-mark-sent")

	err := database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		return store.MarkOutboxSent(ctx, q, outboxID)
	})
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		var status string
		var sentAt *time.Time
		var attemptCount int
		var lastError *string
		rowErr := q.QueryRow(ctx,
			`SELECT status, sent_at, attempt_count, last_error
			 FROM channel_outbox
			 WHERE id = $1`,
			outboxID,
		).Scan(&status, &sentAt, &attemptCount, &lastError)
		require.NoError(t, rowErr)
		assert.Equal(t, string(channels.OutboxStatusSent), status)
		require.NotNil(t, sentAt)
		assert.Equal(t, 0, attemptCount)
		assert.Nil(t, lastError)
		return nil
	})
	require.NoError(t, err)
}

func TestOutboxStore_MarkRetry(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := channels.NewStore()
	tenantID, outboxID := seedAndClaimOutboxJob(t, ctx, pool, store, "outbox-mark-retry")
	nextAttempt := time.Now().UTC().Add(2 * time.Minute).Truncate(time.Second)

	err := database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		return store.MarkOutboxRetry(ctx, q, outboxID, nextAttempt, "provider timeout")
	})
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		var status string
		var attemptCount int
		var dbNextAttempt time.Time
		var lastError *string
		var sentAt *time.Time
		rowErr := q.QueryRow(ctx,
			`SELECT status, attempt_count, next_attempt_at, last_error, sent_at
			 FROM channel_outbox
			 WHERE id = $1`,
			outboxID,
		).Scan(&status, &attemptCount, &dbNextAttempt, &lastError, &sentAt)
		require.NoError(t, rowErr)
		assert.Equal(t, string(channels.OutboxStatusPending), status)
		assert.Equal(t, 1, attemptCount)
		assert.WithinDuration(t, nextAttempt, dbNextAttempt, 2*time.Second)
		require.NotNil(t, lastError)
		assert.Equal(t, "provider timeout", *lastError)
		assert.Nil(t, sentAt)
		return nil
	})
	require.NoError(t, err)
}

func TestOutboxStore_MarkDead(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := channels.NewStore()
	tenantID, outboxID := seedAndClaimOutboxJob(t, ctx, pool, store, "outbox-mark-dead")

	err := database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		return store.MarkOutboxDead(ctx, q, outboxID, "permanent provider failure")
	})
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		var status string
		var attemptCount int
		var lastError *string
		var sentAt *time.Time
		rowErr := q.QueryRow(ctx,
			`SELECT status, attempt_count, last_error, sent_at
			 FROM channel_outbox
			 WHERE id = $1`,
			outboxID,
		).Scan(&status, &attemptCount, &lastError, &sentAt)
		require.NoError(t, rowErr)
		assert.Equal(t, string(channels.OutboxStatusDead), status)
		assert.Equal(t, 1, attemptCount)
		require.NotNil(t, lastError)
		assert.Equal(t, "permanent provider failure", *lastError)
		assert.Nil(t, sentAt)
		return nil
	})
	require.NoError(t, err)
}

func TestOutboxStore_RecoverStaleSending(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := channels.NewStore()
	tenantID, staleID := seedAndClaimOutboxJob(t, ctx, pool, store, "outbox-stale")
	_, freshID := seedAndClaimOutboxJob(t, ctx, pool, store, "outbox-stale")

	staleLockedAt := time.Now().UTC().Add(-10 * time.Minute)
	freshLockedAt := time.Now().UTC()
	err := database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		_, execErr := q.Exec(ctx, `UPDATE channel_outbox SET locked_at = $2 WHERE id = $1`, staleID, staleLockedAt)
		if execErr != nil {
			return execErr
		}
		_, execErr = q.Exec(ctx, `UPDATE channel_outbox SET locked_at = $2 WHERE id = $1`, freshID, freshLockedAt)
		return execErr
	})
	require.NoError(t, err)

	var recovered []channels.ChannelOutbox
	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		var recoverErr error
		recovered, recoverErr = store.RecoverStaleSending(ctx, q, time.Now().UTC().Add(-5*time.Minute), 10)
		return recoverErr
	})
	require.NoError(t, err)
	require.Len(t, recovered, 1)
	assert.Equal(t, staleID, recovered[0].ID)
	assert.Equal(t, channels.OutboxStatusPending, recovered[0].Status)
	assert.Nil(t, recovered[0].LockedAt)

	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		var staleStatus, freshStatus string
		var staleLocked, freshLocked *time.Time
		if scanErr := q.QueryRow(ctx,
			`SELECT status, locked_at FROM channel_outbox WHERE id = $1`,
			staleID,
		).Scan(&staleStatus, &staleLocked); scanErr != nil {
			return scanErr
		}
		if scanErr := q.QueryRow(ctx,
			`SELECT status, locked_at FROM channel_outbox WHERE id = $1`,
			freshID,
		).Scan(&freshStatus, &freshLocked); scanErr != nil {
			return scanErr
		}
		assert.Equal(t, string(channels.OutboxStatusPending), staleStatus)
		assert.Nil(t, staleLocked)
		assert.Equal(t, string(channels.OutboxStatusSending), freshStatus)
		require.NotNil(t, freshLocked)
		return nil
	})
	require.NoError(t, err)
}

func seedAndClaimOutboxJob(
	t *testing.T,
	ctx context.Context,
	pool *database.Pool,
	store *channels.Store,
	slugPrefix string,
) (string, uuid.UUID) {
	t.Helper()

	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ($1, $2) RETURNING id",
		"Tenant "+slugPrefix,
		slugPrefix+"-"+uuid.NewString()[:8],
	).Scan(&tenantID)
	require.NoError(t, err)

	var messageID uuid.UUID
	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		return q.QueryRow(ctx,
			`INSERT INTO channel_messages (
				tenant_id, platform, platform_user_id, platform_message_id, idempotency_key,
				payload_fingerprint, correlation_id, status, expires_at
			) VALUES (
				current_setting('app.current_tenant_id', true)::UUID,
				'whatsapp', '+15550003333', $1, $2,
				$3, $4, 'executed', now() + interval '1 day'
			) RETURNING id`,
			"msg-"+uuid.NewString(),
			"idem-"+uuid.NewString(),
			"fp-"+uuid.NewString(),
			"corr-"+uuid.NewString(),
		).Scan(&messageID)
	})
	require.NoError(t, err)

	var outboxID uuid.UUID
	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		job, enqueueErr := store.EnqueueOutbound(ctx, q, channels.EnqueueOutboundParams{
			ChannelMessageID: messageID.String(),
			Provider:         "whatsapp",
			RecipientID:      "+15550003333",
			Payload:          json.RawMessage(`{"text":"retry me"}`),
		})
		if enqueueErr != nil {
			return enqueueErr
		}
		outboxID = job.ID

		claimed, claimErr := store.ClaimPendingOutbox(ctx, q, time.Now().UTC(), 1)
		if claimErr != nil {
			return claimErr
		}
		require.Len(t, claimed, 1)
		assert.Equal(t, channels.OutboxStatusSending, claimed[0].Status)
		assert.Equal(t, outboxID, claimed[0].ID)
		return nil
	})
	require.NoError(t, err)

	return tenantID, outboxID
}
