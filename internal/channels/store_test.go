package channels_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
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

const testCredentialCryptoKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="

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

func newCredentialStore(t *testing.T) *channels.Store {
	t.Helper()

	crypto, err := channels.NewCredentialCrypto(testCredentialCryptoKey)
	require.NoError(t, err)
	return channels.NewStore(channels.WithCredentialCrypto(crypto))
}

func TestChannelLinkStore_GetByIdentity_TenantScoped(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := newCredentialStore(t)

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
	store := newCredentialStore(t)

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
	store := newCredentialStore(t)

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
	store := newCredentialStore(t)

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

func TestMessageStore_RecoverDispatchFailuresToOutbox(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := channels.NewStore()

	var tenantA, tenantB string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Tenant Msg Recover A', 'tenant-msg-recover-a') RETURNING id",
	).Scan(&tenantA)
	require.NoError(t, err)
	err = pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Tenant Msg Recover B', 'tenant-msg-recover-b') RETURNING id",
	).Scan(&tenantB)
	require.NoError(t, err)

	var recoverableMessageID uuid.UUID
	var deniedRecoverableMessageID uuid.UUID
	err = database.WithTenantConnection(ctx, pool, tenantA, func(ctx context.Context, q database.Querier) error {
		metadataRecoverable := `{"decision":"dispatch_failed","agent_id":"agent-1","outbox_enqueue_failed":true,"outbox_recipient_id":"+15550007777","outbox_thread_ts":"1710000.12345","response_content":"queued later"}`
		if scanErr := q.QueryRow(ctx,
			`INSERT INTO channel_messages (
				tenant_id, platform, platform_user_id, platform_message_id, idempotency_key,
				payload_fingerprint, correlation_id, status, metadata, expires_at
			) VALUES (
				current_setting('app.current_tenant_id', true)::UUID,
				'whatsapp', '+15550007777', 'msg-recoverable', 'idem-recoverable',
				'fp-recoverable', 'corr-recoverable', 'dispatch_failed', $1::jsonb, now() + interval '1 day'
			) RETURNING id`,
			metadataRecoverable,
		).Scan(&recoverableMessageID); scanErr != nil {
			return scanErr
		}
		metadataDeniedRBAC := `{"decision":"denied_rbac","outbox_enqueue_failed":true,"outbox_recipient_id":"+15550009999","response_content":"not authorized"}`
		if scanErr := q.QueryRow(ctx,
			`INSERT INTO channel_messages (
					tenant_id, platform, platform_user_id, platform_message_id, idempotency_key,
					payload_fingerprint, correlation_id, status, metadata, expires_at
				) VALUES (
					current_setting('app.current_tenant_id', true)::UUID,
					'whatsapp', '+15550009999', 'msg-denied-rbac', 'idem-denied-rbac',
					'fp-denied-rbac', 'corr-denied-rbac', 'denied_rbac', $1::jsonb, now() + interval '1 day'
				) RETURNING id`,
			metadataDeniedRBAC,
		).Scan(&deniedRecoverableMessageID); scanErr != nil {
			return scanErr
		}

		metadataSlackMissingRecipient := `{"decision":"dispatch_failed","agent_id":"agent-2","outbox_enqueue_failed":true,"response_content":"missing channel id"}`
		if _, execErr := q.Exec(ctx,
			`INSERT INTO channel_messages (
				tenant_id, platform, platform_user_id, platform_message_id, idempotency_key,
				payload_fingerprint, correlation_id, status, metadata, expires_at
			) VALUES (
				current_setting('app.current_tenant_id', true)::UUID,
				'slack', 'U123', 'slack-msg-missing-recipient', 'idem-slack-missing-recipient',
				'fp-slack-missing-recipient', 'corr-slack-missing-recipient', 'dispatch_failed', $1::jsonb, now() + interval '1 day'
			)`,
			metadataSlackMissingRecipient,
		); execErr != nil {
			return execErr
		}

		metadataNoEnqueueFailure := `{"decision":"dispatch_failed","agent_id":"agent-3","outbox_enqueue_failed":false,"response_content":"should stay failed"}`
		_, execErr := q.Exec(ctx,
			`INSERT INTO channel_messages (
				tenant_id, platform, platform_user_id, platform_message_id, idempotency_key,
				payload_fingerprint, correlation_id, status, metadata, expires_at
			) VALUES (
				current_setting('app.current_tenant_id', true)::UUID,
				'whatsapp', '+15550008888', 'msg-no-enqueue-failure', 'idem-no-enqueue-failure',
				'fp-no-enqueue-failure', 'corr-no-enqueue-failure', 'dispatch_failed', $1::jsonb, now() + interval '1 day'
			)`,
			metadataNoEnqueueFailure,
		)
		return execErr
	})
	require.NoError(t, err)

	var tenantBMessageID uuid.UUID
	err = database.WithTenantConnection(ctx, pool, tenantB, func(ctx context.Context, q database.Querier) error {
		return q.QueryRow(ctx,
			`INSERT INTO channel_messages (
				tenant_id, platform, platform_user_id, platform_message_id, idempotency_key,
				payload_fingerprint, correlation_id, status, metadata, expires_at
			) VALUES (
				current_setting('app.current_tenant_id', true)::UUID,
				'whatsapp', '+15559990000', 'msg-other-tenant', 'idem-other-tenant',
				'fp-other-tenant', 'corr-other-tenant', 'dispatch_failed',
				'{"decision":"dispatch_failed","outbox_enqueue_failed":true,"outbox_recipient_id":"+15559990000","response_content":"other tenant"}'::jsonb,
				now() + interval '1 day'
			) RETURNING id`,
		).Scan(&tenantBMessageID)
	})
	require.NoError(t, err)

	var recovered int
	err = database.WithTenantConnection(ctx, pool, tenantA, func(ctx context.Context, q database.Querier) error {
		var recoverErr error
		recovered, recoverErr = store.RecoverDispatchFailuresToOutbox(ctx, q, 25, 9)
		return recoverErr
	})
	require.NoError(t, err)
	assert.Equal(t, 2, recovered)

	err = database.WithTenantConnection(ctx, pool, tenantA, func(ctx context.Context, q database.Querier) error {
		var status string
		var metadata []byte
		if scanErr := q.QueryRow(ctx,
			`SELECT status, metadata
			 FROM channel_messages
			 WHERE id = $1`,
			recoverableMessageID,
		).Scan(&status, &metadata); scanErr != nil {
			return scanErr
		}
		assert.Equal(t, channels.MessageStatusExecuted, status)
		assert.JSONEq(t, `{
				"decision":"executed",
				"agent_id":"agent-1",
			"outbox_enqueue_failed":false,
			"outbox_recipient_id":"+15550007777",
			"outbox_thread_ts":"1710000.12345",
			"outbox_recovered":true,
				"response_content":"queued later"
			}`, string(metadata))

		var deniedStatus string
		var deniedMetadata []byte
		if scanErr := q.QueryRow(ctx,
			`SELECT status, metadata
				 FROM channel_messages
				 WHERE id = $1`,
			deniedRecoverableMessageID,
		).Scan(&deniedStatus, &deniedMetadata); scanErr != nil {
			return scanErr
		}
		assert.Equal(t, channels.MessageStatusDeniedRBAC, deniedStatus)
		assert.JSONEq(t, `{
				"decision":"denied_rbac",
				"outbox_enqueue_failed":false,
				"outbox_recipient_id":"+15550009999",
				"outbox_recovered":true,
				"response_content":"not authorized"
			}`, string(deniedMetadata))

		var provider, recipientID, payload, outboxStatus string
		var maxAttempts int
		if scanErr := q.QueryRow(ctx,
			`SELECT provider, recipient_id, payload::text, status, max_attempts
			 FROM channel_outbox
			 WHERE channel_message_id = $1`,
			recoverableMessageID,
		).Scan(&provider, &recipientID, &payload, &outboxStatus, &maxAttempts); scanErr != nil {
			return scanErr
		}
		assert.Equal(t, "whatsapp", provider)
		assert.Equal(t, "+15550007777", recipientID)
		assert.Equal(t, string(channels.OutboxStatusPending), outboxStatus)
		assert.Equal(t, 9, maxAttempts)
		assert.JSONEq(t, `{
				"content":"queued later",
				"correlation_id":"corr-recoverable",
				"thread_ts":"1710000.12345"
			}`, payload)

		var deniedOutboxProvider, deniedOutboxRecipient, deniedOutboxPayload, deniedOutboxStatus string
		if scanErr := q.QueryRow(ctx,
			`SELECT provider, recipient_id, payload::text, status
				 FROM channel_outbox
				 WHERE channel_message_id = $1`,
			deniedRecoverableMessageID,
		).Scan(&deniedOutboxProvider, &deniedOutboxRecipient, &deniedOutboxPayload, &deniedOutboxStatus); scanErr != nil {
			return scanErr
		}
		assert.Equal(t, "whatsapp", deniedOutboxProvider)
		assert.Equal(t, "+15550009999", deniedOutboxRecipient)
		assert.Equal(t, string(channels.OutboxStatusPending), deniedOutboxStatus)
		assert.JSONEq(t, `{
				"content":"not authorized",
				"correlation_id":"corr-denied-rbac"
			}`, deniedOutboxPayload)

		var slackStatus string
		if scanErr := q.QueryRow(ctx,
			`SELECT status
			 FROM channel_messages
			 WHERE idempotency_key = 'idem-slack-missing-recipient'`,
		).Scan(&slackStatus); scanErr != nil {
			return scanErr
		}
		assert.Equal(t, channels.MessageStatusDispatchFailed, slackStatus)

		var skippedStatus string
		if scanErr := q.QueryRow(ctx,
			`SELECT status
			 FROM channel_messages
			 WHERE idempotency_key = 'idem-no-enqueue-failure'`,
		).Scan(&skippedStatus); scanErr != nil {
			return scanErr
		}
		assert.Equal(t, channels.MessageStatusDispatchFailed, skippedStatus)

		return nil
	})
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantB, func(ctx context.Context, q database.Querier) error {
		var outboxCount int
		if scanErr := q.QueryRow(ctx,
			`SELECT COUNT(*)
			 FROM channel_outbox
			 WHERE channel_message_id = $1`,
			tenantBMessageID,
		).Scan(&outboxCount); scanErr != nil {
			return scanErr
		}
		assert.Equal(t, 0, outboxCount)
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

func TestStore_ListRecentConversationByUser_ReturnsChronologicalLimitedTurns(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := channels.NewStore()

	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Tenant Conversation', 'tenant-conversation') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	userA := uuid.NewString()
	userB := uuid.NewString()
	base := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)

	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		for i := 1; i <= 15; i++ {
			req := fmt.Sprintf("req-%02d", i)
			resp := fmt.Sprintf("resp-%02d", i)
			_, execErr := q.Exec(ctx,
				`INSERT INTO channel_messages (
					tenant_id, platform, platform_user_id, platform_message_id, idempotency_key,
					payload_fingerprint, correlation_id, status, metadata, first_seen_at, expires_at
				) VALUES (
					current_setting('app.current_tenant_id', true)::UUID,
					'whatsapp', '+15550001111', $1, $2,
					$3, $4, 'executed', jsonb_build_object('user_id', $5::text, 'request_content', $6::text, 'response_content', $7::text), $8, $9
				)`,
				fmt.Sprintf("msg-conv-a-%02d", i),
				fmt.Sprintf("idem-conv-a-%02d", i),
				fmt.Sprintf("fp-conv-a-%02d", i),
				fmt.Sprintf("corr-conv-a-%02d", i),
				userA,
				req,
				resp,
				base.Add(time.Duration(i)*time.Minute),
				base.Add(24*time.Hour),
			)
			if execErr != nil {
				return execErr
			}
		}

		_, execErr := q.Exec(ctx,
			`INSERT INTO channel_messages (
				tenant_id, platform, platform_user_id, platform_message_id, idempotency_key,
				payload_fingerprint, correlation_id, status, metadata, first_seen_at, expires_at
			) VALUES (
				current_setting('app.current_tenant_id', true)::UUID,
				'whatsapp', '+15559990000', 'msg-conv-b-01', 'idem-conv-b-01',
				'fp-conv-b-01', 'corr-conv-b-01', 'executed',
				jsonb_build_object('user_id', $1::text, 'request_content', 'other-user', 'response_content', 'other-user-resp'),
				$2, $3
			)`,
			userB,
			base.Add(30*time.Minute),
			base.Add(24*time.Hour),
		)
		return execErr
	})
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		history, listErr := store.ListRecentConversationByUser(ctx, q, userA, 100)
		require.NoError(t, listErr)
		require.Len(t, history, 12)

		for i := 0; i < len(history); i++ {
			n := i + 4
			assert.Equal(t, fmt.Sprintf("req-%02d", n), history[i].RequestContent)
			assert.Equal(t, fmt.Sprintf("resp-%02d", n), history[i].ResponseContent)
		}
		return nil
	})
	require.NoError(t, err)
}

func TestStore_ListRecentConversationByUser_IgnoresRowsWithoutRequestContent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := channels.NewStore()

	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Tenant Conversation Filter', 'tenant-conversation-filter') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	userID := uuid.NewString()
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)

	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		_, execErr := q.Exec(ctx,
			`INSERT INTO channel_messages (
				tenant_id, platform, platform_user_id, platform_message_id, idempotency_key,
				payload_fingerprint, correlation_id, status, metadata, first_seen_at, expires_at
			) VALUES
			(
				current_setting('app.current_tenant_id', true)::UUID,
				'whatsapp', '+15550002222', 'msg-conv-filter-1', 'idem-conv-filter-1',
				'fp-conv-filter-1', 'corr-conv-filter-1', 'executed',
				jsonb_build_object('user_id', $1::text, 'request_content', '', 'response_content', 'ignored-empty-request'),
				$2, $3
			),
			(
				current_setting('app.current_tenant_id', true)::UUID,
				'whatsapp', '+15550002222', 'msg-conv-filter-2', 'idem-conv-filter-2',
				'fp-conv-filter-2', 'corr-conv-filter-2', 'executed',
				jsonb_build_object('user_id', $1::text, 'response_content', 'ignored-missing-request'),
				$4, $5
			),
			(
				current_setting('app.current_tenant_id', true)::UUID,
				'whatsapp', '+15550002222', 'msg-conv-filter-3', 'idem-conv-filter-3',
				'fp-conv-filter-3', 'corr-conv-filter-3', 'accepted',
				jsonb_build_object('user_id', $1::text, 'request_content', 'ignored-accepted', 'response_content', 'ignored-accepted'),
				$6, $7
			),
			(
				current_setting('app.current_tenant_id', true)::UUID,
				'whatsapp', '+15550002222', 'msg-conv-filter-4', 'idem-conv-filter-4',
				'fp-conv-filter-4', 'corr-conv-filter-4', 'executed',
				jsonb_build_object('user_id', $1::text, 'request_content', 'keep-1', 'response_content', 'keep-resp-1'),
				$8, $9
			),
			(
				current_setting('app.current_tenant_id', true)::UUID,
				'whatsapp', '+15550002222', 'msg-conv-filter-5', 'idem-conv-filter-5',
				'fp-conv-filter-5', 'corr-conv-filter-5', 'denied_rbac',
				jsonb_build_object('user_id', $1::text, 'request_content', 'keep-2', 'response_content', ''),
				$10, $11
			)`,
			userID,
			base.Add(1*time.Minute), base.Add(24*time.Hour),
			base.Add(2*time.Minute), base.Add(24*time.Hour),
			base.Add(3*time.Minute), base.Add(24*time.Hour),
			base.Add(4*time.Minute), base.Add(24*time.Hour),
			base.Add(5*time.Minute), base.Add(24*time.Hour),
		)
		return execErr
	})
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		history, listErr := store.ListRecentConversationByUser(ctx, q, userID, 12)
		require.NoError(t, listErr)
		require.Len(t, history, 2)

		assert.Equal(t, "keep-1", history[0].RequestContent)
		assert.Equal(t, "keep-resp-1", history[0].ResponseContent)
		assert.Equal(t, "keep-2", history[1].RequestContent)
		assert.Equal(t, "", history[1].ResponseContent)
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

func TestOutboxStore_ListOutbox_FilterAndLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := channels.NewStore()

	tenantA := seedTenant(t, ctx, pool, "outbox-list-tenant-a")
	tenantB := seedTenant(t, ctx, pool, "outbox-list-tenant-b")
	var err error

	deadAID := seedOutboxJobInTenant(t, ctx, pool, store, tenantA)
	err = database.WithTenantConnection(ctx, pool, tenantA, func(ctx context.Context, q database.Querier) error {
		claimed, claimErr := store.ClaimPendingOutbox(ctx, q, time.Now().UTC(), 1)
		if claimErr != nil {
			return claimErr
		}
		require.Len(t, claimed, 1)
		if claimed[0].ID != deadAID {
			return fmt.Errorf("unexpected claimed outbox id %s (want %s)", claimed[0].ID, deadAID)
		}
		return store.MarkOutboxDead(ctx, q, deadAID, "dead for listing")
	})
	require.NoError(t, err)
	pendingAID := seedOutboxJobInTenant(t, ctx, pool, store, tenantA)

	_ = seedOutboxJobInTenant(t, ctx, pool, store, tenantB)

	err = database.WithTenantConnection(ctx, pool, tenantA, func(ctx context.Context, q database.Querier) error {
		jobs, listErr := store.ListOutbox(ctx, q, "", 10)
		require.NoError(t, listErr)
		require.Len(t, jobs, 2)
		for _, job := range jobs {
			assert.Equal(t, tenantA, job.TenantID.String())
		}

		deadJobs, deadErr := store.ListOutbox(ctx, q, string(channels.OutboxStatusDead), 10)
		require.NoError(t, deadErr)
		require.Len(t, deadJobs, 1)
		assert.Equal(t, deadAID, deadJobs[0].ID)
		assert.Equal(t, channels.OutboxStatusDead, deadJobs[0].Status)

		pendingJobs, pendingErr := store.ListOutbox(ctx, q, string(channels.OutboxStatusPending), 1)
		require.NoError(t, pendingErr)
		require.Len(t, pendingJobs, 1)
		assert.Equal(t, channels.OutboxStatusPending, pendingJobs[0].Status)
		assert.Equal(t, pendingAID, pendingJobs[0].ID)

		return nil
	})
	require.NoError(t, err)
}

func TestOutboxStore_RequeueDead(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := channels.NewStore()

	tenantA := seedTenant(t, ctx, pool, "outbox-requeue-tenant-a")
	tenantB := seedTenant(t, ctx, pool, "outbox-requeue-tenant-b")
	deadID := seedOutboxJobInTenant(t, ctx, pool, store, tenantA)
	_ = seedOutboxJobInTenant(t, ctx, pool, store, tenantB)
	err := database.WithTenantConnection(ctx, pool, tenantA, func(ctx context.Context, q database.Querier) error {
		claimed, claimErr := store.ClaimPendingOutbox(ctx, q, time.Now().UTC(), 1)
		if claimErr != nil {
			return claimErr
		}
		require.Len(t, claimed, 1)
		return store.MarkOutboxDead(ctx, q, deadID, "seed dead state")
	})
	require.NoError(t, err)
	require.NotEqual(t, tenantA, tenantB)

	err = database.WithTenantConnection(ctx, pool, tenantA, func(ctx context.Context, q database.Querier) error {
		return store.RequeueOutboxDead(ctx, q, deadID)
	})
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantA, func(ctx context.Context, q database.Querier) error {
		var status string
		var attemptCount int
		var nextAttempt time.Time
		var lastError *string
		var lockedAt *time.Time
		rowErr := q.QueryRow(ctx,
			`SELECT status, attempt_count, next_attempt_at, last_error, locked_at
			 FROM channel_outbox
			 WHERE id = $1`,
			deadID,
		).Scan(&status, &attemptCount, &nextAttempt, &lastError, &lockedAt)
		require.NoError(t, rowErr)
		assert.Equal(t, string(channels.OutboxStatusPending), status)
		assert.Equal(t, 1, attemptCount)
		assert.WithinDuration(t, time.Now().UTC(), nextAttempt, 5*time.Second)
		assert.Nil(t, lastError)
		assert.Nil(t, lockedAt)
		return nil
	})
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantB, func(ctx context.Context, q database.Querier) error {
		requeueErr := store.RequeueOutboxDead(ctx, q, deadID)
		require.ErrorIs(t, requeueErr, channels.ErrOutboxNotFound)
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

func seedTenant(t *testing.T, ctx context.Context, pool *database.Pool, slugPrefix string) string {
	t.Helper()

	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ($1, $2) RETURNING id",
		"Tenant "+slugPrefix,
		slugPrefix+"-"+uuid.NewString()[:8],
	).Scan(&tenantID)
	require.NoError(t, err)
	return tenantID
}

func seedOutboxJobInTenant(
	t *testing.T,
	ctx context.Context,
	pool *database.Pool,
	store *channels.Store,
	tenantID string,
) uuid.UUID {
	t.Helper()

	var messageID uuid.UUID
	err := database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		return q.QueryRow(ctx,
			`INSERT INTO channel_messages (
				tenant_id, platform, platform_user_id, platform_message_id, idempotency_key,
				payload_fingerprint, correlation_id, status, expires_at
			) VALUES (
				current_setting('app.current_tenant_id', true)::UUID,
				'whatsapp', '+15550004444', $1, $2,
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
			RecipientID:      "+15550004444",
			Payload:          json.RawMessage(`{"text":"seed outbox"}`),
		})
		if enqueueErr != nil {
			return enqueueErr
		}
		outboxID = job.ID
		return nil
	})
	require.NoError(t, err)
	return outboxID
}

func TestChannelProviderCredentialStore_UpsertGetDelete(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := newCredentialStore(t)

	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Tenant Creds', 'tenant-creds') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		created, upsertErr := store.UpsertProviderCredential(ctx, q, channels.UpsertProviderCredentialParams{
			Provider:      "whatsapp",
			AccessToken:   "wa-token-1",
			SigningSecret: "wa-signing-secret-1",
			PhoneNumberID: "15550001111",
			APIBaseURL:    "https://graph.example.com",
			APIVersion:    "v22.0",
		})
		require.NoError(t, upsertErr)
		assert.Equal(t, tenantID, created.TenantID.String())
		assert.Equal(t, "whatsapp", created.Provider)
		assert.Equal(t, "wa-token-1", created.AccessToken)
		assert.Equal(t, "wa-signing-secret-1", created.SigningSecret)
		assert.Equal(t, "15550001111", created.PhoneNumberID)

		loaded, getErr := store.GetProviderCredential(ctx, q, "whatsapp")
		require.NoError(t, getErr)
		assert.Equal(t, created.ID, loaded.ID)
		assert.Equal(t, "wa-token-1", loaded.AccessToken)
		assert.Equal(t, "wa-signing-secret-1", loaded.SigningSecret)
		assert.Equal(t, "https://graph.example.com", loaded.APIBaseURL)
		assert.Equal(t, "v22.0", loaded.APIVersion)

		updated, upsertErr := store.UpsertProviderCredential(ctx, q, channels.UpsertProviderCredentialParams{
			Provider:      "whatsapp",
			AccessToken:   "wa-token-2",
			SigningSecret: "wa-signing-secret-2",
			PhoneNumberID: "15550001111",
		})
		require.NoError(t, upsertErr)
		assert.Equal(t, created.ID, updated.ID)
		assert.Equal(t, "wa-token-2", updated.AccessToken)
		assert.Equal(t, "wa-signing-secret-2", updated.SigningSecret)

		deleteErr := store.DeleteProviderCredential(ctx, q, "whatsapp")
		require.NoError(t, deleteErr)

		_, getErr = store.GetProviderCredential(ctx, q, "whatsapp")
		require.ErrorIs(t, getErr, channels.ErrProviderCredentialNotFound)
		return nil
	})
	require.NoError(t, err)
}

func TestChannelProviderCredentialStore_EncryptsSecretsAtRest(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	crypto, err := channels.NewCredentialCrypto(testCredentialCryptoKey)
	require.NoError(t, err)
	store := channels.NewStore(channels.WithCredentialCrypto(crypto))

	var tenantID string
	err = pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Tenant Encrypted Creds', 'tenant-encrypted-creds') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		created, upsertErr := store.UpsertProviderCredential(ctx, q, channels.UpsertProviderCredentialParams{
			Provider:      "whatsapp",
			AccessToken:   "wa-token-enc",
			SigningSecret: "wa-signing-enc",
			PhoneNumberID: "15550009999",
		})
		require.NoError(t, upsertErr)
		assert.Equal(t, "wa-token-enc", created.AccessToken)
		assert.Equal(t, "wa-signing-enc", created.SigningSecret)

		var rawAccessToken, rawSigningSecret string
		rawErr := q.QueryRow(ctx,
			`SELECT access_token, signing_secret
			 FROM channel_provider_credentials
			 WHERE tenant_id = current_setting('app.current_tenant_id', true)::UUID
			   AND provider = 'whatsapp'`,
		).Scan(&rawAccessToken, &rawSigningSecret)
		require.NoError(t, rawErr)
		assert.True(t, channels.IsEncryptedCredentialValue(rawAccessToken))
		assert.True(t, channels.IsEncryptedCredentialValue(rawSigningSecret))
		assert.NotEqual(t, "wa-token-enc", rawAccessToken)
		assert.NotEqual(t, "wa-signing-enc", rawSigningSecret)

		loaded, getErr := store.GetProviderCredential(ctx, q, "whatsapp")
		require.NoError(t, getErr)
		assert.Equal(t, "wa-token-enc", loaded.AccessToken)
		assert.Equal(t, "wa-signing-enc", loaded.SigningSecret)
		return nil
	})
	require.NoError(t, err)
}

func TestChannelProviderCredentialStore_LegacyPlaintextCompat(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	crypto, err := channels.NewCredentialCrypto(testCredentialCryptoKey)
	require.NoError(t, err)
	store := channels.NewStore(channels.WithCredentialCrypto(crypto))

	var tenantID string
	err = pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Tenant Legacy Creds', 'tenant-legacy-creds') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		_, insertErr := q.Exec(ctx,
			`INSERT INTO channel_provider_credentials (tenant_id, provider, access_token, signing_secret)
			 VALUES (current_setting('app.current_tenant_id', true)::UUID, 'slack', $1, $2)`,
			"xoxb-legacy-plaintext",
			"slack-signing-legacy",
		)
		require.NoError(t, insertErr)

		loaded, getErr := store.GetProviderCredential(ctx, q, "slack")
		require.NoError(t, getErr)
		assert.Equal(t, "xoxb-legacy-plaintext", loaded.AccessToken)
		assert.Equal(t, "slack-signing-legacy", loaded.SigningSecret)
		assert.False(t, strings.HasPrefix(loaded.AccessToken, "enc:v1:"))
		return nil
	})
	require.NoError(t, err)
}

func TestChannelProviderCredentialStore_EncryptedValueRequiresKey(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	crypto, err := channels.NewCredentialCrypto(testCredentialCryptoKey)
	require.NoError(t, err)
	encryptedStore := channels.NewStore(channels.WithCredentialCrypto(crypto))
	plaintextStore := channels.NewStore()

	var tenantID string
	err = pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Tenant Missing Key', 'tenant-missing-key') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		_, upsertErr := encryptedStore.UpsertProviderCredential(ctx, q, channels.UpsertProviderCredentialParams{
			Provider:      "slack",
			AccessToken:   "xoxb-encrypted",
			SigningSecret: "slack-signing-encrypted",
		})
		require.NoError(t, upsertErr)

		_, getErr := plaintextStore.GetProviderCredential(ctx, q, "slack")
		require.ErrorIs(t, getErr, channels.ErrProviderCredentialCipherRequired)
		return nil
	})
	require.NoError(t, err)
}

func TestChannelProviderCredentialStore_TenantIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := newCredentialStore(t)

	var tenantA, tenantB string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Tenant Cred A', 'tenant-cred-a') RETURNING id",
	).Scan(&tenantA)
	require.NoError(t, err)
	err = pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Tenant Cred B', 'tenant-cred-b') RETURNING id",
	).Scan(&tenantB)
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantA, func(ctx context.Context, q database.Querier) error {
		_, upsertErr := store.UpsertProviderCredential(ctx, q, channels.UpsertProviderCredentialParams{
			Provider:      "slack",
			AccessToken:   "xoxb-tenant-a",
			SigningSecret: "slack-signing-a",
		})
		return upsertErr
	})
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantB, func(ctx context.Context, q database.Querier) error {
		_, upsertErr := store.UpsertProviderCredential(ctx, q, channels.UpsertProviderCredentialParams{
			Provider:      "slack",
			AccessToken:   "xoxb-tenant-b",
			SigningSecret: "slack-signing-b",
		})
		return upsertErr
	})
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantA, func(ctx context.Context, q database.Querier) error {
		cred, getErr := store.GetProviderCredential(ctx, q, "slack")
		require.NoError(t, getErr)
		assert.Equal(t, "xoxb-tenant-a", cred.AccessToken)
		assert.Equal(t, "slack-signing-a", cred.SigningSecret)
		return nil
	})
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantB, func(ctx context.Context, q database.Querier) error {
		cred, getErr := store.GetProviderCredential(ctx, q, "slack")
		require.NoError(t, getErr)
		assert.Equal(t, "xoxb-tenant-b", cred.AccessToken)
		assert.Equal(t, "slack-signing-b", cred.SigningSecret)
		return nil
	})
	require.NoError(t, err)
}

func TestChannelProviderCredentialStore_Validation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := newCredentialStore(t)

	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Tenant Cred Validation', 'tenant-cred-validation') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		_, upsertErr := store.UpsertProviderCredential(ctx, q, channels.UpsertProviderCredentialParams{
			Provider: "slack",
		})
		require.ErrorIs(t, upsertErr, channels.ErrProviderAccessTokenRequired)

		_, upsertErr = store.UpsertProviderCredential(ctx, q, channels.UpsertProviderCredentialParams{
			Provider:      "whatsapp",
			AccessToken:   "wa-token",
			SigningSecret: "wa-signing-secret",
		})
		require.ErrorIs(t, upsertErr, channels.ErrProviderPhoneNumberIDRequired)

		_, upsertErr = store.UpsertProviderCredential(ctx, q, channels.UpsertProviderCredentialParams{
			Provider:    "slack",
			AccessToken: "xoxb-token",
		})
		require.ErrorIs(t, upsertErr, channels.ErrProviderSigningSecretRequired)

		_, upsertErr = store.UpsertProviderCredential(ctx, q, channels.UpsertProviderCredentialParams{
			Provider:    "telegram",
			AccessToken: "123456:ABC",
		})
		require.ErrorIs(t, upsertErr, channels.ErrProviderSecretTokenRequired)

		_, upsertErr = store.UpsertProviderCredential(ctx, q, channels.UpsertProviderCredentialParams{
			Provider:    "telegram",
			AccessToken: "123456:ABC",
			SecretToken: "tg-secret",
		})
		require.NoError(t, upsertErr)

		_, upsertErr = store.UpsertProviderCredential(ctx, q, channels.UpsertProviderCredentialParams{
			Provider:    "teams",
			AccessToken: "token",
		})
		require.ErrorIs(t, upsertErr, channels.ErrProviderUnsupported)
		return nil
	})
	require.NoError(t, err)
}
