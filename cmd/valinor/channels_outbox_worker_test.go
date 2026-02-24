package main

import (
	"context"
	"fmt"
	"sort"
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

func setupWorkerTestDB(t *testing.T) (*database.Pool, func()) {
	t.Helper()
	ctx := context.Background()
	testUser := "valinor_" + uuid.NewString()[:8]
	testPassword := uuid.NewString()

	container, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("valinor_test"),
		postgres.WithUsername(testUser),
		postgres.WithPassword(testPassword),
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

func TestListTenantIDs_NonPositivePageSizeReturnsError(t *testing.T) {
	tenantIDs, err := listTenantIDs(context.Background(), nil, 0)
	require.Error(t, err)
	assert.Nil(t, tenantIDs)
	assert.Contains(t, err.Error(), "must be positive")
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

type noopOutboxSender struct{}

func (noopOutboxSender) Send(_ context.Context, _ channels.ChannelOutbox) error {
	return nil
}

func TestChannelOutboxWorker_SweepRecoversDispatchFailures(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupWorkerTestDB(t)
	defer cleanup()

	ctx := context.Background()

	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Recovery Sweep Tenant', 'recovery-sweep-tenant') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		_, execErr := q.Exec(ctx,
			`INSERT INTO channel_messages (
				tenant_id, platform, platform_user_id, platform_message_id, idempotency_key,
				payload_fingerprint, correlation_id, status, metadata, expires_at
			) VALUES (
				current_setting('app.current_tenant_id', true)::UUID,
				'whatsapp', '+15553334444', 'msg-sweep-recover', 'idem-sweep-recover',
				'fp-sweep-recover', 'corr-sweep-recover', 'dispatch_failed',
				'{"decision":"dispatch_failed","agent_id":"agent-sweep","outbox_enqueue_failed":true,"outbox_recipient_id":"+15553334444","response_content":"recover in sweep"}'::jsonb,
				now() + interval '1 day'
			)`,
		)
		return execErr
	})
	require.NoError(t, err)

	store := channels.NewStore()
	dispatcher := channels.NewOutboxDispatcher(store, noopOutboxSender{}, channels.OutboxDispatcherConfig{
		ClaimBatchSize:    10,
		RecoveryBatchSize: 10,
		MaxAttempts:       5,
		BaseRetryDelay:    time.Second,
		MaxRetryDelay:     10 * time.Second,
	})
	worker := &channelOutboxWorker{
		pool:                pool,
		store:               store,
		dispatcher:          dispatcher,
		pollInterval:        time.Second,
		tenantScanPageSize:  100,
		recoveryBatchSize:   10,
		recoveryMaxAttempts: 7,
	}

	worker.sweep(ctx)

	err = database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
		var status string
		if scanErr := q.QueryRow(ctx,
			`SELECT status
			 FROM channel_messages
			 WHERE idempotency_key = 'idem-sweep-recover'`,
		).Scan(&status); scanErr != nil {
			return scanErr
		}
		assert.Equal(t, channels.MessageStatusExecuted, status)

		var outboxStatus string
		var payload string
		if scanErr := q.QueryRow(ctx,
			`SELECT outbox.status, outbox.payload::text
			 FROM channel_outbox outbox
			 JOIN channel_messages msg ON msg.id = outbox.channel_message_id
			 WHERE msg.idempotency_key = 'idem-sweep-recover'`,
		).Scan(&outboxStatus, &payload); scanErr != nil {
			return scanErr
		}
		assert.Equal(t, string(channels.OutboxStatusSent), outboxStatus)
		assert.JSONEq(t, `{"content":"recover in sweep","correlation_id":"corr-sweep-recover"}`, payload)
		return nil
	})
	require.NoError(t, err)
}
