package channels_test

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/channels"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

type allowVerifier struct{}

func (allowVerifier) Verify(_ http.Header, _ []byte, _ time.Time) error { return nil }

func TestIngress_ConcurrentDuplicateExecutesOnce(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := channels.NewStore()

	var tenantID string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Tenant C', 'tenant-c-integ') RETURNING id",
	).Scan(&tenantID)
	require.NoError(t, err)

	var userID string
	err = pool.QueryRow(ctx,
		"INSERT INTO users (tenant_id, email, display_name) VALUES ($1, 'integ@tenant.com', 'Integ User') RETURNING id",
		tenantID,
	).Scan(&userID)
	require.NoError(t, err)

	_, err = pool.Exec(ctx,
		`INSERT INTO channel_links (tenant_id, user_id, platform, platform_user_id, state, verified)
		 VALUES ($1, $2, 'whatsapp', '+15558889999', 'verified', true)`,
		tenantID, userID,
	)
	require.NoError(t, err)

	resolveLink := func(ctx context.Context, platform, platformUserID string) (*channels.ChannelLink, error) {
		var out *channels.ChannelLink
		err := database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
			var lookupErr error
			out, lookupErr = store.GetLinkByIdentity(ctx, q, platform, platformUserID)
			return lookupErr
		})
		return out, err
	}

	insertIdempotency := func(ctx context.Context, msg channels.IngressMessage) (bool, error) {
		var firstSeen bool
		err := database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
			var insertErr error
			firstSeen, insertErr = store.InsertIdempotency(
				ctx,
				q,
				msg.Platform,
				msg.PlatformUserID,
				msg.PlatformMessageID,
				msg.IdempotencyKey,
				msg.PayloadFingerprint,
				msg.CorrelationID,
				msg.ExpiresAt,
			)
			return insertErr
		})
		return firstSeen, err
	}

	guard := channels.NewIngressGuard(
		allowVerifier{},
		24*time.Hour,
		resolveLink,
		insertIdempotency,
	)

	msg := channels.IngressMessage{
		Platform:           "whatsapp",
		PlatformUserID:     "+15558889999",
		PlatformMessageID:  "wamid.concurrent",
		IdempotencyKey:     "idem-concurrent-1",
		PayloadFingerprint: "fp-concurrent-1",
		CorrelationID:      "corr-concurrent-1",
		Headers:            http.Header{},
		Body:               []byte(`{"text":"hello"}`),
		OccurredAt:         time.Now(),
		ExpiresAt:          time.Now().Add(24 * time.Hour),
	}

	var wg sync.WaitGroup
	start := make(chan struct{})

	decisions := make([]channels.IngressDecision, 0, 2)
	var mu sync.Mutex

	runOne := func() {
		defer wg.Done()
		<-start
		res, err := guard.Process(context.Background(), msg)
		require.NoError(t, err)
		mu.Lock()
		decisions = append(decisions, res.Decision)
		mu.Unlock()
	}

	wg.Add(2)
	go runOne()
	go runOne()
	close(start)
	wg.Wait()

	var accepted, duplicate int
	for _, d := range decisions {
		if d == channels.IngressAccepted {
			accepted++
		}
		if d == channels.IngressDuplicate {
			duplicate++
		}
	}
	assert.Equal(t, 1, accepted)
	assert.Equal(t, 1, duplicate)
}

func TestIngress_CrossTenantIsolation_SamePlatformIdentity(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := channels.NewStore()

	var tenantA, tenantB string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Tenant D', 'tenant-d-integ') RETURNING id",
	).Scan(&tenantA)
	require.NoError(t, err)
	err = pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Tenant E', 'tenant-e-integ') RETURNING id",
	).Scan(&tenantB)
	require.NoError(t, err)

	var userAID, userBID string
	err = pool.QueryRow(ctx,
		"INSERT INTO users (tenant_id, email, display_name) VALUES ($1, 'a@integ.com', 'User A') RETURNING id",
		tenantA,
	).Scan(&userAID)
	require.NoError(t, err)
	err = pool.QueryRow(ctx,
		"INSERT INTO users (tenant_id, email, display_name) VALUES ($1, 'b@integ.com', 'User B') RETURNING id",
		tenantB,
	).Scan(&userBID)
	require.NoError(t, err)

	_, err = pool.Exec(ctx,
		`INSERT INTO channel_links (tenant_id, user_id, platform, platform_user_id, state, verified)
		 VALUES ($1, $2, 'telegram', 'tg-shared-identity', 'verified', true)`,
		tenantA, userAID,
	)
	require.NoError(t, err)
	_, err = pool.Exec(ctx,
		`INSERT INTO channel_links (tenant_id, user_id, platform, platform_user_id, state, verified)
		 VALUES ($1, $2, 'telegram', 'tg-shared-identity', 'verified', true)`,
		tenantB, userBID,
	)
	require.NoError(t, err)

	resolveForTenant := func(tenantID string) func(context.Context, string, string) (*channels.ChannelLink, error) {
		return func(ctx context.Context, platform, platformUserID string) (*channels.ChannelLink, error) {
			var out *channels.ChannelLink
			tenantErr := database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
				var lookupErr error
				out, lookupErr = store.GetLinkByIdentity(ctx, q, platform, platformUserID)
				return lookupErr
			})
			return out, tenantErr
		}
	}

	noopInsert := func(_ context.Context, _ channels.IngressMessage) (bool, error) { return true, nil }

	guardA := channels.NewIngressGuard(allowVerifier{}, 24*time.Hour, resolveForTenant(tenantA), noopInsert)
	guardB := channels.NewIngressGuard(allowVerifier{}, 24*time.Hour, resolveForTenant(tenantB), noopInsert)

	msg := channels.IngressMessage{
		Platform:           "telegram",
		PlatformUserID:     "tg-shared-identity",
		IdempotencyKey:     "idem-tenant-scope",
		PayloadFingerprint: "fp-tenant-scope",
		CorrelationID:      "corr-tenant-scope",
		Headers:            http.Header{},
		Body:               []byte(`{"text":"scope"}`),
		OccurredAt:         time.Now(),
		ExpiresAt:          time.Now().Add(24 * time.Hour),
	}

	resA, err := guardA.Process(ctx, msg)
	require.NoError(t, err)
	resB, err := guardB.Process(ctx, msg)
	require.NoError(t, err)

	require.NotNil(t, resA.Link)
	require.NotNil(t, resB.Link)
	assert.Equal(t, tenantA, resA.Link.TenantID.String())
	assert.Equal(t, tenantB, resB.Link.TenantID.String())
	assert.NotEqual(t, resA.Link.UserID, resB.Link.UserID)
}

func TestOutbox_MultiTenantIsolationAndSingleClaim(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	store := channels.NewStore()

	var tenantA, tenantB string
	err := pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Outbox Tenant IA', 'outbox-tenant-ia') RETURNING id",
	).Scan(&tenantA)
	require.NoError(t, err)
	err = pool.QueryRow(ctx,
		"INSERT INTO tenants (name, slug) VALUES ('Outbox Tenant IB', 'outbox-tenant-ib') RETURNING id",
	).Scan(&tenantB)
	require.NoError(t, err)

	var messageAID, messageBID string
	err = database.WithTenantConnection(ctx, pool, tenantA, func(ctx context.Context, q database.Querier) error {
		if scanErr := q.QueryRow(ctx,
			`INSERT INTO channel_messages (
				tenant_id, platform, platform_user_id, platform_message_id, idempotency_key,
				payload_fingerprint, correlation_id, status, expires_at
			) VALUES (
				current_setting('app.current_tenant_id', true)::UUID,
				'whatsapp', '+15550001111', 'msg-outbox-ia', 'idem-outbox-ia',
				'fp-outbox-ia', 'corr-outbox-ia', 'executed', now() + interval '1 day'
			) RETURNING id`,
		).Scan(&messageAID); scanErr != nil {
			return scanErr
		}

		_, enqueueErr := store.EnqueueOutbound(ctx, q, channels.EnqueueOutboundParams{
			ChannelMessageID: messageAID,
			Provider:         "whatsapp",
			RecipientID:      "+15550001111",
			Payload:          json.RawMessage(`{"content":"tenant a response"}`),
		})
		return enqueueErr
	})
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantB, func(ctx context.Context, q database.Querier) error {
		if scanErr := q.QueryRow(ctx,
			`INSERT INTO channel_messages (
				tenant_id, platform, platform_user_id, platform_message_id, idempotency_key,
				payload_fingerprint, correlation_id, status, expires_at
			) VALUES (
				current_setting('app.current_tenant_id', true)::UUID,
				'whatsapp', '+15550002222', 'msg-outbox-ib', 'idem-outbox-ib',
				'fp-outbox-ib', 'corr-outbox-ib', 'executed', now() + interval '1 day'
			) RETURNING id`,
		).Scan(&messageBID); scanErr != nil {
			return scanErr
		}

		_, enqueueErr := store.EnqueueOutbound(ctx, q, channels.EnqueueOutboundParams{
			ChannelMessageID: messageBID,
			Provider:         "whatsapp",
			RecipientID:      "+15550002222",
			Payload:          json.RawMessage(`{"content":"tenant b response"}`),
		})
		return enqueueErr
	})
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantB, func(ctx context.Context, q database.Querier) error {
		_, enqueueErr := store.EnqueueOutbound(ctx, q, channels.EnqueueOutboundParams{
			ChannelMessageID: messageAID,
			Provider:         "whatsapp",
			RecipientID:      "+15550003333",
			Payload:          json.RawMessage(`{"content":"cross-tenant-forbidden"}`),
		})
		require.ErrorIs(t, enqueueErr, channels.ErrMessageNotFound)
		return nil
	})
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantA, func(ctx context.Context, q database.Querier) error {
		firstClaim, claimErr := store.ClaimPendingOutbox(ctx, q, time.Now().UTC(), 10)
		require.NoError(t, claimErr)
		require.Len(t, firstClaim, 1)
		assert.Equal(t, tenantA, firstClaim[0].TenantID.String())
		assert.Equal(t, messageAID, firstClaim[0].ChannelMessageID.String())

		secondClaim, secondErr := store.ClaimPendingOutbox(ctx, q, time.Now().UTC(), 10)
		require.NoError(t, secondErr)
		assert.Empty(t, secondClaim)
		return nil
	})
	require.NoError(t, err)

	err = database.WithTenantConnection(ctx, pool, tenantB, func(ctx context.Context, q database.Querier) error {
		claim, claimErr := store.ClaimPendingOutbox(ctx, q, time.Now().UTC(), 10)
		require.NoError(t, claimErr)
		require.Len(t, claim, 1)
		assert.Equal(t, tenantB, claim[0].TenantID.String())
		assert.Equal(t, messageBID, claim[0].ChannelMessageID.String())
		return nil
	})
	require.NoError(t, err)
}
