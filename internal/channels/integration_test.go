package channels_test

import (
	"context"
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
