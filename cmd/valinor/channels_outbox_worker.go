package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/valinor-ai/valinor/internal/channels"
	"github.com/valinor-ai/valinor/internal/platform/config"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

type channelOutboxWorker struct {
	pool         *database.Pool
	dispatcher   *channels.OutboxDispatcher
	pollInterval time.Duration
}

type noopOutboxSender struct{}

func (noopOutboxSender) Send(_ context.Context, _ channels.ChannelOutbox) error {
	// TODO(v2): replace this stub with real provider dispatch.
	// V1 adapter stub: successful no-op send for infrastructure wiring.
	return nil
}

func buildChannelOutboxWorker(pool *database.Pool, cfg config.ChannelsConfig) (*channelOutboxWorker, error) {
	if pool == nil || !cfg.Ingress.Enabled || !cfg.Outbox.Enabled {
		return nil, nil
	}

	pollInterval := time.Duration(cfg.Outbox.PollIntervalSeconds) * time.Second
	if pollInterval <= 0 {
		pollInterval = 2 * time.Second
	}

	sender, err := buildChannelOutboxSender(cfg)
	if err != nil {
		return nil, fmt.Errorf("building channel outbox sender: %w", err)
	}

	dispatcher := channels.NewOutboxDispatcher(channels.NewStore(), sender, channels.OutboxDispatcherConfig{
		ClaimBatchSize:    cfg.Outbox.ClaimBatchSize,
		RecoveryBatchSize: cfg.Outbox.RecoveryBatchSize,
		LockTimeout:       time.Duration(cfg.Outbox.LockTimeoutSeconds) * time.Second,
		MaxAttempts:       cfg.Outbox.MaxAttempts,
		BaseRetryDelay:    time.Duration(cfg.Outbox.BaseRetrySeconds) * time.Second,
		MaxRetryDelay:     time.Duration(cfg.Outbox.MaxRetrySeconds) * time.Second,
		JitterFraction:    cfg.Outbox.JitterFraction,
	})

	return &channelOutboxWorker{
		pool:         pool,
		dispatcher:   dispatcher,
		pollInterval: pollInterval,
	}, nil
}

func (w *channelOutboxWorker) Run(ctx context.Context) error {
	if w == nil || w.pool == nil || w.dispatcher == nil {
		return nil
	}

	w.sweep(ctx)

	ticker := time.NewTicker(w.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			w.sweep(ctx)
		}
	}
}

func (w *channelOutboxWorker) sweep(ctx context.Context) {
	tenantIDs, err := listTenantIDs(ctx, w.pool)
	if err != nil {
		slog.Error("channel outbox worker failed to list tenants", "error", err)
		return
	}

	for _, tenantID := range tenantIDs {
		if ctx.Err() != nil {
			return
		}

		tenantErr := database.WithTenantConnection(ctx, w.pool, tenantID, func(ctx context.Context, q database.Querier) error {
			_, dispatchErr := w.dispatcher.DispatchOnce(ctx, q)
			return dispatchErr
		})
		if tenantErr != nil {
			slog.Error(
				"channel outbox worker tenant sweep failed",
				"tenant_id", tenantID,
				"error", tenantErr,
			)
		}
	}
}

func listTenantIDs(ctx context.Context, pool *database.Pool) ([]string, error) {
	// TODO: paginate tenant scanning when tenant count grows large.
	rows, err := pool.Query(ctx, `SELECT id::text FROM tenants ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tenantIDs := make([]string, 0)
	for rows.Next() {
		var tenantID string
		if scanErr := rows.Scan(&tenantID); scanErr != nil {
			return nil, scanErr
		}
		tenantIDs = append(tenantIDs, tenantID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return tenantIDs, nil
}
