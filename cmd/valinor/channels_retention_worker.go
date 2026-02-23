package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/valinor-ai/valinor/internal/channels"
	"github.com/valinor-ai/valinor/internal/platform/config"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

const (
	defaultRetentionCleanupInterval  = time.Hour
	defaultRetentionCleanupBatchSize = 500
)

type channelRetentionWorker struct {
	pool      *database.Pool
	store     *channels.Store
	interval  time.Duration
	batchSize int
	now       func() time.Time
}

func buildChannelRetentionWorker(pool *database.Pool, cfg config.ChannelsConfig) *channelRetentionWorker {
	if pool == nil || !cfg.Ingress.Enabled || !cfg.Ingress.RetentionCleanupEnabled {
		return nil
	}

	interval := time.Duration(cfg.Ingress.RetentionCleanupIntervalSeconds) * time.Second
	if interval <= 0 {
		interval = defaultRetentionCleanupInterval
	}

	batchSize := cfg.Ingress.RetentionCleanupBatchSize
	if batchSize <= 0 {
		batchSize = defaultRetentionCleanupBatchSize
	}

	return &channelRetentionWorker{
		pool:      pool,
		store:     channels.NewStore(),
		interval:  interval,
		batchSize: batchSize,
		now:       time.Now,
	}
}

func (w *channelRetentionWorker) Run(ctx context.Context) error {
	if w == nil || w.pool == nil || w.store == nil {
		return nil
	}

	w.sweep(ctx)

	ticker := time.NewTicker(w.interval)
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

func (w *channelRetentionWorker) sweep(ctx context.Context) {
	tenantIDs, err := listTenantIDs(ctx, w.pool, defaultTenantScanPageSize)
	if err != nil {
		slog.Error("channel retention worker failed to list tenants", "error", err)
		return
	}

	now := time.Now().UTC()
	if w.now != nil {
		now = w.now().UTC()
	}

	for _, tenantID := range tenantIDs {
		if ctx.Err() != nil {
			return
		}

		tenantErr := database.WithTenantConnection(ctx, w.pool, tenantID, func(ctx context.Context, q database.Querier) error {
			totalDeleted := 0
			for {
				deleted, cleanupErr := w.store.DeleteExpiredMessages(ctx, q, now, w.batchSize)
				if cleanupErr != nil {
					return cleanupErr
				}
				totalDeleted += deleted
				if deleted < w.batchSize {
					break
				}
			}

			if totalDeleted > 0 {
				slog.Info(
					"channel retention cleanup completed",
					"tenant_id", tenantID,
					"deleted_rows", totalDeleted,
				)
			}
			return nil
		})
		if tenantErr != nil {
			slog.Error(
				"channel retention worker tenant cleanup failed",
				"tenant_id", tenantID,
				"error", tenantErr,
			)
		}
	}
}
