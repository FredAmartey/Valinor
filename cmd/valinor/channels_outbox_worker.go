package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/valinor-ai/valinor/internal/channels"
	"github.com/valinor-ai/valinor/internal/platform/config"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

type channelOutboxWorker struct {
	pool                *database.Pool
	store               *channels.Store
	dispatcher          *channels.OutboxDispatcher
	pollInterval        time.Duration
	tenantScanPageSize  int
	recoveryBatchSize   int
	recoveryMaxAttempts int
}

func buildChannelOutboxWorker(pool *database.Pool, cfg config.ChannelsConfig) (*channelOutboxWorker, error) {
	if pool == nil || !cfg.Ingress.Enabled || !cfg.Outbox.Enabled {
		return nil, nil
	}

	pollInterval := time.Duration(cfg.Outbox.PollIntervalSeconds) * time.Second
	if pollInterval <= 0 {
		pollInterval = 2 * time.Second
	}
	tenantScanPageSize := cfg.Outbox.TenantScanPageSize
	if tenantScanPageSize <= 0 {
		tenantScanPageSize = defaultTenantScanPageSize
	}

	store, err := buildChannelStore(cfg)
	if err != nil {
		return nil, fmt.Errorf("building channel store: %w", err)
	}
	credentialResolver := newDBOutboxProviderCredentialResolver(pool, store, cfg.Providers)
	sender, err := buildChannelOutboxSender(cfg, credentialResolver)
	if err != nil {
		return nil, fmt.Errorf("building channel outbox sender: %w", err)
	}

	dispatcher := channels.NewOutboxDispatcher(store, sender, channels.OutboxDispatcherConfig{
		ClaimBatchSize:    cfg.Outbox.ClaimBatchSize,
		RecoveryBatchSize: cfg.Outbox.RecoveryBatchSize,
		LockTimeout:       time.Duration(cfg.Outbox.LockTimeoutSeconds) * time.Second,
		MaxAttempts:       cfg.Outbox.MaxAttempts,
		BaseRetryDelay:    time.Duration(cfg.Outbox.BaseRetrySeconds) * time.Second,
		MaxRetryDelay:     time.Duration(cfg.Outbox.MaxRetrySeconds) * time.Second,
		JitterFraction:    cfg.Outbox.JitterFraction,
	})
	recoveryBatchSize := cfg.Outbox.RecoveryBatchSize
	if recoveryBatchSize <= 0 {
		recoveryBatchSize = cfg.Outbox.ClaimBatchSize
	}
	if recoveryBatchSize <= 0 {
		recoveryBatchSize = 10
	}
	recoveryMaxAttempts := cfg.Outbox.MaxAttempts
	if recoveryMaxAttempts <= 0 {
		recoveryMaxAttempts = 5
	}

	return &channelOutboxWorker{
		pool:                pool,
		store:               store,
		dispatcher:          dispatcher,
		pollInterval:        pollInterval,
		tenantScanPageSize:  tenantScanPageSize,
		recoveryBatchSize:   recoveryBatchSize,
		recoveryMaxAttempts: recoveryMaxAttempts,
	}, nil
}

func (w *channelOutboxWorker) Run(ctx context.Context) error {
	if w == nil || w.pool == nil || w.store == nil || w.dispatcher == nil {
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
	tenantIDs, err := listTenantIDs(ctx, w.pool, w.tenantScanPageSize)
	if err != nil {
		slog.Error("channel outbox worker failed to list tenants", "error", err)
		return
	}
	recoveryBatchSize := w.recoveryBatchSize
	if recoveryBatchSize <= 0 {
		recoveryBatchSize = 1
	}
	recoveryMaxAttempts := w.recoveryMaxAttempts
	if recoveryMaxAttempts <= 0 {
		recoveryMaxAttempts = 5
	}

	for _, tenantID := range tenantIDs {
		if ctx.Err() != nil {
			return
		}

		tenantErr := database.WithTenantConnection(ctx, w.pool, tenantID, func(ctx context.Context, q database.Querier) error {
			totalRecovered := 0
			for {
				recovered, recoverErr := w.store.RecoverDispatchFailuresToOutbox(
					ctx,
					q,
					recoveryBatchSize,
					recoveryMaxAttempts,
				)
				if recoverErr != nil {
					return recoverErr
				}
				totalRecovered += recovered
				if recovered < recoveryBatchSize {
					break
				}
			}
			if totalRecovered > 0 {
				slog.Info(
					"channel outbox worker recovered dispatch failures",
					"tenant_id", tenantID,
					"recovered_rows", totalRecovered,
				)
			}

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

func listTenantIDs(ctx context.Context, pool *database.Pool, pageSize int) ([]string, error) {
	if pageSize <= 0 {
		return nil, fmt.Errorf("tenant scan page size must be positive")
	}

	tenantIDs := make([]string, 0, pageSize)
	var cursor uuid.UUID
	hasCursor := false

	for {
		var (
			rows pgx.Rows
			err  error
		)
		if hasCursor {
			rows, err = pool.Query(ctx,
				`SELECT id::text
				 FROM tenants
				 WHERE id > $1
				 ORDER BY id ASC
				 LIMIT $2`,
				cursor,
				pageSize,
			)
		} else {
			rows, err = pool.Query(ctx,
				`SELECT id::text
				 FROM tenants
				 ORDER BY id ASC
				 LIMIT $1`,
				pageSize,
			)
		}
		if err != nil {
			return nil, err
		}

		pageCount := 0
		lastCursor := cursor
		for rows.Next() {
			var tenantID string
			if scanErr := rows.Scan(&tenantID); scanErr != nil {
				rows.Close()
				return nil, scanErr
			}
			parsedID, parseErr := uuid.Parse(tenantID)
			if parseErr != nil {
				rows.Close()
				return nil, fmt.Errorf("parsing tenant id: %w", parseErr)
			}
			tenantIDs = append(tenantIDs, tenantID)
			lastCursor = parsedID
			pageCount++
		}
		if rowsErr := rows.Err(); rowsErr != nil {
			rows.Close()
			return nil, rowsErr
		}
		rows.Close()

		if pageCount < pageSize {
			break
		}
		cursor = lastCursor
		hasCursor = true
	}

	return tenantIDs, nil
}
