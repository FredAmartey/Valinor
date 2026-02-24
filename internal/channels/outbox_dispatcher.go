package channels

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

// OutboxSender delivers a claimed outbox job to a provider.
type OutboxSender interface {
	Send(ctx context.Context, job ChannelOutbox) error
}

type outboxStore interface {
	ClaimPendingOutbox(ctx context.Context, q database.Querier, now time.Time, limit int) ([]ChannelOutbox, error)
	MarkOutboxSent(ctx context.Context, q database.Querier, outboxID uuid.UUID) error
	MarkOutboxRetry(ctx context.Context, q database.Querier, outboxID uuid.UUID, nextAttempt time.Time, lastError string) error
	MarkOutboxDead(ctx context.Context, q database.Querier, outboxID uuid.UUID, lastError string) error
	RecoverStaleSending(ctx context.Context, q database.Querier, staleBefore time.Time, limit int) ([]ChannelOutbox, error)
}

// OutboxDispatcherConfig controls claim/retry behavior.
type OutboxDispatcherConfig struct {
	ClaimBatchSize    int
	RecoveryBatchSize int
	LockTimeout       time.Duration
	MaxAttempts       int
	BaseRetryDelay    time.Duration
	MaxRetryDelay     time.Duration
	JitterFraction    float64
}

// OutboxDispatcher processes pending outbox jobs using store transitions.
type OutboxDispatcher struct {
	store  outboxStore
	sender OutboxSender
	cfg    OutboxDispatcherConfig
	now    func() time.Time
	jitter func() float64
}

// NewOutboxDispatcher creates a dispatcher with safe defaults.
func NewOutboxDispatcher(store outboxStore, sender OutboxSender, cfg OutboxDispatcherConfig) *OutboxDispatcher {
	if cfg.ClaimBatchSize <= 0 {
		cfg.ClaimBatchSize = 10
	}
	if cfg.RecoveryBatchSize <= 0 {
		cfg.RecoveryBatchSize = cfg.ClaimBatchSize
	}
	if cfg.LockTimeout <= 0 {
		cfg.LockTimeout = 30 * time.Second
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 5
	}
	if cfg.BaseRetryDelay <= 0 {
		cfg.BaseRetryDelay = 5 * time.Second
	}
	if cfg.MaxRetryDelay <= 0 {
		cfg.MaxRetryDelay = 2 * time.Minute
	}
	if cfg.JitterFraction < 0 {
		cfg.JitterFraction = 0
	}
	if cfg.JitterFraction > 1 {
		cfg.JitterFraction = 1
	}

	return &OutboxDispatcher{
		store:  store,
		sender: sender,
		cfg:    cfg,
		now:    time.Now,
		jitter: cryptoRandomUnitFloat64,
	}
}

// DispatchOnce recovers stale locks, claims due jobs, and applies transitions.
func (d *OutboxDispatcher) DispatchOnce(ctx context.Context, q database.Querier) (int, error) {
	now := d.now().UTC()
	if _, err := d.store.RecoverStaleSending(ctx, q, now.Add(-d.cfg.LockTimeout), d.cfg.RecoveryBatchSize); err != nil {
		return 0, fmt.Errorf("recovering stale outbox jobs: %w", err)
	}

	processed := 0
	for {
		claimed, err := d.store.ClaimPendingOutbox(ctx, q, now, d.cfg.ClaimBatchSize)
		if err != nil {
			return processed, fmt.Errorf("claiming pending outbox jobs: %w", err)
		}
		if len(claimed) == 0 {
			return processed, nil
		}

		for _, job := range claimed {
			if err := d.sender.Send(ctx, job); err != nil {
				errText := strings.TrimSpace(err.Error())
				if errText == "" {
					errText = "provider send failed"
				}

				if IsOutboxPermanentError(err) {
					if deadErr := d.store.MarkOutboxDead(ctx, q, job.ID, errText); deadErr != nil {
						return processed, fmt.Errorf("marking outbox dead: %w", deadErr)
					}
					processed++
					continue
				}

				attemptsAfter := job.AttemptCount + 1
				maxAttempts := job.MaxAttempts
				if maxAttempts <= 0 {
					maxAttempts = d.cfg.MaxAttempts
				}

				if attemptsAfter >= maxAttempts {
					if deadErr := d.store.MarkOutboxDead(ctx, q, job.ID, errText); deadErr != nil {
						return processed, fmt.Errorf("marking outbox dead: %w", deadErr)
					}
					processed++
					continue
				}

				nextAttempt := now.Add(d.retryDelay(attemptsAfter))
				if retryErr := d.store.MarkOutboxRetry(ctx, q, job.ID, nextAttempt, errText); retryErr != nil {
					return processed, fmt.Errorf("marking outbox retry: %w", retryErr)
				}
				processed++
				continue
			}

			if err := d.store.MarkOutboxSent(ctx, q, job.ID); err != nil {
				return processed, fmt.Errorf("marking outbox sent: %w", err)
			}
			processed++
		}
	}
}

func (d *OutboxDispatcher) retryDelay(attemptsAfterFailure int) time.Duration {
	if attemptsAfterFailure <= 0 {
		attemptsAfterFailure = 1
	}

	multiplier := math.Pow(2, float64(attemptsAfterFailure-1))
	base := float64(d.cfg.BaseRetryDelay) * multiplier
	delay := time.Duration(base)
	if delay > d.cfg.MaxRetryDelay {
		delay = d.cfg.MaxRetryDelay
	}

	if d.cfg.JitterFraction <= 0 {
		return delay
	}

	jitter := d.jitter()
	if jitter < 0 {
		jitter = 0
	}
	if jitter > 1 {
		jitter = 1
	}
	jittered := time.Duration(float64(delay) * (1 + (d.cfg.JitterFraction * jitter)))
	if jittered > d.cfg.MaxRetryDelay {
		return d.cfg.MaxRetryDelay
	}
	return jittered
}

func cryptoRandomUnitFloat64() float64 {
	var randomBytes [8]byte
	if _, err := cryptorand.Read(randomBytes[:]); err != nil {
		return 0
	}

	const mantissaDenominator = 1 << 53
	// Keep the top 53 bits for uniform mapping into [0, 1).
	mantissa := binary.BigEndian.Uint64(randomBytes[:]) >> 11
	return float64(mantissa) / float64(mantissaDenominator)
}
