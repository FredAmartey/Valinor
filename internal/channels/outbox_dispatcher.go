package channels

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/valinor-ai/valinor/internal/activity"
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
	MarkOutboxPendingApproval(ctx context.Context, q database.Querier, outboxID uuid.UUID, lastError string) error
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
	store      outboxStore
	sender     OutboxSender
	cfg        OutboxDispatcherConfig
	now        func() time.Time
	jitter     func() float64
	scanner    OutboundScanner
	reviewSink OutboundReviewSink
	activity   activity.Logger
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

func (d *OutboxDispatcher) WithScanner(scanner OutboundScanner) *OutboxDispatcher {
	if d == nil {
		return nil
	}
	d.scanner = scanner
	return d
}

func (d *OutboxDispatcher) WithReviewSink(reviewSink OutboundReviewSink) *OutboxDispatcher {
	if d == nil {
		return nil
	}
	d.reviewSink = reviewSink
	return d
}

func (d *OutboxDispatcher) WithActivityLogger(logger activity.Logger) *OutboxDispatcher {
	if d == nil {
		return nil
	}
	d.activity = logger
	return d
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
			if report, handled, err := d.applyOutboundScan(ctx, q, job); err != nil {
				return processed, err
			} else if handled {
				processed++
				_ = report
				continue
			}

			if err := d.sender.Send(ctx, job); err != nil {
				errText := strings.TrimSpace(err.Error())
				if errText == "" {
					errText = "provider send failed"
				}

				if IsOutboxPermanentError(err) {
					if deadErr := d.store.MarkOutboxDead(ctx, q, job.ID, errText); deadErr != nil {
						return processed, fmt.Errorf("marking outbox dead: %w", deadErr)
					}
					d.logEvent(ctx, job, activity.KindChannelFailed, activity.StatusFailed, "Outbound delivery failed", errText, map[string]any{"phase": "delivery"})
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

				retryDelay := d.retryDelay(attemptsAfter)
				if retryAfter, ok := OutboxRetryAfter(err); ok && retryAfter > retryDelay {
					retryDelay = retryAfter
				}
				if retryDelay > d.cfg.MaxRetryDelay {
					retryDelay = d.cfg.MaxRetryDelay
				}
				nextAttempt := now.Add(retryDelay)
				if retryErr := d.store.MarkOutboxRetry(ctx, q, job.ID, nextAttempt, errText); retryErr != nil {
					return processed, fmt.Errorf("marking outbox retry: %w", retryErr)
				}
				d.logEvent(ctx, job, activity.KindChannelRetry, activity.StatusFlagged, "Outbound delivery scheduled for retry", errText, map[string]any{"next_attempt_at": nextAttempt})
				processed++
				continue
			}

			if err := d.store.MarkOutboxSent(ctx, q, job.ID); err != nil {
				return processed, fmt.Errorf("marking outbox sent: %w", err)
			}
			d.logEvent(ctx, job, activity.KindChannelSent, activity.StatusSent, "Outbound delivery sent", "Delivery reached the provider queue.", nil)
			processed++
		}
	}
}

func (d *OutboxDispatcher) applyOutboundScan(ctx context.Context, q database.Querier, job ChannelOutbox) (OutboundScanReport, bool, error) {
	if d == nil || d.scanner == nil {
		return OutboundScanReport{}, false, nil
	}

	report, err := d.scanner.Scan(ctx, job)
	if err != nil {
		return OutboundScanReport{}, false, fmt.Errorf("scanning outbound payload: %w", err)
	}

	if finding, ok := report.FirstByAction(OutboundActionBlock); ok {
		lastError := fmt.Sprintf("blocked by outbound scan: %s (%s)", finding.Category, finding.Path)
		if err := d.store.MarkOutboxDead(ctx, q, job.ID, lastError); err != nil {
			return report, false, fmt.Errorf("marking outbox blocked: %w", err)
		}
		d.logEvent(ctx, job, activity.KindSecurityFlagged, activity.StatusBlocked, "Outbound delivery blocked", lastError, map[string]any{"findings": redactedFindings(report.Findings)})
		return report, true, nil
	}

	if finding, ok := report.FirstByAction(OutboundActionReview); ok {
		lastError := fmt.Sprintf("review required by outbound scan: %s (%s)", finding.Category, finding.Path)
		if d.reviewSink == nil {
			return report, false, fmt.Errorf("review required by outbound scan but no review sink is configured")
		}
		if err := d.reviewSink.CreateReview(ctx, q, OutboundReviewRequest{
			TenantID:  job.TenantID,
			OutboxID:  job.ID,
			Provider:  job.Provider,
			Recipient: job.RecipientID,
			Report:    report,
		}); err != nil {
			return report, false, fmt.Errorf("creating outbound review: %w", err)
		}
		if err := d.store.MarkOutboxPendingApproval(ctx, q, job.ID, lastError); err != nil {
			return report, false, fmt.Errorf("marking outbox pending approval: %w", err)
		}
		d.logEvent(ctx, job, activity.KindSecurityFlagged, activity.StatusApprovalRequired, "Outbound delivery queued for review", lastError, map[string]any{"findings": redactedFindings(report.Findings)})
		return report, true, nil
	}

	return report, false, nil
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

func (d *OutboxDispatcher) logEvent(ctx context.Context, job ChannelOutbox, kind, status, title, summary string, metadata map[string]any) {
	if d == nil || d.activity == nil {
		return
	}
	event := activity.Event{
		TenantID:          job.TenantID,
		ChannelMessageID:  &job.ChannelMessageID,
		Kind:              kind,
		Status:            status,
		Source:            "channels",
		Provenance:        activity.ProvenanceControlPlaneOutbox,
		InternalEventType: "channel_outbox",
		Binding:           strings.ToLower(strings.TrimSpace(job.Provider)),
		DeliveryTarget:    strings.TrimSpace(job.RecipientID),
		RuntimeSource:     "channel_outbox",
		Title:             title,
		Summary:           summary,
		OccurredAt:        d.now().UTC(),
		Metadata:          metadata,
	}
	if event.Kind == activity.KindSecurityFlagged {
		event.RiskClass = activity.RiskClassChannelSends
	}
	if correlationID := correlationIDFromPayload(job.Payload); correlationID != "" {
		event.CorrelationID = correlationID
	}
	d.activity.Log(ctx, event)
}

func correlationIDFromPayload(payload []byte) string {
	if len(payload) == 0 {
		return ""
	}
	var parsed map[string]any
	if err := json.Unmarshal(payload, &parsed); err != nil {
		return ""
	}
	value, _ := parsed["correlation_id"].(string)
	value = strings.TrimSpace(value)
	if len(value) > 128 {
		return value[:128]
	}
	return value
}

func redactedFindings(findings []OutboundScanFinding) []OutboundScanFinding {
	if len(findings) == 0 {
		return nil
	}
	redacted := make([]OutboundScanFinding, len(findings))
	for i, finding := range findings {
		finding.Preview = ""
		redacted[i] = finding
	}
	return redacted
}
