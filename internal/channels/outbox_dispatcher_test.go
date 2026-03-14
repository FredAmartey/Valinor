package channels

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/activity"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

type fakeOutboxStore struct {
	claimBatches   [][]ChannelOutbox
	claimCalls     int
	recoveredJobs  []ChannelOutbox
	recoveredAt    time.Time
	recoveredLimit int

	markSentIDs  []uuid.UUID
	markRetry    []retryCall
	markDead     []deadCall
	markApproval []approvalCall
	callOrder    []string
}

type retryCall struct {
	id          uuid.UUID
	nextAttempt time.Time
	lastError   string
}

type deadCall struct {
	id        uuid.UUID
	lastError string
}

type approvalCall struct {
	id        uuid.UUID
	lastError string
}

func (f *fakeOutboxStore) ClaimPendingOutbox(_ context.Context, _ database.Querier, _ time.Time, _ int) ([]ChannelOutbox, error) {
	f.callOrder = append(f.callOrder, "claim")
	if f.claimCalls >= len(f.claimBatches) {
		return []ChannelOutbox{}, nil
	}
	batch := f.claimBatches[f.claimCalls]
	f.claimCalls++
	return batch, nil
}

func (f *fakeOutboxStore) MarkOutboxSent(_ context.Context, _ database.Querier, outboxID uuid.UUID) error {
	f.markSentIDs = append(f.markSentIDs, outboxID)
	return nil
}

func (f *fakeOutboxStore) MarkOutboxRetry(_ context.Context, _ database.Querier, outboxID uuid.UUID, nextAttempt time.Time, lastError string) error {
	f.markRetry = append(f.markRetry, retryCall{
		id:          outboxID,
		nextAttempt: nextAttempt,
		lastError:   lastError,
	})
	return nil
}

func (f *fakeOutboxStore) MarkOutboxDead(_ context.Context, _ database.Querier, outboxID uuid.UUID, lastError string) error {
	f.markDead = append(f.markDead, deadCall{id: outboxID, lastError: lastError})
	return nil
}

func (f *fakeOutboxStore) MarkOutboxPendingApproval(_ context.Context, _ database.Querier, outboxID uuid.UUID, lastError string) error {
	f.markApproval = append(f.markApproval, approvalCall{id: outboxID, lastError: lastError})
	return nil
}

func (f *fakeOutboxStore) RecoverStaleSending(_ context.Context, _ database.Querier, staleBefore time.Time, limit int) ([]ChannelOutbox, error) {
	f.callOrder = append(f.callOrder, "recover")
	f.recoveredAt = staleBefore
	f.recoveredLimit = limit
	return f.recoveredJobs, nil
}

type fakeOutboxSender struct {
	sendErr map[uuid.UUID]error
	sentIDs []uuid.UUID
}

func (f *fakeOutboxSender) Send(_ context.Context, job ChannelOutbox) error {
	f.sentIDs = append(f.sentIDs, job.ID)
	if err, ok := f.sendErr[job.ID]; ok {
		return err
	}
	return nil
}

type fakeOutboundScanner struct {
	reports map[uuid.UUID]OutboundScanReport
	errs    map[uuid.UUID]error
}

func (f *fakeOutboundScanner) Scan(_ context.Context, job ChannelOutbox) (OutboundScanReport, error) {
	if err, ok := f.errs[job.ID]; ok {
		return OutboundScanReport{}, err
	}
	if report, ok := f.reports[job.ID]; ok {
		return report, nil
	}
	return OutboundScanReport{}, nil
}

type fakeReviewSink struct {
	requests []OutboundReviewRequest
}

func (f *fakeReviewSink) CreateReview(_ context.Context, _ database.Querier, request OutboundReviewRequest) error {
	f.requests = append(f.requests, request)
	return nil
}

type fakeActivityLogger struct {
	events []activity.Event
	ctxs   []context.Context
}

func (f *fakeActivityLogger) Log(ctx context.Context, event activity.Event) {
	f.ctxs = append(f.ctxs, ctx)
	f.events = append(f.events, event)
}

func (f *fakeActivityLogger) Close() error { return nil }

func TestOutboxDispatcher_SendsPendingJob(t *testing.T) {
	jobID := uuid.New()
	store := &fakeOutboxStore{
		claimBatches: [][]ChannelOutbox{
			{
				{ID: jobID, AttemptCount: 0, MaxAttempts: 5},
			},
			{},
		},
	}
	sender := &fakeOutboxSender{sendErr: map[uuid.UUID]error{}}

	dispatcher := NewOutboxDispatcher(store, sender, OutboxDispatcherConfig{
		ClaimBatchSize: 4,
	})
	dispatcher.now = func() time.Time { return time.Date(2026, 2, 23, 6, 0, 0, 0, time.UTC) }

	processed, err := dispatcher.DispatchOnce(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, 1, processed)
	assert.Equal(t, []uuid.UUID{jobID}, sender.sentIDs)
	assert.Equal(t, []uuid.UUID{jobID}, store.markSentIDs)
	assert.Empty(t, store.markRetry)
	assert.Empty(t, store.markDead)
	assert.Empty(t, store.markApproval)
}

func TestOutboxDispatcher_BlocksDeterministicOutboundFindings(t *testing.T) {
	jobID := uuid.New()
	store := &fakeOutboxStore{
		claimBatches: [][]ChannelOutbox{
			{{
				ID:          jobID,
				Provider:    "slack",
				RecipientID: "C123",
				Payload:     json.RawMessage(`{"content":"send secret sk_live_123"}`),
				MaxAttempts: 5,
			}},
			{},
		},
	}
	sender := &fakeOutboxSender{sendErr: map[uuid.UUID]error{}}
	scanner := &fakeOutboundScanner{
		reports: map[uuid.UUID]OutboundScanReport{
			jobID: {
				Findings: []OutboundScanFinding{{
					Category: "secret_leak",
					Path:     "content",
					Preview:  "sk_live_123",
					Action:   OutboundActionBlock,
				}},
			},
		},
	}

	dispatcher := NewOutboxDispatcher(store, sender, OutboxDispatcherConfig{ClaimBatchSize: 1})
	dispatcher.scanner = scanner

	processed, err := dispatcher.DispatchOnce(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, 1, processed)
	assert.Empty(t, sender.sentIDs)
	require.Len(t, store.markDead, 1)
	assert.Contains(t, store.markDead[0].lastError, "secret_leak")
	assert.Empty(t, store.markApproval)
}

func TestOutboxDispatcher_QueuesAmbiguousFindingsForReview(t *testing.T) {
	jobID := uuid.New()
	store := &fakeOutboxStore{
		claimBatches: [][]ChannelOutbox{
			{{
				ID:          jobID,
				Provider:    "telegram",
				RecipientID: "chat-1",
				Payload:     json.RawMessage(`{"content":"customer said call 555-1212"}`),
				MaxAttempts: 5,
			}},
			{},
		},
	}
	sender := &fakeOutboxSender{sendErr: map[uuid.UUID]error{}}
	scanner := &fakeOutboundScanner{
		reports: map[uuid.UUID]OutboundScanReport{
			jobID: {
				Findings: []OutboundScanFinding{{
					Category: "pii",
					Path:     "content",
					Preview:  "555-1212",
					Action:   OutboundActionReview,
				}},
			},
		},
	}
	reviews := &fakeReviewSink{}

	dispatcher := NewOutboxDispatcher(store, sender, OutboxDispatcherConfig{ClaimBatchSize: 1})
	dispatcher.scanner = scanner
	dispatcher.reviewSink = reviews

	processed, err := dispatcher.DispatchOnce(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, 1, processed)
	assert.Empty(t, sender.sentIDs)
	require.Len(t, store.markApproval, 1)
	require.Len(t, reviews.requests, 1)
	assert.Equal(t, jobID, reviews.requests[0].OutboxID)
	assert.Equal(t, "telegram", reviews.requests[0].Provider)
	assert.Empty(t, store.markDead)
}

func TestOutboxDispatcher_ReviewFindingWithoutReviewSinkReturnsError(t *testing.T) {
	jobID := uuid.New()
	store := &fakeOutboxStore{
		claimBatches: [][]ChannelOutbox{
			{{
				ID:          jobID,
				Provider:    "telegram",
				RecipientID: "chat-1",
				Payload:     json.RawMessage(`{"content":"customer said call 555-1212"}`),
				MaxAttempts: 5,
			}},
		},
	}
	sender := &fakeOutboxSender{sendErr: map[uuid.UUID]error{}}
	scanner := &fakeOutboundScanner{
		reports: map[uuid.UUID]OutboundScanReport{
			jobID: {
				Findings: []OutboundScanFinding{{
					Category: "pii",
					Path:     "content",
					Preview:  "555-1212",
					Action:   OutboundActionReview,
				}},
			},
		},
	}

	dispatcher := NewOutboxDispatcher(store, sender, OutboxDispatcherConfig{ClaimBatchSize: 1})
	dispatcher.scanner = scanner

	processed, err := dispatcher.DispatchOnce(context.Background(), nil)
	require.Error(t, err)
	assert.Equal(t, 0, processed)
	assert.Empty(t, store.markApproval)
	assert.Empty(t, store.markDead)
	assert.Empty(t, sender.sentIDs)
}

func TestOutboxDispatcher_RedactsScanPreviewInActivityLog(t *testing.T) {
	jobID := uuid.New()
	store := &fakeOutboxStore{
		claimBatches: [][]ChannelOutbox{
			{{
				ID:               jobID,
				TenantID:         uuid.MustParse("00000000-0000-4000-8000-000000000123"),
				ChannelMessageID: uuid.New(),
				Provider:         "slack",
				RecipientID:      "C123",
				Payload:          json.RawMessage(`{"content":"send secret sk_live_123","correlation_id":"corr-123"}`),
				MaxAttempts:      5,
			}},
			{},
		},
	}
	sender := &fakeOutboxSender{sendErr: map[uuid.UUID]error{}}
	scanner := &fakeOutboundScanner{
		reports: map[uuid.UUID]OutboundScanReport{
			jobID: {
				Findings: []OutboundScanFinding{{
					Category: "secret_leak",
					Path:     "content",
					Preview:  "sk_live_123",
					Action:   OutboundActionBlock,
				}},
			},
		},
	}
	activityLogger := &fakeActivityLogger{}

	dispatcher := NewOutboxDispatcher(store, sender, OutboxDispatcherConfig{ClaimBatchSize: 1})
	dispatcher.scanner = scanner
	dispatcher.activity = activityLogger

	processed, err := dispatcher.DispatchOnce(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, 1, processed)
	require.Len(t, activityLogger.events, 1)
	findings, ok := activityLogger.events[0].Metadata["findings"].([]OutboundScanFinding)
	require.True(t, ok)
	require.Len(t, findings, 1)
	assert.Empty(t, findings[0].Preview)
	assert.Equal(t, "corr-123", activityLogger.events[0].CorrelationID)
}

func TestOutboxDispatcher_ScannerErrorAbortsDispatch(t *testing.T) {
	jobID := uuid.New()
	store := &fakeOutboxStore{
		claimBatches: [][]ChannelOutbox{
			{{ID: jobID, Provider: "slack", RecipientID: "C123", Payload: json.RawMessage(`{"content":"hello"}`), MaxAttempts: 5}},
		},
	}
	sender := &fakeOutboxSender{sendErr: map[uuid.UUID]error{}}
	scanner := &fakeOutboundScanner{
		errs: map[uuid.UUID]error{
			jobID: errors.New("scanner unavailable"),
		},
	}

	dispatcher := NewOutboxDispatcher(store, sender, OutboxDispatcherConfig{ClaimBatchSize: 1})
	dispatcher.scanner = scanner

	processed, err := dispatcher.DispatchOnce(context.Background(), nil)
	require.Error(t, err)
	assert.Equal(t, 0, processed)
	assert.Empty(t, sender.sentIDs)
	assert.Empty(t, store.markDead)
	assert.Empty(t, store.markApproval)
}

func TestOutboxDispatcher_PreservesDispatchContextInActivityLog(t *testing.T) {
	jobID := uuid.New()
	store := &fakeOutboxStore{
		claimBatches: [][]ChannelOutbox{
			{{
				ID:               jobID,
				TenantID:         uuid.MustParse("00000000-0000-4000-8000-000000000123"),
				ChannelMessageID: uuid.New(),
				Provider:         "slack",
				RecipientID:      "C123",
				Payload:          json.RawMessage(`{"content":"send secret sk_live_123"}`),
				MaxAttempts:      5,
			}},
			{},
		},
	}
	sender := &fakeOutboxSender{sendErr: map[uuid.UUID]error{}}
	scanner := &fakeOutboundScanner{
		reports: map[uuid.UUID]OutboundScanReport{
			jobID: {
				Findings: []OutboundScanFinding{{
					Category: "secret_leak",
					Path:     "content",
					Preview:  "sk_live_123",
					Action:   OutboundActionBlock,
				}},
			},
		},
	}
	activityLogger := &fakeActivityLogger{}

	dispatcher := NewOutboxDispatcher(store, sender, OutboxDispatcherConfig{ClaimBatchSize: 1})
	dispatcher.scanner = scanner
	dispatcher.activity = activityLogger

	type ctxKey string
	ctx := context.WithValue(context.Background(), ctxKey("request_id"), "req-123")

	processed, err := dispatcher.DispatchOnce(ctx, nil)
	require.NoError(t, err)
	assert.Equal(t, 1, processed)
	require.Len(t, activityLogger.ctxs, 1)
	assert.Equal(t, "req-123", activityLogger.ctxs[0].Value(ctxKey("request_id")))
}

func TestOutboxDispatcher_RetriesWithBoundedBackoff(t *testing.T) {
	jobID := uuid.New()
	fixedNow := time.Date(2026, 2, 23, 6, 10, 0, 0, time.UTC)
	store := &fakeOutboxStore{
		claimBatches: [][]ChannelOutbox{
			{
				{ID: jobID, AttemptCount: 1, MaxAttempts: 5},
			},
			{},
		},
	}
	sender := &fakeOutboxSender{
		sendErr: map[uuid.UUID]error{
			jobID: errors.New("provider timeout"),
		},
	}

	dispatcher := NewOutboxDispatcher(store, sender, OutboxDispatcherConfig{
		ClaimBatchSize: 4,
		MaxAttempts:    5,
		BaseRetryDelay: 10 * time.Second,
		MaxRetryDelay:  60 * time.Second,
		JitterFraction: 0.2,
	})
	dispatcher.now = func() time.Time { return fixedNow }
	dispatcher.jitter = func() float64 { return 0.5 }

	processed, err := dispatcher.DispatchOnce(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, 1, processed)
	require.Len(t, store.markRetry, 1)
	assert.Equal(t, jobID, store.markRetry[0].id)
	assert.Equal(t, "provider timeout", store.markRetry[0].lastError)
	assert.WithinDuration(t, fixedNow.Add(20*time.Second), store.markRetry[0].nextAttempt, 5*time.Second)
	assert.Empty(t, store.markSentIDs)
	assert.Empty(t, store.markDead)
}

func TestOutboxDispatcher_UsesRetryAfterWhenGreaterThanBackoff(t *testing.T) {
	jobID := uuid.New()
	fixedNow := time.Date(2026, 2, 24, 0, 20, 0, 0, time.UTC)
	store := &fakeOutboxStore{
		claimBatches: [][]ChannelOutbox{
			{
				{ID: jobID, AttemptCount: 0, MaxAttempts: 5},
			},
			{},
		},
	}
	sender := &fakeOutboxSender{
		sendErr: map[uuid.UUID]error{
			jobID: NewOutboxTransientErrorWithRetryAfter(errors.New("rate limited"), 45*time.Second),
		},
	}

	dispatcher := NewOutboxDispatcher(store, sender, OutboxDispatcherConfig{
		ClaimBatchSize: 2,
		MaxAttempts:    5,
		BaseRetryDelay: 5 * time.Second,
		MaxRetryDelay:  2 * time.Minute,
		JitterFraction: 0,
	})
	dispatcher.now = func() time.Time { return fixedNow }

	processed, err := dispatcher.DispatchOnce(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, 1, processed)
	require.Len(t, store.markRetry, 1)
	assert.Equal(t, jobID, store.markRetry[0].id)
	assert.WithinDuration(t, fixedNow.Add(45*time.Second), store.markRetry[0].nextAttempt, time.Second)
	assert.Empty(t, store.markDead)
}

func TestOutboxDispatcher_UsesBackoffWhenRetryAfterIsSmaller(t *testing.T) {
	jobID := uuid.New()
	fixedNow := time.Date(2026, 2, 24, 0, 25, 0, 0, time.UTC)
	store := &fakeOutboxStore{
		claimBatches: [][]ChannelOutbox{
			{
				{ID: jobID, AttemptCount: 1, MaxAttempts: 5},
			},
			{},
		},
	}
	sender := &fakeOutboxSender{
		sendErr: map[uuid.UUID]error{
			jobID: NewOutboxTransientErrorWithRetryAfter(errors.New("rate limited"), 5*time.Second),
		},
	}

	dispatcher := NewOutboxDispatcher(store, sender, OutboxDispatcherConfig{
		ClaimBatchSize: 2,
		MaxAttempts:    5,
		BaseRetryDelay: 10 * time.Second,
		MaxRetryDelay:  time.Minute,
		JitterFraction: 0,
	})
	dispatcher.now = func() time.Time { return fixedNow }

	processed, err := dispatcher.DispatchOnce(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, 1, processed)
	require.Len(t, store.markRetry, 1)
	// AttemptCount=1 -> attemptsAfter=2 -> backoff=20s should win over Retry-After=5s.
	assert.WithinDuration(t, fixedNow.Add(20*time.Second), store.markRetry[0].nextAttempt, time.Second)
}

func TestOutboxDispatcher_CapsRetryAfterAtMaxRetryDelay(t *testing.T) {
	jobID := uuid.New()
	fixedNow := time.Date(2026, 2, 24, 0, 30, 0, 0, time.UTC)
	store := &fakeOutboxStore{
		claimBatches: [][]ChannelOutbox{
			{
				{ID: jobID, AttemptCount: 0, MaxAttempts: 5},
			},
			{},
		},
	}
	sender := &fakeOutboxSender{
		sendErr: map[uuid.UUID]error{
			jobID: NewOutboxTransientErrorWithRetryAfter(errors.New("rate limited"), 24*time.Hour),
		},
	}

	dispatcher := NewOutboxDispatcher(store, sender, OutboxDispatcherConfig{
		ClaimBatchSize: 2,
		MaxAttempts:    5,
		BaseRetryDelay: 5 * time.Second,
		MaxRetryDelay:  2 * time.Minute,
		JitterFraction: 0,
	})
	dispatcher.now = func() time.Time { return fixedNow }

	processed, err := dispatcher.DispatchOnce(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, 1, processed)
	require.Len(t, store.markRetry, 1)
	assert.WithinDuration(t, fixedNow.Add(2*time.Minute), store.markRetry[0].nextAttempt, time.Second)
}

func TestOutboxDispatcher_DeadLettersAfterMaxAttempts(t *testing.T) {
	jobID := uuid.New()
	store := &fakeOutboxStore{
		claimBatches: [][]ChannelOutbox{
			{
				{ID: jobID, AttemptCount: 4, MaxAttempts: 5},
			},
			{},
		},
	}
	sender := &fakeOutboxSender{
		sendErr: map[uuid.UUID]error{
			jobID: errors.New("provider unavailable"),
		},
	}

	dispatcher := NewOutboxDispatcher(store, sender, OutboxDispatcherConfig{ClaimBatchSize: 2})

	processed, err := dispatcher.DispatchOnce(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, 1, processed)
	require.Len(t, store.markDead, 1)
	assert.Equal(t, jobID, store.markDead[0].id)
	assert.Equal(t, "provider unavailable", store.markDead[0].lastError)
	assert.Empty(t, store.markSentIDs)
	assert.Empty(t, store.markRetry)
}

func TestOutboxDispatcher_PermanentErrorDeadLettersImmediately(t *testing.T) {
	jobID := uuid.New()
	store := &fakeOutboxStore{
		claimBatches: [][]ChannelOutbox{
			{
				{ID: jobID, AttemptCount: 0, MaxAttempts: 5},
			},
			{},
		},
	}
	sender := &fakeOutboxSender{
		sendErr: map[uuid.UUID]error{
			jobID: NewOutboxPermanentError(errors.New("invalid provider credentials")),
		},
	}

	dispatcher := NewOutboxDispatcher(store, sender, OutboxDispatcherConfig{ClaimBatchSize: 2})

	processed, err := dispatcher.DispatchOnce(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, 1, processed)
	require.Len(t, store.markDead, 1)
	assert.Equal(t, jobID, store.markDead[0].id)
	assert.Equal(t, "invalid provider credentials", store.markDead[0].lastError)
	assert.Empty(t, store.markSentIDs)
	assert.Empty(t, store.markRetry)
}

func TestOutboxDispatcher_RecoversStaleSendingBeforeClaim(t *testing.T) {
	fixedNow := time.Date(2026, 2, 23, 6, 20, 0, 0, time.UTC)
	store := &fakeOutboxStore{
		claimBatches: [][]ChannelOutbox{
			{},
		},
	}
	sender := &fakeOutboxSender{sendErr: map[uuid.UUID]error{}}

	dispatcher := NewOutboxDispatcher(store, sender, OutboxDispatcherConfig{
		ClaimBatchSize:    3,
		RecoveryBatchSize: 7,
		LockTimeout:       45 * time.Second,
	})
	dispatcher.now = func() time.Time { return fixedNow }

	processed, err := dispatcher.DispatchOnce(context.Background(), nil)
	require.NoError(t, err)
	assert.Equal(t, 0, processed)
	require.NotEmpty(t, store.callOrder)
	assert.Equal(t, "recover", store.callOrder[0])
	assert.WithinDuration(t, fixedNow.Add(-45*time.Second), store.recoveredAt, time.Second)
	assert.Equal(t, 7, store.recoveredLimit)
	require.GreaterOrEqual(t, len(store.callOrder), 2)
	assert.Equal(t, "claim", store.callOrder[1])
}

func TestOutboxDispatcher_CryptoRandomUnitInterval(t *testing.T) {
	nonZeroSeen := false
	for i := 0; i < 256; i++ {
		v := cryptoRandomUnitFloat64()
		assert.GreaterOrEqual(t, v, 0.0)
		assert.Less(t, v, 1.0)
		if v > 0 {
			nonZeroSeen = true
		}
	}
	assert.True(t, nonZeroSeen)
}
