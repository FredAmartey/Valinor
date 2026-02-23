package channels

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/audit"
)

type captureAuditLogger struct {
	events []audit.Event
}

func (l *captureAuditLogger) Log(_ context.Context, event audit.Event) {
	l.events = append(l.events, event)
}

func (l *captureAuditLogger) Close() error { return nil }

func TestChannelAudit_RejectedSignature(t *testing.T) {
	logger := &captureAuditLogger{}
	guard := NewIngressGuard(
		stubVerifier{verifyErr: ErrInvalidSignature},
		24*time.Hour,
		func(_ context.Context, _, _ string) (*ChannelLink, error) { return nil, nil },
		func(_ context.Context, _ IngressMessage) (bool, error) { return true, nil },
	).WithAuditLogger(logger)

	_, err := guard.Process(context.Background(), IngressMessage{
		Platform:           "whatsapp",
		PlatformUserID:     "+15550001111",
		PlatformMessageID:  "wamid.sig",
		IdempotencyKey:     "idem-sig",
		PayloadFingerprint: "fp-sig",
		CorrelationID:      "corr-sig",
		Headers:            http.Header{},
		Body:               []byte(`{}`),
		OccurredAt:         time.Now(),
	})
	require.ErrorIs(t, err, ErrInvalidSignature)
	require.Len(t, logger.events, 1)

	evt := logger.events[0]
	assert.Equal(t, audit.ActionChannelWebhookRejectedSignature, evt.Action)
	assert.Equal(t, "whatsapp", evt.Source)
	assert.Equal(t, "corr-sig", evt.Metadata[audit.MetadataCorrelationID])
	assert.Equal(t, string(IngressRejectedSignature), evt.Metadata[audit.MetadataDecision])
}

func TestChannelAudit_DuplicateAndReplay(t *testing.T) {
	t.Run("duplicate logs duplicate decision metadata", func(t *testing.T) {
		logger := &captureAuditLogger{}
		tenantID := uuid.New()
		userID := uuid.New()

		guard := NewIngressGuard(
			stubVerifier{},
			24*time.Hour,
			func(_ context.Context, _, _ string) (*ChannelLink, error) {
				return &ChannelLink{
					TenantID: tenantID,
					UserID:   userID,
					State:    LinkStateVerified,
				}, nil
			},
			func(_ context.Context, _ IngressMessage) (bool, error) {
				return false, nil
			},
		).WithAuditLogger(logger)

		result, err := guard.Process(context.Background(), IngressMessage{
			Platform:           "telegram",
			PlatformUserID:     "tg-1",
			PlatformMessageID:  "tg-msg-1",
			IdempotencyKey:     "idem-dup",
			PayloadFingerprint: "fp-dup",
			CorrelationID:      "corr-dup",
			Headers:            http.Header{},
			Body:               []byte(`{}`),
			OccurredAt:         time.Now(),
		})
		require.NoError(t, err)
		assert.Equal(t, IngressDuplicate, result.Decision)
		require.Len(t, logger.events, 1)
		assert.Equal(t, audit.ActionChannelMessageDuplicate, logger.events[0].Action)
		assert.Equal(t, "corr-dup", logger.events[0].Metadata[audit.MetadataCorrelationID])
		assert.Equal(t, "idem-dup", logger.events[0].Metadata[audit.MetadataIdempotencyKey])
		assert.Equal(t, "tg-msg-1", logger.events[0].Metadata[audit.MetadataPlatformMessage])
	})

	t.Run("replay blocked logs replay decision metadata", func(t *testing.T) {
		logger := &captureAuditLogger{}
		now := time.Unix(1730000000, 0)

		guard := NewIngressGuard(
			stubVerifier{},
			5*time.Minute,
			func(_ context.Context, _, _ string) (*ChannelLink, error) {
				return &ChannelLink{State: LinkStateVerified}, nil
			},
			func(_ context.Context, _ IngressMessage) (bool, error) {
				return true, nil
			},
		).WithAuditLogger(logger)
		guard.now = func() time.Time { return now }

		result, err := guard.Process(context.Background(), IngressMessage{
			Platform:           "slack",
			PlatformUserID:     "U123",
			PlatformMessageID:  "sl-msg-1",
			IdempotencyKey:     "idem-replay",
			PayloadFingerprint: "fp-replay",
			CorrelationID:      "corr-replay",
			Headers:            http.Header{},
			Body:               []byte(`{}`),
			OccurredAt:         now.Add(-10 * time.Minute),
		})
		require.NoError(t, err)
		assert.Equal(t, IngressReplayBlocked, result.Decision)
		require.Len(t, logger.events, 1)
		assert.Equal(t, audit.ActionChannelMessageReplayBlocked, logger.events[0].Action)
		assert.Equal(t, string(IngressReplayBlocked), logger.events[0].Metadata[audit.MetadataDecision])
		assert.Equal(t, "corr-replay", logger.events[0].Metadata[audit.MetadataCorrelationID])
	})
}
