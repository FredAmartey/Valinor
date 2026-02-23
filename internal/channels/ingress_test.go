package channels

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubVerifier struct {
	verifyErr error
}

func (s stubVerifier) Verify(_ http.Header, _ []byte, _ time.Time) error {
	return s.verifyErr
}

func TestIngress_RejectsInvalidSignature(t *testing.T) {
	linkLookupCalled := false
	insertCalled := false

	guard := NewIngressGuard(
		stubVerifier{verifyErr: ErrInvalidSignature},
		24*time.Hour,
		func(_ context.Context, _, _ string) (*ChannelLink, error) {
			linkLookupCalled = true
			return nil, nil
		},
		func(_ context.Context, _ IngressMessage) (bool, error) {
			insertCalled = true
			return true, nil
		},
	)

	result, err := guard.Process(context.Background(), IngressMessage{
		Platform:           "whatsapp",
		PlatformUserID:     "+15550001111",
		IdempotencyKey:     "idem-1",
		PayloadFingerprint: "fp-1",
		CorrelationID:      "corr-1",
		Headers:            http.Header{},
		Body:               []byte(`{}`),
		OccurredAt:         time.Now(),
	})
	require.ErrorIs(t, err, ErrInvalidSignature)
	assert.Equal(t, IngressRejectedSignature, result.Decision)
	assert.False(t, linkLookupCalled)
	assert.False(t, insertCalled)
}

func TestIngress_DuplicateMessage_NoReexecution(t *testing.T) {
	insertCalled := false

	guard := NewIngressGuard(
		stubVerifier{},
		24*time.Hour,
		func(_ context.Context, _, _ string) (*ChannelLink, error) {
			return &ChannelLink{State: LinkStateVerified}, nil
		},
		func(_ context.Context, _ IngressMessage) (bool, error) {
			insertCalled = true
			return false, nil
		},
	)

	result, err := guard.Process(context.Background(), IngressMessage{
		Platform:           "whatsapp",
		PlatformUserID:     "+15550001111",
		IdempotencyKey:     "idem-2",
		PayloadFingerprint: "fp-2",
		CorrelationID:      "corr-2",
		Headers:            http.Header{},
		Body:               []byte(`{}`),
		OccurredAt:         time.Now(),
	})
	require.NoError(t, err)
	assert.Equal(t, IngressDuplicate, result.Decision)
	assert.True(t, insertCalled)
}

func TestIngress_ReplayBlocked(t *testing.T) {
	insertCalled := false
	now := time.Unix(1730000000, 0)

	guard := NewIngressGuard(
		stubVerifier{},
		5*time.Minute,
		func(_ context.Context, _, _ string) (*ChannelLink, error) {
			return &ChannelLink{State: LinkStateVerified}, nil
		},
		func(_ context.Context, _ IngressMessage) (bool, error) {
			insertCalled = true
			return true, nil
		},
	)
	guard.now = func() time.Time { return now }

	result, err := guard.Process(context.Background(), IngressMessage{
		Platform:           "whatsapp",
		PlatformUserID:     "+15550001111",
		IdempotencyKey:     "idem-3",
		PayloadFingerprint: "fp-3",
		CorrelationID:      "corr-3",
		Headers:            http.Header{},
		Body:               []byte(`{}`),
		OccurredAt:         now.Add(-10 * time.Minute),
	})
	require.NoError(t, err)
	assert.Equal(t, IngressReplayBlocked, result.Decision)
	assert.False(t, insertCalled)
}

func TestIngress_UnverifiedLinkDenied(t *testing.T) {
	insertCalled := false

	guard := NewIngressGuard(
		stubVerifier{},
		24*time.Hour,
		func(_ context.Context, _, _ string) (*ChannelLink, error) {
			return &ChannelLink{State: LinkStatePendingVerification}, nil
		},
		func(_ context.Context, _ IngressMessage) (bool, error) {
			insertCalled = true
			return true, nil
		},
	)

	result, err := guard.Process(context.Background(), IngressMessage{
		Platform:           "whatsapp",
		PlatformUserID:     "+15550001111",
		IdempotencyKey:     "idem-4",
		PayloadFingerprint: "fp-4",
		CorrelationID:      "corr-4",
		Headers:            http.Header{},
		Body:               []byte(`{}`),
		OccurredAt:         time.Now(),
	})
	require.ErrorIs(t, err, ErrLinkUnverified)
	assert.Equal(t, IngressDeniedUnverified, result.Decision)
	assert.False(t, insertCalled)
}

func TestIngress_VerifiedLinkAccepted(t *testing.T) {
	guard := NewIngressGuard(
		stubVerifier{},
		24*time.Hour,
		func(_ context.Context, _, _ string) (*ChannelLink, error) {
			return &ChannelLink{State: LinkStateVerified}, nil
		},
		func(_ context.Context, _ IngressMessage) (bool, error) {
			return true, nil
		},
	)

	result, err := guard.Process(context.Background(), IngressMessage{
		Platform:           "whatsapp",
		PlatformUserID:     "+15550001111",
		IdempotencyKey:     "idem-5",
		PayloadFingerprint: "fp-5",
		CorrelationID:      "corr-5",
		Headers:            http.Header{},
		Body:               []byte(`{}`),
		OccurredAt:         time.Now(),
	})
	require.NoError(t, err)
	assert.Equal(t, IngressAccepted, result.Decision)
	assert.NotNil(t, result.Link)
	assert.True(t, result.Link.IsVerified())
}
