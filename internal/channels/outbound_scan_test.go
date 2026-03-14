package channels

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStructuredOutboundScanner_ReviewsFullPhoneNumbers(t *testing.T) {
	scanner := NewStructuredOutboundScanner()
	report, err := scanner.Scan(context.Background(), ChannelOutbox{
		ID:      uuid.New(),
		Payload: json.RawMessage(`{"content":"call me at 212-555-0199"}`),
	})
	require.NoError(t, err)
	finding, ok := report.FirstByAction(OutboundActionReview)
	require.True(t, ok)
	assert.Equal(t, "pii", finding.Category)
	assert.Equal(t, "payload.content", finding.Path)
}

func TestStructuredOutboundScanner_DoesNotReviewSevenDigitSequences(t *testing.T) {
	scanner := NewStructuredOutboundScanner()
	report, err := scanner.Scan(context.Background(), ChannelOutbox{
		ID:      uuid.New(),
		Payload: json.RawMessage(`{"content":"ticket 123-4567 was updated"}`),
	})
	require.NoError(t, err)
	_, ok := report.FirstByAction(OutboundActionReview)
	assert.False(t, ok)
}
