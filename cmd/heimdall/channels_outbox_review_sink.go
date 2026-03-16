package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/FredAmartey/heimdall/internal/approvals"
	"github.com/FredAmartey/heimdall/internal/channels"
	"github.com/FredAmartey/heimdall/internal/platform/database"
)

type approvalCreator interface {
	Create(ctx context.Context, q database.Querier, params approvals.CreateParams) (*approvals.Request, error)
}

type channelOutboxReviewSink struct {
	store approvalCreator
}

func (s *channelOutboxReviewSink) CreateReview(ctx context.Context, q database.Querier, request channels.OutboundReviewRequest) error {
	if s == nil || s.store == nil {
		return fmt.Errorf("approval store is not configured")
	}

	provider := strings.ToLower(strings.TrimSpace(request.Provider))
	recipient := strings.TrimSpace(request.Recipient)

	_, err := s.store.Create(ctx, q, approvals.CreateParams{
		TenantID:        request.TenantID,
		ChannelOutboxID: &request.OutboxID,
		RiskClass:       "channel_sends",
		TargetType:      "channel_delivery",
		TargetLabel:     fmt.Sprintf("%s:%s", provider, recipient),
		ActionSummary:   "Review outbound delivery before it reaches the external channel.",
		Metadata: map[string]any{
			"provider":  provider,
			"recipient": recipient,
			"findings":  redactFindings(request.Report.Findings),
		},
	})
	if err != nil {
		return fmt.Errorf("creating approval request: %w", err)
	}
	return nil
}

func redactFindings(findings []channels.OutboundScanFinding) []channels.OutboundScanFinding {
	if len(findings) == 0 {
		return nil
	}
	redacted := make([]channels.OutboundScanFinding, len(findings))
	for i, finding := range findings {
		finding.Preview = ""
		redacted[i] = finding
	}
	return redacted
}
