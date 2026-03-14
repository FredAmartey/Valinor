package main

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/approvals"
	"github.com/valinor-ai/valinor/internal/channels"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

type fakeApprovalCreator struct {
	params approvals.CreateParams
}

func (f *fakeApprovalCreator) Create(_ context.Context, _ database.Querier, params approvals.CreateParams) (*approvals.Request, error) {
	f.params = params
	return &approvals.Request{ID: uuid.New(), TenantID: params.TenantID, Status: approvals.StatusPending}, nil
}

func TestChannelOutboxReviewSink_CreateReviewUsesTenantScopeAndRedactsFindings(t *testing.T) {
	tenantID := uuid.MustParse("00000000-0000-4000-8000-000000000123")
	outboxID := uuid.New()
	creator := &fakeApprovalCreator{}
	sink := &channelOutboxReviewSink{store: creator}

	err := sink.CreateReview(context.Background(), nil, channels.OutboundReviewRequest{
		TenantID:  tenantID,
		OutboxID:  outboxID,
		Provider:  "slack",
		Recipient: "C123",
		Report: channels.OutboundScanReport{
			Findings: []channels.OutboundScanFinding{{
				Category: "secret_leak",
				Path:     "payload.content",
				Preview:  "sk_live_123",
				Action:   channels.OutboundActionBlock,
			}},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, tenantID, creator.params.TenantID)
	assert.Equal(t, &outboxID, creator.params.ChannelOutboxID)
	findings, ok := creator.params.Metadata["findings"].([]channels.OutboundScanFinding)
	require.True(t, ok)
	require.Len(t, findings, 1)
	assert.Empty(t, findings[0].Preview)
}
