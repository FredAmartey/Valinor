package channels

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/valinor-ai/valinor/internal/audit"
)

// IngressDecision represents the disposition of an inbound channel message.
type IngressDecision string

const (
	IngressAccepted          IngressDecision = "accepted"
	IngressDuplicate         IngressDecision = "duplicate"
	IngressReplayBlocked     IngressDecision = "replay_blocked"
	IngressRejectedSignature IngressDecision = "rejected_signature"
	IngressDeniedUnverified  IngressDecision = "denied_unverified"
	IngressIgnored           IngressDecision = "ignored"
)

// IngressMessage is the normalized inbound webhook payload metadata.
type IngressMessage struct {
	Platform           string
	PlatformUserID     string
	PlatformMessageID  string
	IdempotencyKey     string
	PayloadFingerprint string
	CorrelationID      string
	Headers            http.Header
	Body               []byte
	OccurredAt         time.Time
	ExpiresAt          time.Time
}

// IngressResult captures ingress decision and resolved identity context.
type IngressResult struct {
	Decision IngressDecision
	Link     *ChannelLink
}

type linkResolver func(ctx context.Context, platform, platformUserID string) (*ChannelLink, error)
type idempotencyInserter func(ctx context.Context, msg IngressMessage) (bool, error)

// IngressGuard enforces the ingress security pipeline before execution.
type IngressGuard struct {
	verifier          Verifier
	replayWindow      time.Duration
	resolveLink       linkResolver
	insertIdempotency idempotencyInserter
	auditLogger       audit.Logger
	now               func() time.Time
}

// NewIngressGuard constructs an ingress guard with injected dependencies.
func NewIngressGuard(
	verifier Verifier,
	replayWindow time.Duration,
	resolveLink linkResolver,
	insertIdempotency idempotencyInserter,
) *IngressGuard {
	return &IngressGuard{
		verifier:          verifier,
		replayWindow:      replayWindow,
		resolveLink:       resolveLink,
		insertIdempotency: insertIdempotency,
		now:               time.Now,
	}
}

// WithAuditLogger sets an optional audit logger for ingress decisions.
func (g *IngressGuard) WithAuditLogger(logger audit.Logger) *IngressGuard {
	g.auditLogger = logger
	return g
}

// Verify validates provider authenticity checks without executing link/idempotency stages.
func (g *IngressGuard) Verify(headers http.Header, body []byte) error {
	return g.verifier.Verify(headers, body, g.now())
}

// Process executes the required ingress checks in order:
// signature verification -> link resolution -> verification state -> replay window -> idempotency.
func (g *IngressGuard) Process(ctx context.Context, msg IngressMessage) (IngressResult, error) {
	if err := g.verifier.Verify(msg.Headers, msg.Body, g.now()); err != nil {
		g.logDecision(ctx, msg, IngressRejectedSignature, nil)
		return IngressResult{Decision: IngressRejectedSignature}, err
	}

	link, err := g.resolveLink(ctx, msg.Platform, msg.PlatformUserID)
	if err != nil {
		if errors.Is(err, ErrLinkNotFound) {
			g.logDecision(ctx, msg, IngressDeniedUnverified, nil)
			return IngressResult{Decision: IngressDeniedUnverified}, ErrLinkUnverified
		}
		return IngressResult{}, err
	}
	if !link.IsVerified() {
		g.logDecision(ctx, msg, IngressDeniedUnverified, link)
		return IngressResult{Decision: IngressDeniedUnverified, Link: link}, ErrLinkUnverified
	}

	if g.replayWindow > 0 && !msg.OccurredAt.IsZero() {
		skew := g.now().Sub(msg.OccurredAt)
		if skew > g.replayWindow || skew < -g.replayWindow {
			g.logDecision(ctx, msg, IngressReplayBlocked, link)
			return IngressResult{Decision: IngressReplayBlocked, Link: link}, nil
		}
	}

	firstSeen, err := g.insertIdempotency(ctx, msg)
	if err != nil {
		return IngressResult{}, err
	}
	if !firstSeen {
		g.logDecision(ctx, msg, IngressDuplicate, link)
		return IngressResult{Decision: IngressDuplicate, Link: link}, nil
	}

	g.logDecision(ctx, msg, IngressAccepted, link)
	return IngressResult{Decision: IngressAccepted, Link: link}, nil
}

func (g *IngressGuard) logDecision(ctx context.Context, msg IngressMessage, decision IngressDecision, link *ChannelLink) {
	if g.auditLogger == nil {
		return
	}

	tenantID := uuid.Nil
	var userID *uuid.UUID
	if link != nil {
		tenantID = link.TenantID
		if link.UserID != uuid.Nil {
			u := link.UserID
			userID = &u
		}
	}

	action := audit.ActionChannelMessageAccepted
	switch decision {
	case IngressDuplicate:
		action = audit.ActionChannelMessageDuplicate
	case IngressReplayBlocked:
		action = audit.ActionChannelMessageReplayBlocked
	case IngressRejectedSignature:
		action = audit.ActionChannelWebhookRejectedSignature
	case IngressDeniedUnverified:
		action = audit.ActionChannelActionDeniedUnverified
	}

	g.auditLogger.Log(ctx, audit.Event{
		TenantID:     tenantID,
		UserID:       userID,
		Action:       action,
		ResourceType: "channel_message",
		Metadata: map[string]any{
			audit.MetadataCorrelationID:   msg.CorrelationID,
			audit.MetadataDecision:        string(decision),
			audit.MetadataIdempotencyKey:  msg.IdempotencyKey,
			audit.MetadataPlatformMessage: msg.PlatformMessageID,
		},
		Source: msg.Platform,
	})
}
