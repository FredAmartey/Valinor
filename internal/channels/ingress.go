package channels

import (
	"context"
	"net/http"
	"time"
)

// IngressDecision represents the disposition of an inbound channel message.
type IngressDecision string

const (
	IngressAccepted          IngressDecision = "accepted"
	IngressDuplicate         IngressDecision = "duplicate"
	IngressReplayBlocked     IngressDecision = "replay_blocked"
	IngressRejectedSignature IngressDecision = "rejected_signature"
	IngressDeniedUnverified  IngressDecision = "denied_unverified"
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

// Process executes the required ingress checks in order:
// signature verification -> link resolution -> verification state -> replay window -> idempotency.
func (g *IngressGuard) Process(ctx context.Context, msg IngressMessage) (IngressResult, error) {
	if err := g.verifier.Verify(msg.Headers, msg.Body, g.now()); err != nil {
		return IngressResult{Decision: IngressRejectedSignature}, err
	}

	link, err := g.resolveLink(ctx, msg.Platform, msg.PlatformUserID)
	if err != nil {
		return IngressResult{}, err
	}
	if !link.IsVerified() {
		return IngressResult{Decision: IngressDeniedUnverified, Link: link}, ErrLinkUnverified
	}

	if g.replayWindow > 0 && !msg.OccurredAt.IsZero() {
		if g.now().Sub(msg.OccurredAt) > g.replayWindow {
			return IngressResult{Decision: IngressReplayBlocked, Link: link}, nil
		}
	}

	firstSeen, err := g.insertIdempotency(ctx, msg)
	if err != nil {
		return IngressResult{}, err
	}
	if !firstSeen {
		return IngressResult{Decision: IngressDuplicate, Link: link}, nil
	}

	return IngressResult{Decision: IngressAccepted, Link: link}, nil
}
