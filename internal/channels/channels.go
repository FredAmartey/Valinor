package channels

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

// LinkState represents channel identity verification state.
type LinkState string

const (
	LinkStatePendingVerification LinkState = "pending_verification"
	LinkStateVerified            LinkState = "verified"
	LinkStateRevoked             LinkState = "revoked"
)

const (
	// MessageStatusAccepted marks the first successful processing attempt.
	MessageStatusAccepted = "accepted"
	// MessageStatusExecuted marks accepted messages that successfully dispatched.
	MessageStatusExecuted = "executed"
	// MessageStatusDeniedRBAC marks messages denied by RBAC during execution.
	MessageStatusDeniedRBAC = "denied_rbac"
	// MessageStatusDeniedNoAgent marks messages that had no eligible running agent.
	MessageStatusDeniedNoAgent = "denied_no_agent"
	// MessageStatusDeniedSentinel marks messages blocked by input sentinel.
	MessageStatusDeniedSentinel = "denied_sentinel"
	// MessageStatusDispatchFailed marks accepted messages that failed during dispatch.
	MessageStatusDispatchFailed = "dispatch_failed"
	// MessageStatusDuplicate marks a duplicate delivery that should not re-execute.
	MessageStatusDuplicate = "duplicate"
	// MessageStatusRejectedSignature marks failed authenticity checks.
	MessageStatusRejectedSignature = "rejected_signature"
	// MessageStatusReplayBlocked marks stale/replayed deliveries.
	MessageStatusReplayBlocked = "replay_blocked"
)

// OutboxStatus represents delivery status for a provider-agnostic outbound job.
type OutboxStatus string

const (
	OutboxStatusPending OutboxStatus = "pending"
	OutboxStatusSending OutboxStatus = "sending"
	OutboxStatusSent    OutboxStatus = "sent"
	OutboxStatusDead    OutboxStatus = "dead"
)

// ChannelLink maps an external channel identity to a Valinor user in a tenant.
type ChannelLink struct {
	ID             uuid.UUID `json:"id"`
	TenantID       uuid.UUID `json:"tenant_id"`
	UserID         uuid.UUID `json:"user_id"`
	Platform       string    `json:"platform"`
	PlatformUserID string    `json:"platform_user_id"`
	State          LinkState `json:"state"`
	// Verified mirrors a legacy DB column; State is the source of truth for behavior gates.
	Verified             bool            `json:"verified"`
	CreatedAt            time.Time       `json:"created_at"`
	VerifiedAt           *time.Time      `json:"verified_at,omitempty"`
	RevokedAt            *time.Time      `json:"revoked_at,omitempty"`
	VerificationMethod   string          `json:"verification_method,omitempty"`
	VerificationMetadata json.RawMessage `json:"verification_metadata,omitempty"`
}

// UpsertLinkParams defines input for creating/updating a channel link.
type UpsertLinkParams struct {
	UserID               string
	Platform             string
	PlatformUserID       string
	State                LinkState
	VerificationMethod   string
	VerificationMetadata json.RawMessage
}

// ChannelOutbox stores an outbound delivery job and retry metadata.
type ChannelOutbox struct {
	ID               uuid.UUID       `json:"id"`
	TenantID         uuid.UUID       `json:"tenant_id"`
	ChannelMessageID uuid.UUID       `json:"channel_message_id"`
	Provider         string          `json:"provider"`
	RecipientID      string          `json:"recipient_id"`
	Payload          json.RawMessage `json:"payload"`
	Status           OutboxStatus    `json:"status"`
	AttemptCount     int             `json:"attempt_count"`
	MaxAttempts      int             `json:"max_attempts"`
	NextAttemptAt    time.Time       `json:"next_attempt_at"`
	LastError        *string         `json:"last_error,omitempty"`
	LockedAt         *time.Time      `json:"locked_at,omitempty"`
	SentAt           *time.Time      `json:"sent_at,omitempty"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
}

// EnqueueOutboundParams defines input for inserting an outbox job.
type EnqueueOutboundParams struct {
	ChannelMessageID string
	Provider         string
	RecipientID      string
	Payload          json.RawMessage
	MaxAttempts      int
}

// IsVerified returns whether this link can execute channel actions.
func (l ChannelLink) IsVerified() bool {
	return l.State == LinkStateVerified
}

var (
	ErrLinkNotFound    = errors.New("channel link not found")
	ErrLinkUnverified  = errors.New("channel link is not verified")
	ErrMessageNotFound = errors.New("channel message not found")
	ErrOutboxNotFound  = errors.New("channel outbox job not found")
	ErrPlatformEmpty   = errors.New("platform is required")
	ErrIdentityEmpty   = errors.New("platform user id is required")
	ErrUserIDRequired  = errors.New("user id is required")
	ErrUserNotFound    = errors.New("user not found")
	ErrLinkState       = errors.New("link state is invalid")
	ErrLinkIDRequired  = errors.New("link id is required")
	ErrLinkIDInvalid   = errors.New("link id must be a valid UUID")
	ErrIdempotencyKey  = errors.New("idempotency key is required")
	ErrCorrelationID   = errors.New("correlation id is required")
	ErrFingerprint     = errors.New("payload fingerprint is required")
	ErrExpiryRequired  = errors.New("expiry timestamp is required")
	ErrStatusRequired  = errors.New("status is required")
	ErrPayloadRequired = errors.New("payload is required")
)
