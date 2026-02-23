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
	// MessageStatusDuplicate marks a duplicate delivery that should not re-execute.
	MessageStatusDuplicate = "duplicate"
	// MessageStatusRejectedSignature marks failed authenticity checks.
	MessageStatusRejectedSignature = "rejected_signature"
	// MessageStatusReplayBlocked marks stale/replayed deliveries.
	MessageStatusReplayBlocked = "replay_blocked"
)

// ChannelLink maps an external channel identity to a Valinor user in a tenant.
type ChannelLink struct {
	ID                   uuid.UUID       `json:"id"`
	TenantID             uuid.UUID       `json:"tenant_id"`
	UserID               uuid.UUID       `json:"user_id"`
	Platform             string          `json:"platform"`
	PlatformUserID       string          `json:"platform_user_id"`
	State                LinkState       `json:"state"`
	Verified             bool            `json:"verified"`
	CreatedAt            time.Time       `json:"created_at"`
	VerifiedAt           *time.Time      `json:"verified_at,omitempty"`
	RevokedAt            *time.Time      `json:"revoked_at,omitempty"`
	VerificationMethod   string          `json:"verification_method,omitempty"`
	VerificationMetadata json.RawMessage `json:"verification_metadata,omitempty"`
}

// IsVerified returns whether this link can execute channel actions.
func (l ChannelLink) IsVerified() bool {
	return l.State == LinkStateVerified
}

var (
	ErrLinkNotFound   = errors.New("channel link not found")
	ErrPlatformEmpty  = errors.New("platform is required")
	ErrIdentityEmpty  = errors.New("platform user id is required")
	ErrIdempotencyKey = errors.New("idempotency key is required")
	ErrCorrelationID  = errors.New("correlation id is required")
	ErrFingerprint    = errors.New("payload fingerprint is required")
	ErrExpiryRequired = errors.New("expiry timestamp is required")
)
