package audit

import (
	"context"

	"github.com/google/uuid"
)

// Event represents a single auditable action in the system.
type Event struct {
	TenantID     uuid.UUID
	UserID       *uuid.UUID // nil for system events
	Action       string     // e.g. "message.sent", "tool.blocked", "access.denied"
	ResourceType string     // e.g. "agent", "user", "connector"
	ResourceID   *uuid.UUID
	Metadata     map[string]any
	Source       string // "api", "whatsapp", "system"
}

const (
	ActionChannelMessageAccepted          = "channel.message.accepted"
	ActionChannelMessageDuplicate         = "channel.message.duplicate"
	ActionChannelMessageReplayBlocked     = "channel.message.replay_blocked"
	ActionChannelWebhookRejectedSignature = "channel.webhook.rejected_signature"
	ActionChannelActionDeniedUnverified   = "channel.action_denied_unverified"
)

const (
	MetadataCorrelationID   = "correlation_id"
	MetadataDecision        = "decision"
	MetadataIdempotencyKey  = "idempotency_key"
	MetadataPlatformMessage = "platform_message_id"
)

// Logger is the audit logging interface. Log is fire-and-forget.
type Logger interface {
	Log(ctx context.Context, event Event)
	Close() error
}

// NopLogger is a no-op audit logger for testing and when audit is disabled.
type NopLogger struct{}

func (NopLogger) Log(context.Context, Event) {}
func (NopLogger) Close() error               { return nil }
