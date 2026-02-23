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
	ActionChannelWebhookIgnored           = "channel.webhook.ignored"
	ActionChannelWebhookRejectedSignature = "channel.webhook.rejected_signature"
	ActionChannelActionDeniedUnverified   = "channel.action_denied_unverified"
	ActionChannelActionExecuted           = "channel.action_executed"
	ActionChannelActionDeniedRBAC         = "channel.action_denied_rbac"
	ActionChannelActionDeniedNoAgent      = "channel.action_denied_no_agent"
	ActionChannelActionDeniedSentinel     = "channel.action_denied_sentinel"
	ActionChannelActionDispatchFailed     = "channel.action_dispatch_failed"
)

const (
	MetadataCorrelationID   = "correlation_id"
	MetadataDecision        = "decision"
	MetadataIdempotencyKey  = "idempotency_key"
	MetadataPlatformMessage = "platform_message_id"
	MetadataPlatformUserID  = "platform_user_id"
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
