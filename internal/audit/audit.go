package audit

import (
	"context"

	"github.com/google/uuid"
	"github.com/valinor-ai/valinor/internal/auth"
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
	// CRUD actions
	ActionUserCreated      = "user.created"
	ActionUserUpdated      = "user.updated"
	ActionUserSuspended    = "user.suspended"
	ActionUserReactivated  = "user.reactivated"

	ActionAgentProvisioned = "agent.provisioned"
	ActionAgentUpdated     = "agent.updated"
	ActionAgentDestroyed   = "agent.destroyed"

	ActionTenantCreated    = "tenant.created"
	ActionTenantUpdated    = "tenant.updated"
	ActionTenantSuspended  = "tenant.suspended"

	ActionDepartmentCreated = "department.created"
	ActionDepartmentUpdated = "department.updated"
	ActionDepartmentDeleted = "department.deleted"

	ActionRoleCreated = "role.created"
	ActionRoleUpdated = "role.updated"
	ActionRoleDeleted = "role.deleted"

	ActionUserRoleAssigned = "user_role.assigned"
	ActionUserRoleRevoked  = "user_role.revoked"
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

// ActorIDFromContext extracts the authenticated user's UUID from the
// request context, returning nil if no identity is present or the
// user ID is not a valid UUID.
func ActorIDFromContext(ctx context.Context) *uuid.UUID {
	identity := auth.GetIdentity(ctx)
	if identity == nil {
		return nil
	}
	uid, err := uuid.Parse(identity.UserID)
	if err != nil {
		return nil
	}
	return &uid
}
