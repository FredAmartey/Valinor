package activity

import (
	"context"
	"time"

	"github.com/google/uuid"
)

const (
	KindPromptReceived    = "prompt.received"
	KindRunStarted        = "run.started"
	KindRunFailed         = "run.failed"
	KindRunYielded        = "run.yielded"
	KindRunCompleted      = "run.completed"
	KindRuntimeEvent      = "runtime.event"
	KindToolCalled        = "tool.called"
	KindToolBlocked       = "tool.blocked"
	KindConnectorCalled   = "connector.called"
	KindConnectorBlocked  = "connector.blocked"
	KindApprovalRequested = "approval.requested"
	KindApprovalResolved  = "approval.resolved"
	KindChannelReceived   = "channel.received"
	KindChannelSent       = "channel.sent"
	KindChannelRetry      = "channel.retry"
	KindChannelFailed     = "channel.failed"
	KindSecurityFlagged   = "security.flagged"
	KindMemoryAccessed    = "memory.accessed"
	KindMemoryBlocked     = "memory.blocked"
)

const (
	StatusAllowed          = "allowed"
	StatusBlocked          = "blocked"
	StatusFlagged          = "flagged"
	StatusHalted           = "halted"
	StatusApprovalRequired = "approval_required"
	StatusPending          = "pending"
	StatusSent             = "sent"
	StatusFailed           = "failed"
	StatusCompleted        = "completed"
)

const (
	RiskClassExternalWrites         = "external_writes"
	RiskClassDestructiveActions     = "destructive_actions"
	RiskClassSensitiveDataAccess    = "sensitive_data_access"
	RiskClassChannelSends           = "channel_sends"
	RiskClassCredentialedThirdParty = "credentialed_third_party_actions" // #nosec G101 -- policy label, not a credential
	RiskClassCrossScopeMemoryAccess = "cross_scope_memory_access"
)

const (
	ProvenanceControlPlaneHTTP   = "control_plane_http"
	ProvenanceControlPlaneOutbox = "control_plane_outbox"
	ProvenanceRuntimeVsock       = "runtime_vsock"
	ProvenanceChannelIngress     = "channel_ingress"
)

// SensitiveContentRef points to sensitive payloads stored elsewhere.
type SensitiveContentRef struct {
	Store   string `json:"store"`
	Key     string `json:"key"`
	Preview string `json:"preview,omitempty"`
}

// Event is the append-only behavior record used by timelines and security views.
type Event struct {
	ID                  uuid.UUID            `json:"id,omitempty"`
	TenantID            uuid.UUID            `json:"tenant_id"`
	AgentID             *uuid.UUID           `json:"agent_id,omitempty"`
	UserID              *uuid.UUID           `json:"user_id,omitempty"`
	DepartmentID        *uuid.UUID           `json:"department_id,omitempty"`
	SessionID           string               `json:"session_id,omitempty"`
	CorrelationID       string               `json:"correlation_id,omitempty"`
	ApprovalID          *uuid.UUID           `json:"approval_id,omitempty"`
	ConnectorID         *uuid.UUID           `json:"connector_id,omitempty"`
	ChannelMessageID    *uuid.UUID           `json:"channel_message_id,omitempty"`
	Kind                string               `json:"kind"`
	Status              string               `json:"status"`
	RiskClass           string               `json:"risk_class,omitempty"`
	Source              string               `json:"source"`
	Provenance          string               `json:"provenance,omitempty"`
	InternalEventType   string               `json:"internal_event_type,omitempty"`
	Binding             string               `json:"binding,omitempty"`
	DeliveryTarget      string               `json:"delivery_target,omitempty"`
	RuntimeSource       string               `json:"runtime_source,omitempty"`
	Title               string               `json:"title"`
	Summary             string               `json:"summary"`
	ActorLabel          string               `json:"actor_label,omitempty"`
	TargetLabel         string               `json:"target_label,omitempty"`
	SensitiveContentRef *SensitiveContentRef `json:"sensitive_content_ref,omitempty"`
	Metadata            map[string]any       `json:"metadata,omitempty"`
	OccurredAt          time.Time            `json:"occurred_at"`
	CompletedAt         *time.Time           `json:"completed_at,omitempty"`
	CreatedAt           time.Time            `json:"created_at,omitempty"`
}

// Logger is the non-blocking activity logging interface.
type Logger interface {
	Log(ctx context.Context, event Event)
	Close() error
}

// NopLogger disables activity logging.
type NopLogger struct{}

func (NopLogger) Log(context.Context, Event) {}
func (NopLogger) Close() error               { return nil }
