package activity

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

// Store handles activity event persistence.
type Store struct{}

func NewStore() *Store {
	return &Store{}
}

// InsertBatch writes activity events to the append-only ledger.
func (s *Store) InsertBatch(ctx context.Context, db database.Querier, events []Event) error {
	if len(events) == 0 {
		return nil
	}
	sql, args, err := buildBatchInsert(events)
	if err != nil {
		return fmt.Errorf("building activity batch insert: %w", err)
	}
	if _, err := db.Exec(ctx, sql, args...); err != nil {
		return fmt.Errorf("inserting activity events: %w", err)
	}
	return nil
}

func buildBatchInsert(events []Event) (string, []any, error) {
	const cols = "(" +
		"tenant_id, agent_id, user_id, department_id, session_id, correlation_id, approval_id, connector_id, channel_message_id, " +
		"kind, status, risk_class, source, provenance, internal_event_type, binding, delivery_target, runtime_source, " +
		"title, summary, actor_label, target_label, sensitive_content_ref, metadata, occurred_at, completed_at" +
		")"

	var placeholders []string
	args := make([]any, 0, len(events)*26)

	for i, event := range events {
		base := i * 26
		placeholders = append(placeholders, fmt.Sprintf(
			"($%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d, $%d)",
			base+1, base+2, base+3, base+4, base+5, base+6, base+7, base+8, base+9, base+10, base+11,
			base+12, base+13, base+14, base+15, base+16, base+17, base+18, base+19, base+20, base+21,
			base+22, base+23, base+24, base+25, base+26,
		))

		var (
			sensitiveRefJSON []byte
			metadataJSON     []byte
			err              error
		)
		if event.SensitiveContentRef != nil {
			sensitiveRefJSON, err = json.Marshal(event.SensitiveContentRef)
			if err != nil {
				return "", nil, fmt.Errorf("marshaling sensitive content ref: %w", err)
			}
		}
		if event.Metadata != nil {
			metadataJSON, err = json.Marshal(event.Metadata)
			if err != nil {
				return "", nil, fmt.Errorf("marshaling metadata: %w", err)
			}
		}

		occurredAt := event.OccurredAt
		if occurredAt.IsZero() {
			occurredAt = time.Now().UTC()
		}

		args = append(args,
			event.TenantID,
			event.AgentID,
			event.UserID,
			event.DepartmentID,
			nullableString(event.SessionID),
			nullableString(event.CorrelationID),
			event.ApprovalID,
			event.ConnectorID,
			event.ChannelMessageID,
			event.Kind,
			event.Status,
			nullableString(event.RiskClass),
			event.Source,
			nullableString(event.Provenance),
			nullableString(event.InternalEventType),
			nullableString(event.Binding),
			nullableString(event.DeliveryTarget),
			nullableString(event.RuntimeSource),
			event.Title,
			event.Summary,
			nullableString(event.ActorLabel),
			nullableString(event.TargetLabel),
			sensitiveRefJSON,
			metadataJSON,
			occurredAt,
			event.CompletedAt,
		)
	}

	return fmt.Sprintf("INSERT INTO agent_activity_events %s VALUES %s", cols, strings.Join(placeholders, ", ")), args, nil
}

func nullableString(value string) any {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return value
}

// ListEventsParams defines filters for activity queries.
type ListEventsParams struct {
	TenantID     uuid.UUID
	AgentID      *uuid.UUID
	UserID       *uuid.UUID
	DepartmentID *uuid.UUID
	Kind         *string
	Status       *string
	RiskClass    *string
	Source       *string
	After        *time.Time
	Before       *time.Time
	Limit        int
}

func buildListQuery(params ListEventsParams) (string, []any) {
	return buildListQueryWithExtraConditions(params, nil)
}

func buildListQueryWithExtraConditions(params ListEventsParams, extraConditions []string) (string, []any) {
	var (
		conditions []string
		args       []any
		argN       = 1
	)

	conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argN))
	args = append(args, params.TenantID)
	argN++

	if params.AgentID != nil {
		conditions = append(conditions, fmt.Sprintf("agent_id = $%d", argN))
		args = append(args, *params.AgentID)
		argN++
	}
	if params.UserID != nil {
		conditions = append(conditions, fmt.Sprintf("user_id = $%d", argN))
		args = append(args, *params.UserID)
		argN++
	}
	if params.DepartmentID != nil {
		conditions = append(conditions, fmt.Sprintf("department_id = $%d", argN))
		args = append(args, *params.DepartmentID)
		argN++
	}
	if params.Kind != nil {
		conditions = append(conditions, fmt.Sprintf("kind = $%d", argN))
		args = append(args, *params.Kind)
		argN++
	}
	if params.Status != nil {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argN))
		args = append(args, *params.Status)
		argN++
	}
	if params.RiskClass != nil {
		conditions = append(conditions, fmt.Sprintf("risk_class = $%d", argN))
		args = append(args, *params.RiskClass)
		argN++
	}
	if params.Source != nil {
		conditions = append(conditions, fmt.Sprintf("source = $%d", argN))
		args = append(args, *params.Source)
		argN++
	}
	if params.After != nil {
		conditions = append(conditions, fmt.Sprintf("occurred_at > $%d", argN))
		args = append(args, *params.After)
		argN++
	}
	if params.Before != nil {
		conditions = append(conditions, fmt.Sprintf("occurred_at < $%d", argN))
		args = append(args, *params.Before)
		argN++
	}
	conditions = append(conditions, extraConditions...)

	sql := fmt.Sprintf(
		`SELECT id, tenant_id, agent_id, user_id, department_id, session_id, correlation_id, approval_id, connector_id,
		        channel_message_id, kind, status, risk_class, source, provenance, internal_event_type, binding, delivery_target,
		        runtime_source, title, summary, actor_label, target_label, sensitive_content_ref, metadata, occurred_at, completed_at, created_at
		   FROM agent_activity_events
		  WHERE %s
		  ORDER BY occurred_at DESC, created_at DESC
		  LIMIT $%d`,
		strings.Join(conditions, " AND "), argN,
	)
	args = append(args, params.Limit)

	return sql, args
}

func buildSecurityListQuery(params ListEventsParams) (string, []any) {
	return buildListQueryWithExtraConditions(params, []string{
		"(kind = 'security.flagged' OR status IN ('blocked', 'flagged', 'halted', 'approval_required'))",
	})
}
