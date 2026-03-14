package activity

import (
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func scanEvents(rows pgx.Rows) []Event {
	var events []Event
	for rows.Next() {
		var (
			event               Event
			sessionID           *string
			correlationID       *string
			riskClass           *string
			provenance          *string
			internalEventType   *string
			binding             *string
			deliveryTarget      *string
			runtimeSource       *string
			actorLabel          *string
			targetLabel         *string
			sensitiveContentRaw json.RawMessage
			metadataRaw         json.RawMessage
		)
		if err := rows.Scan(
			&event.ID,
			&event.TenantID,
			&event.AgentID,
			&event.UserID,
			&event.DepartmentID,
			&sessionID,
			&correlationID,
			&event.ApprovalID,
			&event.ConnectorID,
			&event.ChannelMessageID,
			&event.Kind,
			&event.Status,
			&riskClass,
			&event.Source,
			&provenance,
			&internalEventType,
			&binding,
			&deliveryTarget,
			&runtimeSource,
			&event.Title,
			&event.Summary,
			&actorLabel,
			&targetLabel,
			&sensitiveContentRaw,
			&metadataRaw,
			&event.OccurredAt,
			&event.CompletedAt,
			&event.CreatedAt,
		); err != nil {
			slog.Warn("skipping activity event: scan error", "error", err)
			continue
		}

		if sessionID != nil {
			event.SessionID = *sessionID
		}
		if correlationID != nil {
			event.CorrelationID = *correlationID
		}
		if riskClass != nil {
			event.RiskClass = *riskClass
		}
		if provenance != nil {
			event.Provenance = *provenance
		}
		if internalEventType != nil {
			event.InternalEventType = *internalEventType
		}
		if binding != nil {
			event.Binding = *binding
		}
		if deliveryTarget != nil {
			event.DeliveryTarget = *deliveryTarget
		}
		if runtimeSource != nil {
			event.RuntimeSource = *runtimeSource
		}
		if actorLabel != nil {
			event.ActorLabel = *actorLabel
		}
		if targetLabel != nil {
			event.TargetLabel = *targetLabel
		}
		if len(sensitiveContentRaw) > 0 {
			var ref SensitiveContentRef
			if err := json.Unmarshal(sensitiveContentRaw, &ref); err == nil {
				event.SensitiveContentRef = &ref
			}
		}
		if len(metadataRaw) > 0 {
			var metadata map[string]any
			if err := json.Unmarshal(metadataRaw, &metadata); err == nil {
				event.Metadata = metadata
			}
		}
		if event.OccurredAt.IsZero() {
			event.OccurredAt = time.Now().UTC()
		}
		events = append(events, event)
	}
	return events
}

// Ensure uuid is retained by goimports when this file compiles under all build paths.
var _ uuid.UUID
