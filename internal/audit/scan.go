package audit

import (
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// scanEvents reads audit event rows into a slice of maps for JSON serialization.
func scanEvents(rows pgx.Rows) []map[string]any {
	var events []map[string]any
	for rows.Next() {
		var (
			id, tid    uuid.UUID
			uid, resID *uuid.UUID
			action     string
			resType    *string
			metadata   json.RawMessage
			source     string
			createdAt  time.Time
		)
		if scanErr := rows.Scan(&id, &tid, &uid, &action, &resType, &resID, &metadata, &source, &createdAt); scanErr != nil {
			slog.Warn("skipping audit event: scan error", "error", scanErr)
			continue
		}
		events = append(events, map[string]any{
			"id":            id,
			"tenant_id":     tid,
			"user_id":       uid,
			"action":        action,
			"resource_type": resType,
			"resource_id":   resID,
			"metadata":      metadata,
			"source":        source,
			"created_at":    createdAt,
		})
	}
	return events
}
