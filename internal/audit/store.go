package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

// Store handles audit event persistence.
type Store struct{}

// NewStore creates an audit Store.
func NewStore() *Store {
	return &Store{}
}

// InsertBatch writes a batch of events to the database.
func (s *Store) InsertBatch(ctx context.Context, db database.Querier, events []Event) error {
	if len(events) == 0 {
		return nil
	}
	sql, args, err := buildBatchInsert(events)
	if err != nil {
		return fmt.Errorf("building batch insert: %w", err)
	}
	_, err = db.Exec(ctx, sql, args...)
	if err != nil {
		return fmt.Errorf("inserting audit events: %w", err)
	}
	return nil
}

// buildBatchInsert constructs a multi-row INSERT statement.
func buildBatchInsert(events []Event) (string, []any, error) {
	const cols = "(tenant_id, user_id, action, resource_type, resource_id, metadata, source)"
	var placeholders []string
	var args []any

	for i, e := range events {
		base := i * 7
		placeholders = append(placeholders, fmt.Sprintf(
			"($%d, $%d, $%d, $%d, $%d, $%d, $%d)",
			base+1, base+2, base+3, base+4, base+5, base+6, base+7,
		))

		var metaJSON []byte
		var err error
		if e.Metadata != nil {
			metaJSON, err = json.Marshal(e.Metadata)
			if err != nil {
				return "", nil, fmt.Errorf("marshaling metadata: %w", err)
			}
		}

		args = append(args, e.TenantID, e.UserID, e.Action, e.ResourceType, e.ResourceID, metaJSON, e.Source)
	}

	sql := fmt.Sprintf("INSERT INTO audit_events %s VALUES %s", cols, strings.Join(placeholders, ", "))
	return sql, args, nil
}

// ListEventsParams defines filters for querying audit events.
type ListEventsParams struct {
	TenantID     uuid.UUID
	Action       *string
	ResourceType *string
	UserID       *uuid.UUID
	Source       *string
	After        *time.Time
	Before       *time.Time
	Limit        int
}

// buildListQuery constructs a parameterized SELECT for audit events.
func buildListQuery(p ListEventsParams) (string, []any) {
	var conditions []string
	var args []any
	argN := 1

	conditions = append(conditions, fmt.Sprintf("tenant_id = $%d", argN))
	args = append(args, p.TenantID)
	argN++

	if p.Action != nil {
		conditions = append(conditions, fmt.Sprintf("action = $%d", argN))
		args = append(args, *p.Action)
		argN++
	}
	if p.ResourceType != nil {
		conditions = append(conditions, fmt.Sprintf("resource_type = $%d", argN))
		args = append(args, *p.ResourceType)
		argN++
	}
	if p.UserID != nil {
		conditions = append(conditions, fmt.Sprintf("user_id = $%d", argN))
		args = append(args, *p.UserID)
		argN++
	}
	if p.Source != nil {
		conditions = append(conditions, fmt.Sprintf("source = $%d", argN))
		args = append(args, *p.Source)
		argN++
	}
	if p.After != nil {
		conditions = append(conditions, fmt.Sprintf("created_at > $%d", argN))
		args = append(args, *p.After)
		argN++
	}
	if p.Before != nil {
		conditions = append(conditions, fmt.Sprintf("created_at < $%d", argN))
		args = append(args, *p.Before)
		argN++
	}

	sql := fmt.Sprintf(
		`SELECT id, tenant_id, user_id, action, resource_type, resource_id, metadata, source, created_at
		FROM audit_events
		WHERE %s
		ORDER BY created_at DESC
		LIMIT $%d`,
		strings.Join(conditions, " AND "), argN,
	)
	args = append(args, p.Limit)

	return sql, args
}
