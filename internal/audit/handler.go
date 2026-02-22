package audit

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/valinor-ai/valinor/internal/platform/database"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
)

// Handler serves audit query endpoints.
type Handler struct {
	db database.Querier
}

// NewHandler creates an audit query handler.
func NewHandler(db database.Querier) *Handler {
	return &Handler{db: db}
}

// HandleListEvents returns audit events for the current tenant.
// GET /api/v1/audit/events?limit=50&after=<timestamp>
func (h *Handler) HandleListEvents(w http.ResponseWriter, r *http.Request) {
	tenantIDStr := middleware.GetTenantID(r.Context())
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		writeAuditJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid tenant context"})
		return
	}

	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 200 {
			limit = n
		}
	}

	var after time.Time
	if raw := r.URL.Query().Get("after"); raw != "" {
		if t, err := time.Parse(time.RFC3339, raw); err == nil {
			after = t
		}
	}

	if h.db == nil {
		writeAuditJSON(w, http.StatusOK, map[string]any{"events": []any{}, "count": 0})
		return
	}

	sql := `SELECT id, tenant_id, user_id, action, resource_type, resource_id, metadata, source, created_at
		FROM audit_events
		WHERE tenant_id = $1 AND created_at > $2
		ORDER BY created_at DESC
		LIMIT $3`

	rows, err := h.db.Query(r.Context(), sql, tenantID, after, limit)
	if err != nil {
		writeAuditJSON(w, http.StatusInternalServerError, map[string]string{"error": "query failed"})
		return
	}
	defer rows.Close()

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
		if err := rows.Scan(&id, &tid, &uid, &action, &resType, &resID, &metadata, &source, &createdAt); err != nil {
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

	if events == nil {
		events = []map[string]any{}
	}

	writeAuditJSON(w, http.StatusOK, map[string]any{"events": events, "count": len(events)})
}

func writeAuditJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
