package audit

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/valinor-ai/valinor/internal/platform/database"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
)

// Handler serves audit query endpoints.
type Handler struct {
	pool *pgxpool.Pool
}

// NewHandler creates an audit query handler.
func NewHandler(pool *pgxpool.Pool) *Handler {
	return &Handler{pool: pool}
}

// HandleListEvents returns audit events for the current tenant.
// GET /api/v1/audit/events?limit=50&action=...&resource_type=...&user_id=...&source=...&after=...&before=...
func (h *Handler) HandleListEvents(w http.ResponseWriter, r *http.Request) {
	tenantIDStr := middleware.GetTenantID(r.Context())
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		writeAuditJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid tenant context"})
		return
	}

	params := ListEventsParams{
		TenantID: tenantID,
		Limit:    50,
	}

	// Parse limit
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, parseErr := strconv.Atoi(raw); parseErr == nil && n > 0 && n <= 200 {
			params.Limit = n
		}
	}

	// Parse optional filters
	if v := r.URL.Query().Get("action"); v != "" {
		params.Action = &v
	}
	if v := r.URL.Query().Get("resource_type"); v != "" {
		params.ResourceType = &v
	}
	if v := r.URL.Query().Get("source"); v != "" {
		params.Source = &v
	}
	if raw := r.URL.Query().Get("user_id"); raw != "" {
		uid, parseErr := uuid.Parse(raw)
		if parseErr != nil {
			writeAuditJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid user_id"})
			return
		}
		params.UserID = &uid
	}
	if raw := r.URL.Query().Get("after"); raw != "" {
		if t, parseErr := time.Parse(time.RFC3339, raw); parseErr == nil {
			params.After = &t
		}
	}
	if raw := r.URL.Query().Get("before"); raw != "" {
		if t, parseErr := time.Parse(time.RFC3339, raw); parseErr == nil {
			params.Before = &t
		}
	}

	if h.pool == nil {
		writeAuditJSON(w, http.StatusOK, map[string]any{"events": []any{}, "count": 0})
		return
	}

	var events []map[string]any
	queryErr := database.WithTenantConnection(r.Context(), h.pool, tenantIDStr, func(ctx context.Context, q database.Querier) error {
		sql, args := buildListQuery(params)
		rows, qErr := q.Query(ctx, sql, args...)
		if qErr != nil {
			return qErr
		}
		defer rows.Close()

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
		return nil
	})

	if queryErr != nil {
		writeAuditJSON(w, http.StatusInternalServerError, map[string]string{"error": "query failed"})
		return
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
