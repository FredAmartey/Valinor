package activity

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/FredAmartey/heimdall/internal/platform/database"
	"github.com/FredAmartey/heimdall/internal/platform/middleware"
)

type Handler struct {
	pool           *pgxpool.Pool
	securityConfig SecurityOverviewConfig
}

func NewHandler(pool *pgxpool.Pool) *Handler {
	return &Handler{pool: pool}
}

func (h *Handler) WithSecurityOverviewConfig(cfg SecurityOverviewConfig) *Handler {
	if h == nil {
		return nil
	}
	h.securityConfig = cfg
	return h
}

func (h *Handler) HandleListActivity(w http.ResponseWriter, r *http.Request) {
	tenantID, tenantIDStr, ok := parseTenantContext(w, r)
	if !ok {
		return
	}
	params, ok := parseListParams(w, r, tenantID, nil)
	if !ok {
		return
	}
	h.list(w, r, tenantIDStr, params, buildListQuery)
}

func (h *Handler) HandleListAgentActivity(w http.ResponseWriter, r *http.Request) {
	tenantID, tenantIDStr, ok := parseTenantContext(w, r)
	if !ok {
		return
	}
	agentIDValue := r.PathValue("id")
	agentID, err := uuid.Parse(agentIDValue)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "agent id must be a valid UUID"})
		return
	}
	params, ok := parseListParams(w, r, tenantID, &agentID)
	if !ok {
		return
	}
	h.list(w, r, tenantIDStr, params, buildListQuery)
}

func (h *Handler) HandleListSecurityEvents(w http.ResponseWriter, r *http.Request) {
	tenantID, tenantIDStr, ok := parseTenantContext(w, r)
	if !ok {
		return
	}
	params, ok := parseListParams(w, r, tenantID, nil)
	if !ok {
		return
	}
	h.list(w, r, tenantIDStr, params, buildSecurityListQuery)
}

func (h *Handler) HandleGetSecurityOverview(w http.ResponseWriter, r *http.Request) {
	_, tenantIDStr, ok := parseTenantContext(w, r)
	if !ok {
		return
	}

	if h.pool == nil {
		writeJSON(w, http.StatusOK, buildSecurityOverview(h.securityConfig, securityOverviewStats{}))
		return
	}

	var overview SecurityOverview
	queryErr := database.WithTenantConnection(r.Context(), h.pool, tenantIDStr, func(ctx context.Context, q database.Querier) error {
		stats, err := loadSecurityOverviewStats(ctx, q, h.securityConfig)
		if err != nil {
			return err
		}
		overview = buildSecurityOverview(h.securityConfig, stats)
		return nil
	})
	if queryErr != nil {
		slog.Error("security overview query failed", "error", queryErr, "tenant_id", tenantIDStr)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "query failed"})
		return
	}

	writeJSON(w, http.StatusOK, overview)
}

func (h *Handler) list(
	w http.ResponseWriter,
	r *http.Request,
	tenantIDStr string,
	params ListEventsParams,
	queryBuilder func(ListEventsParams) (string, []any),
) {
	if h.pool == nil {
		writeJSON(w, http.StatusOK, map[string]any{"events": []Event{}, "count": 0})
		return
	}

	var events []Event
	queryErr := database.WithTenantConnection(r.Context(), h.pool, tenantIDStr, func(ctx context.Context, q database.Querier) error {
		sql, args := queryBuilder(params)
		rows, err := q.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		defer rows.Close()

		events = scanEvents(rows)
		return rows.Err()
	})
	if queryErr != nil {
		slog.Error("activity query failed", "error", queryErr, "tenant_id", tenantIDStr)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "query failed"})
		return
	}
	if events == nil {
		events = []Event{}
	}

	writeJSON(w, http.StatusOK, map[string]any{"events": events, "count": len(events)})
}

func parseTenantContext(w http.ResponseWriter, r *http.Request) (uuid.UUID, string, bool) {
	tenantIDStr := middleware.GetTenantID(r.Context())
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid tenant context"})
		return uuid.Nil, "", false
	}
	return tenantID, tenantIDStr, true
}

func parseListParams(w http.ResponseWriter, r *http.Request, tenantID uuid.UUID, agentID *uuid.UUID) (ListEventsParams, bool) {
	params := ListEventsParams{
		TenantID: tenantID,
		AgentID:  agentID,
		Limit:    50,
	}

	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 || n > 200 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be between 1 and 200"})
			return ListEventsParams{}, false
		}
		params.Limit = n
	}

	if raw := r.URL.Query().Get("agent_id"); raw != "" && params.AgentID == nil {
		value, err := uuid.Parse(raw)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid agent_id"})
			return ListEventsParams{}, false
		}
		params.AgentID = &value
	}
	if raw := r.URL.Query().Get("user_id"); raw != "" {
		value, err := uuid.Parse(raw)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid user_id"})
			return ListEventsParams{}, false
		}
		params.UserID = &value
	}
	if raw := r.URL.Query().Get("department_id"); raw != "" {
		value, err := uuid.Parse(raw)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid department_id"})
			return ListEventsParams{}, false
		}
		params.DepartmentID = &value
	}
	if raw := r.URL.Query().Get("kind"); raw != "" {
		params.Kind = &raw
	}
	if raw := r.URL.Query().Get("status"); raw != "" {
		params.Status = &raw
	}
	if raw := r.URL.Query().Get("risk_class"); raw != "" {
		params.RiskClass = &raw
	}
	if raw := r.URL.Query().Get("source"); raw != "" {
		params.Source = &raw
	}
	if raw := r.URL.Query().Get("after"); raw != "" {
		value, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid after timestamp"})
			return ListEventsParams{}, false
		}
		params.After = &value
	}
	if raw := r.URL.Query().Get("before"); raw != "" {
		value, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid before timestamp"})
			return ListEventsParams{}, false
		}
		params.Before = &value
	}

	return params, true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
