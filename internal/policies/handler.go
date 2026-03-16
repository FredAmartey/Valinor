package policies

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/FredAmartey/heimdall/internal/platform/database"
	httpjson "github.com/FredAmartey/heimdall/internal/platform/httputil"
	"github.com/FredAmartey/heimdall/internal/platform/middleware"
)

const maxPolicyBodyBytes int64 = 64 << 10

type Handler struct {
	pool  *pgxpool.Pool
	store *Store
}

func NewHandler(pool *pgxpool.Pool, store *Store) *Handler {
	if store == nil {
		store = NewStore()
	}
	return &Handler{pool: pool, store: store}
}

func (h *Handler) HandleGetDefaults(w http.ResponseWriter, r *http.Request) {
	tenantID, tenantIDStr, ok := parseTenantID(w, r)
	if !ok {
		return
	}
	if h.pool == nil {
		httpjson.WriteJSON(w, http.StatusOK, map[string]any{"policies": DefaultPolicySet()})
		return
	}

	policies := DefaultPolicySet()
	err := database.WithTenantConnection(r.Context(), h.pool, tenantIDStr, func(ctx context.Context, q database.Querier) error {
		stored, err := h.store.GetTenantDefaults(ctx, q, tenantID)
		if err != nil {
			return err
		}
		for riskClass, decision := range stored {
			policies[riskClass] = decision
		}
		return nil
	})
	if err != nil {
		httpjson.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "query failed"})
		return
	}

	httpjson.WriteJSON(w, http.StatusOK, map[string]any{"policies": policies})
}

func (h *Handler) HandlePutDefaults(w http.ResponseWriter, r *http.Request) {
	tenantID, tenantIDStr, ok := parseTenantID(w, r)
	if !ok {
		return
	}
	if h.pool == nil {
		httpjson.WriteJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "policy store unavailable"})
		return
	}

	var body struct {
		Policies PolicySet `json:"policies"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxPolicyBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpjson.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if err := ValidatePolicySet(body.Policies); err != nil {
		httpjson.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	err := database.WithTenantConnection(r.Context(), h.pool, tenantIDStr, func(ctx context.Context, q database.Querier) error {
		return h.store.PutTenantDefaults(ctx, q, tenantID, body.Policies)
	})
	if err != nil {
		httpjson.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "update failed"})
		return
	}

	httpjson.WriteJSON(w, http.StatusOK, map[string]any{"policies": body.Policies})
}

func (h *Handler) HandleGetAgentOverrides(w http.ResponseWriter, r *http.Request) {
	tenantID, tenantIDStr, ok := parseTenantID(w, r)
	if !ok {
		return
	}
	agentID, ok := parseAgentID(w, r)
	if !ok {
		return
	}
	if h.pool == nil {
		httpjson.WriteJSON(w, http.StatusOK, map[string]any{"policies": PolicySet{}})
		return
	}

	var set PolicySet
	err := database.WithTenantConnection(r.Context(), h.pool, tenantIDStr, func(ctx context.Context, q database.Querier) error {
		var err error
		set, err = h.store.GetAgentOverrides(ctx, q, tenantID, agentID)
		return err
	})
	if err != nil {
		httpjson.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "query failed"})
		return
	}

	httpjson.WriteJSON(w, http.StatusOK, map[string]any{"policies": set})
}

func (h *Handler) HandlePutAgentOverrides(w http.ResponseWriter, r *http.Request) {
	tenantID, tenantIDStr, ok := parseTenantID(w, r)
	if !ok {
		return
	}
	agentID, ok := parseAgentID(w, r)
	if !ok {
		return
	}
	if h.pool == nil {
		httpjson.WriteJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "policy store unavailable"})
		return
	}

	var body struct {
		Policies PolicySet `json:"policies"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxPolicyBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpjson.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if err := ValidatePolicySet(body.Policies); err != nil {
		httpjson.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	err := database.WithTenantConnection(r.Context(), h.pool, tenantIDStr, func(ctx context.Context, q database.Querier) error {
		return h.store.PutAgentOverrides(ctx, q, tenantID, agentID, body.Policies)
	})
	if err != nil {
		httpjson.WriteJSON(w, http.StatusInternalServerError, map[string]string{"error": "update failed"})
		return
	}

	httpjson.WriteJSON(w, http.StatusOK, map[string]any{"policies": body.Policies})
}

func parseTenantID(w http.ResponseWriter, r *http.Request) (uuid.UUID, string, bool) {
	tenantIDStr := middleware.GetTenantID(r.Context())
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		httpjson.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid tenant context"})
		return uuid.Nil, "", false
	}
	return tenantID, tenantIDStr, true
}

func parseAgentID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	agentID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpjson.WriteJSON(w, http.StatusBadRequest, map[string]string{"error": "agent id must be a valid UUID"})
		return uuid.Nil, false
	}
	return agentID, true
}
