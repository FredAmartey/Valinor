package approvals

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/platform/database"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
)

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

func (h *Handler) HandleList(w http.ResponseWriter, r *http.Request) {
	tenantID, tenantIDStr, ok := parseTenant(w, r)
	if !ok {
		return
	}
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 || n > 200 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be between 1 and 200"})
			return
		}
		limit = n
	}
	var status *string
	if value := r.URL.Query().Get("status"); value != "" {
		status = &value
	}

	if h.pool == nil {
		writeJSON(w, http.StatusOK, map[string]any{"approvals": []Request{}, "count": 0})
		return
	}

	var requests []Request
	err := database.WithTenantConnection(r.Context(), h.pool, tenantIDStr, func(ctx context.Context, q database.Querier) error {
		var err error
		requests, err = h.store.List(ctx, q, ListParams{
			TenantID: tenantID,
			Status:   status,
			Limit:    limit,
		})
		return err
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "query failed"})
		return
	}
	if requests == nil {
		requests = []Request{}
	}

	writeJSON(w, http.StatusOK, map[string]any{"approvals": requests, "count": len(requests)})
}

func (h *Handler) HandleApprove(w http.ResponseWriter, r *http.Request) {
	h.resolve(w, r, StatusApproved)
}

func (h *Handler) HandleDeny(w http.ResponseWriter, r *http.Request) {
	h.resolve(w, r, StatusDenied)
}

func (h *Handler) resolve(w http.ResponseWriter, r *http.Request, resolution string) {
	tenantID, tenantIDStr, ok := parseTenant(w, r)
	if !ok {
		return
	}
	approvalID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "approval id must be a valid UUID"})
		return
	}
	identity := auth.GetIdentity(r.Context())
	if identity == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	reviewerID, err := uuid.Parse(identity.UserID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid user identity"})
		return
	}
	if h.pool == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "approval store unavailable"})
		return
	}

	var request *Request
	err = database.WithTenantConnection(r.Context(), h.pool, tenantIDStr, func(ctx context.Context, q database.Querier) error {
		if resolution == StatusApproved {
			request, err = h.store.Approve(ctx, q, approvalID, reviewerID, tenantID)
		} else {
			request, err = h.store.Deny(ctx, q, approvalID, reviewerID, tenantID)
		}
		return err
	})
	if err != nil {
		if errors.Is(err, ErrApprovalNotPending) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": "approval request is not pending"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "resolution failed"})
		return
	}

	writeJSON(w, http.StatusOK, request)
}

func parseTenant(w http.ResponseWriter, r *http.Request) (uuid.UUID, string, bool) {
	tenantIDStr := middleware.GetTenantID(r.Context())
	tenantID, err := uuid.Parse(tenantIDStr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid tenant context"})
		return uuid.Nil, "", false
	}
	return tenantID, tenantIDStr, true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
