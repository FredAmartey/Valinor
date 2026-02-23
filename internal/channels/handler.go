package channels

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/valinor-ai/valinor/internal/platform/middleware"
)

var errTenantContextRequired = errors.New("tenant context required")

// Handler handles channel webhook and link management endpoints.
type Handler struct {
	ingressByProvider map[string]*IngressGuard
}

// NewHandler creates a channels handler.
func NewHandler(ingressByProvider map[string]*IngressGuard) *Handler {
	if ingressByProvider == nil {
		ingressByProvider = map[string]*IngressGuard{}
	}
	return &Handler{ingressByProvider: ingressByProvider}
}

// HandleWebhook processes inbound provider webhook traffic.
// POST /api/v1/channels/{provider}/webhook
func (h *Handler) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	provider := strings.ToLower(strings.TrimSpace(r.PathValue("provider")))
	if provider == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "provider is required"})
		return
	}
	guard, ok := h.ingressByProvider[provider]
	if !ok || guard == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unsupported provider"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	correlationID := middleware.GetRequestID(r.Context())
	if correlationID == "" {
		correlationID = r.Header.Get("X-Request-ID")
	}
	if correlationID == "" {
		correlationID = "channel-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	}

	platformMessageID := r.Header.Get("X-Provider-Message-ID")
	platformUserID := strings.TrimSpace(r.Header.Get("X-Platform-User-ID"))
	digest := sha256.Sum256(body)
	fingerprint := hex.EncodeToString(digest[:])
	idempotencyKey := strings.TrimSpace(platformMessageID)
	if idempotencyKey == "" {
		idempotencyKey = strings.TrimSpace(r.Header.Get("X-Idempotency-Key"))
	}
	if idempotencyKey == "" {
		// Fallback must be deterministic across retries.
		idempotencyKey = provider + ":" + fingerprint
		if platformUserID != "" {
			idempotencyKey = provider + ":" + platformUserID + ":" + fingerprint
		}
	}

	occurredAt := time.Now()
	if ts := r.Header.Get("X-Message-Timestamp"); ts != "" {
		if unixTs, parseErr := strconv.ParseInt(ts, 10, 64); parseErr == nil {
			occurredAt = time.Unix(unixTs, 0)
		}
	}

	result, err := guard.Process(r.Context(), IngressMessage{
		Platform:           provider,
		PlatformUserID:     platformUserID,
		PlatformMessageID:  platformMessageID,
		IdempotencyKey:     idempotencyKey,
		PayloadFingerprint: fingerprint,
		CorrelationID:      correlationID,
		Headers:            r.Header,
		Body:               body,
		OccurredAt:         occurredAt,
		ExpiresAt:          time.Now().Add(24 * time.Hour),
	})

	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidSignature),
			errors.Is(err, ErrMissingSignature),
			errors.Is(err, ErrInvalidTimestamp),
			errors.Is(err, ErrTimestampExpired):
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error":          err.Error(),
				"decision":       string(IngressRejectedSignature),
				"correlation_id": correlationID,
			})
		case errors.Is(err, ErrLinkUnverified):
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error":          err.Error(),
				"decision":       string(IngressDeniedUnverified),
				"correlation_id": correlationID,
			})
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error":          "processing webhook failed",
				"correlation_id": correlationID,
			})
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"decision":       string(result.Decision),
		"correlation_id": correlationID,
	})
}

// HandleListLinks lists tenant channel links.
// GET /api/v1/channels/links
func (h *Handler) HandleListLinks(w http.ResponseWriter, r *http.Request) {
	if _, err := resolveTenantID(r); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, []any{})
}

// HandleCreateLink creates or updates a tenant channel link.
// POST /api/v1/channels/links
func (h *Handler) HandleCreateLink(w http.ResponseWriter, r *http.Request) {
	if _, err := resolveTenantID(r); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "not implemented"})
}

// HandleDeleteLink revokes/removes a tenant channel link.
// DELETE /api/v1/channels/links/{id}
func (h *Handler) HandleDeleteLink(w http.ResponseWriter, r *http.Request) {
	if _, err := resolveTenantID(r); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "not implemented"})
}

func resolveTenantID(r *http.Request) (string, error) {
	tenantID := middleware.GetTenantID(r.Context())
	if tenantID == "" {
		return "", errTenantContextRequired
	}
	return tenantID, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
