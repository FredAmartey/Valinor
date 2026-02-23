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

	"github.com/google/uuid"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
)

var errTenantContextRequired = errors.New("tenant context required")
var errTenantPathRequired = errors.New("tenant path is required")
var errTenantPathInvalid = errors.New("tenant path must be a valid UUID")

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
// POST /api/v1/tenants/{tenantID}/channels/{provider}/webhook
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

	tenantID, err := resolveWebhookTenantID(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	ctx := middleware.WithTenantID(r.Context(), tenantID)

	correlationID := middleware.GetRequestID(r.Context())
	if correlationID == "" {
		correlationID = r.Header.Get("X-Request-ID")
	}
	if correlationID == "" {
		correlationID = "channel-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	}

	meta, err := extractIngressMetadata(provider, r.Header, body, time.Now())
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":          "invalid webhook payload",
			"correlation_id": correlationID,
		})
		return
	}
	if meta.Control != nil && meta.Control.AcknowledgeOnly {
		if verifyErr := guard.Verify(r.Header, body); verifyErr != nil {
			if handled := writeIngressError(w, verifyErr, correlationID); handled {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error":          "processing webhook failed",
				"correlation_id": correlationID,
			})
			return
		}
		if meta.Control.SlackChallenge != "" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(meta.Control.SlackChallenge))
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"decision":       string(IngressIgnored),
			"correlation_id": correlationID,
		})
		return
	}

	platformMessageID := meta.PlatformMessageID
	platformUserID := meta.PlatformUserID
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

	result, err := guard.Process(ctx, IngressMessage{
		Platform:           provider,
		PlatformUserID:     platformUserID,
		PlatformMessageID:  platformMessageID,
		IdempotencyKey:     idempotencyKey,
		PayloadFingerprint: fingerprint,
		CorrelationID:      correlationID,
		Headers:            r.Header,
		Body:               body,
		OccurredAt:         meta.OccurredAt,
		ExpiresAt:          time.Now().Add(24 * time.Hour),
	})

	if err != nil {
		if handled := writeIngressError(w, err, correlationID); handled {
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error":          "processing webhook failed",
			"correlation_id": correlationID,
		})
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

func resolveWebhookTenantID(r *http.Request) (string, error) {
	tenantID := strings.TrimSpace(r.PathValue("tenantID"))
	if tenantID == "" {
		return "", errTenantPathRequired
	}
	if _, err := uuid.Parse(tenantID); err != nil {
		return "", errTenantPathInvalid
	}
	return tenantID, nil
}

func writeIngressError(w http.ResponseWriter, err error, correlationID string) bool {
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
		return true
	case errors.Is(err, ErrLinkUnverified):
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error":          err.Error(),
			"decision":       string(IngressDeniedUnverified),
			"correlation_id": correlationID,
		})
		return true
	default:
		return false
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
