package channels

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/valinor-ai/valinor/internal/platform/database"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
)

var errTenantContextRequired = errors.New("tenant context required")
var errTenantPathRequired = errors.New("tenant path is required")
var errTenantPathInvalid = errors.New("tenant path must be a valid UUID")

type listLinksFunc func(ctx context.Context, tenantID string) ([]ChannelLink, error)
type upsertLinkFunc func(ctx context.Context, tenantID, userID, platform, platformUserID string, state LinkState, verificationMethod string, verificationMetadata json.RawMessage) (*ChannelLink, error)
type deleteLinkFunc func(ctx context.Context, tenantID, id string) error
type listOutboxFunc func(ctx context.Context, tenantID, status string, limit int) ([]ChannelOutbox, error)
type requeueOutboxDeadFunc func(ctx context.Context, tenantID string, outboxID uuid.UUID) error
type updateMessageStatusFunc func(ctx context.Context, tenantID, platform, idempotencyKey, status string, metadata json.RawMessage) error
type getMessageByIdempotencyKeyFunc func(ctx context.Context, tenantID, platform, idempotencyKey string) (*ChannelMessageRecord, error)
type enqueueOutboundFunc func(ctx context.Context, tenantID, platform, idempotencyKey, recipientID, outboxThreadTS, correlationID, responseContent string) error
type getProviderCredentialFunc func(ctx context.Context, tenantID, provider string) (*ProviderCredential, error)
type upsertProviderCredentialFunc func(ctx context.Context, tenantID string, params UpsertProviderCredentialParams) (*ProviderCredential, error)
type deleteProviderCredentialFunc func(ctx context.Context, tenantID, provider string) error

// Handler handles channel webhook and link management endpoints.
type Handler struct {
	ingressByProvider          map[string]*IngressGuard
	listLinks                  listLinksFunc
	upsertLink                 upsertLinkFunc
	deleteLink                 deleteLinkFunc
	listOutbox                 listOutboxFunc
	requeueOutboxDead          requeueOutboxDeadFunc
	updateMessageStatus        updateMessageStatusFunc
	getMessageByIdempotencyKey getMessageByIdempotencyKeyFunc
	enqueueOutbound            enqueueOutboundFunc
	getProviderCredential      getProviderCredentialFunc
	upsertProviderCredential   upsertProviderCredentialFunc
	deleteProviderCredential   deleteProviderCredentialFunc
	execute                    executeFunc
}

// NewHandler creates a channels handler.
func NewHandler(ingressByProvider map[string]*IngressGuard) *Handler {
	if ingressByProvider == nil {
		ingressByProvider = map[string]*IngressGuard{}
	}
	return &Handler{ingressByProvider: ingressByProvider}
}

// WithLinkStore wires channel link CRUD operations backed by the channels store.
func (h *Handler) WithLinkStore(pool *database.Pool, store *Store) *Handler {
	if pool == nil || store == nil {
		h.listLinks = nil
		h.upsertLink = nil
		h.deleteLink = nil
		h.listOutbox = nil
		h.requeueOutboxDead = nil
		h.updateMessageStatus = nil
		h.getMessageByIdempotencyKey = nil
		h.enqueueOutbound = nil
		h.getProviderCredential = nil
		h.upsertProviderCredential = nil
		h.deleteProviderCredential = nil
		return h
	}

	h.listLinks = func(ctx context.Context, tenantID string) ([]ChannelLink, error) {
		var links []ChannelLink
		err := database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
			var listErr error
			links, listErr = store.ListLinks(ctx, q)
			return listErr
		})
		return links, err
	}

	h.upsertLink = func(ctx context.Context, tenantID, userID, platform, platformUserID string, state LinkState, verificationMethod string, verificationMetadata json.RawMessage) (*ChannelLink, error) {
		var link *ChannelLink
		err := database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
			var upsertErr error
			link, upsertErr = store.UpsertLink(ctx, q, UpsertLinkParams{
				UserID:               userID,
				Platform:             platform,
				PlatformUserID:       platformUserID,
				State:                state,
				VerificationMethod:   verificationMethod,
				VerificationMetadata: verificationMetadata,
			})
			return upsertErr
		})
		return link, err
	}

	h.deleteLink = func(ctx context.Context, tenantID, id string) error {
		return database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
			return store.DeleteLink(ctx, q, id)
		})
	}

	h.listOutbox = func(ctx context.Context, tenantID, status string, limit int) ([]ChannelOutbox, error) {
		var jobs []ChannelOutbox
		err := database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
			var listErr error
			jobs, listErr = store.ListOutbox(ctx, q, status, limit)
			return listErr
		})
		return jobs, err
	}

	h.requeueOutboxDead = func(ctx context.Context, tenantID string, outboxID uuid.UUID) error {
		return database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
			return store.RequeueOutboxDead(ctx, q, outboxID)
		})
	}

	h.updateMessageStatus = func(ctx context.Context, tenantID, platform, idempotencyKey, status string, metadata json.RawMessage) error {
		return database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
			return store.UpdateMessageStatus(ctx, q, platform, idempotencyKey, status, metadata)
		})
	}

	h.getMessageByIdempotencyKey = func(ctx context.Context, tenantID, platform, idempotencyKey string) (*ChannelMessageRecord, error) {
		var record *ChannelMessageRecord
		err := database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
			var lookupErr error
			record, lookupErr = store.GetMessageByIdempotencyKey(ctx, q, platform, idempotencyKey)
			return lookupErr
		})
		return record, err
	}

	h.enqueueOutbound = func(ctx context.Context, tenantID, platform, idempotencyKey, recipientID, outboxThreadTS, correlationID, responseContent string) error {
		return database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
			messageID, err := store.GetMessageIDByIdempotencyKey(ctx, q, platform, idempotencyKey)
			if err != nil {
				return fmt.Errorf("resolving channel message for outbox enqueue: %w", err)
			}

			payloadBody := map[string]string{
				"content":        responseContent,
				"correlation_id": correlationID,
			}
			if threadTS := strings.TrimSpace(outboxThreadTS); threadTS != "" {
				payloadBody["thread_ts"] = threadTS
			}

			payload, err := json.Marshal(payloadBody)
			if err != nil {
				return fmt.Errorf("marshaling outbox payload: %w", err)
			}

			_, err = store.EnqueueOutbound(ctx, q, EnqueueOutboundParams{
				ChannelMessageID: messageID.String(),
				Provider:         platform,
				RecipientID:      recipientID,
				Payload:          payload,
			})
			if err != nil {
				return fmt.Errorf("enqueuing outbound response: %w", err)
			}
			return nil
		})
	}

	h.getProviderCredential = func(ctx context.Context, tenantID, provider string) (*ProviderCredential, error) {
		var credential *ProviderCredential
		err := database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
			var lookupErr error
			credential, lookupErr = store.GetProviderCredential(ctx, q, provider)
			return lookupErr
		})
		return credential, err
	}

	h.upsertProviderCredential = func(ctx context.Context, tenantID string, params UpsertProviderCredentialParams) (*ProviderCredential, error) {
		var credential *ProviderCredential
		err := database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
			var upsertErr error
			credential, upsertErr = store.UpsertProviderCredential(ctx, q, params)
			return upsertErr
		})
		return credential, err
	}

	h.deleteProviderCredential = func(ctx context.Context, tenantID, provider string) error {
		return database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
			return store.DeleteProviderCredential(ctx, q, provider)
		})
	}

	return h
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
	now := time.Now()

	correlationID := middleware.GetRequestID(r.Context())
	if correlationID == "" {
		correlationID = r.Header.Get("X-Request-ID")
	}
	if correlationID == "" {
		correlationID = "channel-" + strconv.FormatInt(now.UnixNano(), 10)
	}

	metas, err := extractIngressMetadata(provider, r.Header, body, now)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":          "invalid webhook payload",
			"correlation_id": correlationID,
		})
		return
	}
	if len(metas) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":          "invalid webhook payload",
			"correlation_id": correlationID,
		})
		return
	}

	digest := sha256.Sum256(body)
	fingerprint := hex.EncodeToString(digest[:])

	decision := IngressIgnored
	actionableCount := 0
	controlVerified := false
	executedAgentID := ""
	// For batched webhook payloads, response fields reflect the most recent
	// actionable message processed in this request.

	for _, meta := range metas {
		if meta.Control != nil && meta.Control.AcknowledgeOnly {
			if !controlVerified {
				if verifyErr := guard.VerifyWithContext(ctx, r.Header, body); verifyErr != nil {
					if handled := writeIngressError(w, verifyErr, correlationID); handled {
						return
					}
					writeJSON(w, http.StatusInternalServerError, map[string]string{
						"error":          "processing webhook failed",
						"correlation_id": correlationID,
					})
					return
				}
				controlVerified = true
			}
			if meta.Control.SlackChallenge != "" {
				writeJSON(w, http.StatusOK, map[string]string{
					"challenge": meta.Control.SlackChallenge,
				})
				return
			}
			continue
		}

		actionableCount++
		messageAgentID := ""
		messageResponseContent := ""
		statusMetadataExtra := map[string]any{}
		enqueueFailed := false

		platformMessageID := meta.PlatformMessageID
		platformUserID := meta.PlatformUserID
		outboundRecipientID := strings.TrimSpace(meta.OutboundRecipientID)
		outboundThreadTS := strings.TrimSpace(meta.OutboundThreadTS)
		if outboundRecipientID == "" && provider != "slack" {
			outboundRecipientID = strings.TrimSpace(platformUserID)
		}
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

		result, processErr := guard.Process(ctx, IngressMessage{
			Platform:           provider,
			PlatformUserID:     platformUserID,
			PlatformMessageID:  platformMessageID,
			IdempotencyKey:     idempotencyKey,
			PayloadFingerprint: fingerprint,
			CorrelationID:      correlationID,
			Headers:            r.Header,
			Body:               body,
			OccurredAt:         meta.OccurredAt,
			ExpiresAt:          now.Add(24 * time.Hour),
		})
		if processErr != nil {
			if handled := writeIngressError(w, processErr, correlationID); handled {
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error":          "processing webhook failed",
				"correlation_id": correlationID,
			})
			return
		}
		messageDecision := result.Decision
		if result.Decision == IngressDuplicate && h.getMessageByIdempotencyKey != nil && h.enqueueOutbound != nil {
			recoveredAgentID, recoveredResponse, recovered, recoverErr := h.recoverDuplicateDispatchFailure(
				ctx,
				tenantID,
				provider,
				idempotencyKey,
				outboundRecipientID,
				outboundThreadTS,
				correlationID,
			)
			if recoverErr != nil {
				slog.Error(
					"channel outbox duplicate recovery failed",
					"tenant_id", tenantID,
					"provider", provider,
					"idempotency_key", idempotencyKey,
					"platform_user_id", platformUserID,
					"correlation_id", correlationID,
					"error", recoverErr,
				)
				writeJSON(w, http.StatusInternalServerError, map[string]string{
					"error":          "processing webhook failed",
					"correlation_id": correlationID,
				})
				return
			}
			if recovered {
				messageDecision = IngressExecuted
				if recoveredAgentID != "" {
					messageAgentID = recoveredAgentID
					executedAgentID = recoveredAgentID
				}
				statusMetadataExtra["outbox_enqueue_failed"] = false
				statusMetadataExtra["outbox_recovered"] = true
				if outboundRecipientID != "" {
					statusMetadataExtra["outbox_recipient_id"] = outboundRecipientID
				}
				if outboundThreadTS != "" {
					statusMetadataExtra["outbox_thread_ts"] = outboundThreadTS
				}
				if recoveredResponse != "" {
					statusMetadataExtra["response_content"] = recoveredResponse
				}
			}
		}
		if h.execute != nil && result.Decision == IngressAccepted && result.Link != nil {
			content := strings.TrimSpace(meta.Content)
			if content != "" {
				execResult := h.execute(ctx, ExecutionMessage{
					TenantID:          tenantID,
					Platform:          provider,
					PlatformUserID:    platformUserID,
					PlatformMessageID: platformMessageID,
					CorrelationID:     correlationID,
					Content:           content,
					Link:              *result.Link,
				})
				if execResult.Decision != "" {
					messageDecision = execResult.Decision
				}
				if execResult.AgentID != "" {
					messageAgentID = execResult.AgentID
					executedAgentID = execResult.AgentID
				}
				messageResponseContent = execResult.ResponseContent
				if messageResponseContent == "" {
					messageResponseContent = defaultOutboundContentForDecision(messageDecision)
				}
				shouldEnqueue := h.enqueueOutbound != nil &&
					shouldEnqueueOutboundForDecision(messageDecision) &&
					strings.TrimSpace(messageResponseContent) != ""
				if shouldEnqueue {
					if provider == "slack" && outboundRecipientID == "" {
						slog.Error(
							"channel outbox enqueue target resolution failed",
							"tenant_id", tenantID,
							"provider", provider,
							"idempotency_key", idempotencyKey,
							"platform_user_id", platformUserID,
							"correlation_id", correlationID,
							"error", "missing slack outbound channel",
						)
						statusMetadataExtra["outbox_enqueue_failed"] = true
						if outboundRecipientID != "" {
							statusMetadataExtra["outbox_recipient_id"] = outboundRecipientID
						}
						if outboundThreadTS != "" {
							statusMetadataExtra["outbox_thread_ts"] = outboundThreadTS
						}
						statusMetadataExtra["response_content"] = messageResponseContent
						if messageDecision == IngressExecuted {
							messageDecision = IngressDispatchFailed
							enqueueFailed = true
						}
						shouldEnqueue = false
					}
				}
				if shouldEnqueue && !enqueueFailed {
					enqueueErr := h.enqueueOutbound(
						ctx,
						tenantID,
						provider,
						idempotencyKey,
						outboundRecipientID,
						outboundThreadTS,
						correlationID,
						messageResponseContent,
					)
					if enqueueErr != nil {
						slog.Error(
							"channel outbox enqueue failed",
							"tenant_id", tenantID,
							"provider", provider,
							"idempotency_key", idempotencyKey,
							"platform_user_id", platformUserID,
							"correlation_id", correlationID,
							"error", enqueueErr,
						)
						statusMetadataExtra["outbox_enqueue_failed"] = true
						if outboundRecipientID != "" {
							statusMetadataExtra["outbox_recipient_id"] = outboundRecipientID
						}
						if outboundThreadTS != "" {
							statusMetadataExtra["outbox_thread_ts"] = outboundThreadTS
						}
						statusMetadataExtra["response_content"] = messageResponseContent
						if messageDecision == IngressExecuted {
							messageDecision = IngressDispatchFailed
							enqueueFailed = true
						}
					} else if messageDecision != IngressExecuted {
						statusMetadataExtra["outbox_enqueue_failed"] = false
						if outboundRecipientID != "" {
							statusMetadataExtra["outbox_recipient_id"] = outboundRecipientID
						}
						if outboundThreadTS != "" {
							statusMetadataExtra["outbox_thread_ts"] = outboundThreadTS
						}
						statusMetadataExtra["response_content"] = messageResponseContent
					}
				}
			}
		}
		if h.updateMessageStatus != nil {
			// InsertIdempotency persists the initial "accepted" state. This
			// best-effort write only records terminal execution outcomes.
			if status, ok := messageStatusForDecision(messageDecision); ok {
				statusMetadata := map[string]any{
					"decision": string(messageDecision),
				}
				if messageAgentID != "" {
					statusMetadata["agent_id"] = messageAgentID
				}
				for key, value := range statusMetadataExtra {
					statusMetadata[key] = value
				}
				rawStatusMetadata, marshalErr := json.Marshal(statusMetadata)
				if marshalErr != nil {
					writeJSON(w, http.StatusInternalServerError, map[string]string{
						"error":          "processing webhook failed",
						"correlation_id": correlationID,
					})
					return
				}

				updateErr := h.updateMessageStatus(
					ctx,
					tenantID,
					provider,
					idempotencyKey,
					status,
					rawStatusMetadata,
				)
				if updateErr != nil {
					if errors.Is(updateErr, ErrMessageNotFound) {
						slog.Error(
							"channel message status update missing idempotency row",
							"tenant_id", tenantID,
							"provider", provider,
							"idempotency_key", idempotencyKey,
							"decision", string(messageDecision),
							"correlation_id", correlationID,
							"error", updateErr,
						)
					} else {
						slog.Error(
							"channel message status update failed",
							"tenant_id", tenantID,
							"provider", provider,
							"idempotency_key", idempotencyKey,
							"decision", string(messageDecision),
							"correlation_id", correlationID,
							"error", updateErr,
						)
					}
					writeJSON(w, http.StatusInternalServerError, map[string]string{
						"error":          "processing webhook failed",
						"correlation_id": correlationID,
					})
					return
				}
			}
		}
		if enqueueFailed {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error":          "processing webhook failed",
				"correlation_id": correlationID,
			})
			return
		}
		decision = messageDecision
	}

	if actionableCount == 0 {
		writeJSON(w, http.StatusOK, map[string]string{
			"decision":       string(IngressIgnored),
			"correlation_id": correlationID,
		})
		return
	}

	resp := map[string]string{
		"decision":       string(decision),
		"correlation_id": correlationID,
	}
	if executedAgentID != "" {
		resp["agent_id"] = executedAgentID
	}

	writeJSON(w, http.StatusOK, resp)
}

func messageStatusForDecision(decision IngressDecision) (string, bool) {
	switch decision {
	case IngressExecuted:
		return MessageStatusExecuted, true
	case IngressDeniedRBAC:
		return MessageStatusDeniedRBAC, true
	case IngressDeniedNoAgent:
		return MessageStatusDeniedNoAgent, true
	case IngressDeniedSentinel:
		return MessageStatusDeniedSentinel, true
	case IngressDispatchFailed:
		return MessageStatusDispatchFailed, true
	default:
		return "", false
	}
}

func defaultOutboundContentForDecision(decision IngressDecision) string {
	switch decision {
	case IngressDeniedRBAC:
		return "I can't perform that action from this channel."
	case IngressDeniedNoAgent:
		return "No agent is available right now. Please try again shortly."
	case IngressDeniedSentinel:
		return "I can't process that request due to policy."
	case IngressDispatchFailed:
		return "I couldn't process your request right now. Please try again."
	default:
		return ""
	}
}

func shouldEnqueueOutboundForDecision(decision IngressDecision) bool {
	switch decision {
	case IngressExecuted, IngressDeniedRBAC, IngressDeniedNoAgent, IngressDeniedSentinel, IngressDispatchFailed:
		return true
	default:
		return false
	}
}

type dispatchFailureMetadata struct {
	AgentID             string `json:"agent_id"`
	ResponseContent     string `json:"response_content"`
	OutboxEnqueueFailed bool   `json:"outbox_enqueue_failed"`
	OutboxRecipientID   string `json:"outbox_recipient_id"`
	OutboxThreadTS      string `json:"outbox_thread_ts"`
}

func (h *Handler) recoverDuplicateDispatchFailure(
	ctx context.Context,
	tenantID string,
	provider string,
	idempotencyKey string,
	fallbackRecipientID string,
	fallbackThreadTS string,
	correlationID string,
) (string, string, bool, error) {
	record, err := h.getMessageByIdempotencyKey(ctx, tenantID, provider, idempotencyKey)
	if err != nil {
		if errors.Is(err, ErrMessageNotFound) {
			return "", "", false, nil
		}
		return "", "", false, fmt.Errorf("loading duplicate message state: %w", err)
	}
	if record == nil || strings.TrimSpace(record.Status) != MessageStatusDispatchFailed {
		return "", "", false, nil
	}

	var metadata dispatchFailureMetadata
	if len(record.Metadata) > 0 {
		if unmarshalErr := json.Unmarshal(record.Metadata, &metadata); unmarshalErr != nil {
			slog.Warn(
				"channel duplicate recovery metadata unmarshal failed",
				"tenant_id", tenantID,
				"provider", provider,
				"idempotency_key", idempotencyKey,
				"error", unmarshalErr,
			)
			return "", "", false, nil
		}
	}
	responseContent := strings.TrimSpace(metadata.ResponseContent)
	if !metadata.OutboxEnqueueFailed || responseContent == "" {
		return "", "", false, nil
	}

	recipientID := strings.TrimSpace(metadata.OutboxRecipientID)
	if recipientID == "" {
		recipientID = strings.TrimSpace(fallbackRecipientID)
	}
	if recipientID == "" && provider != "slack" {
		recipientID = strings.TrimSpace(record.PlatformUserID)
	}
	if recipientID == "" {
		return "", "", false, fmt.Errorf("missing recipient id for duplicate dispatch recovery")
	}
	threadTS := strings.TrimSpace(metadata.OutboxThreadTS)
	if threadTS == "" {
		threadTS = strings.TrimSpace(fallbackThreadTS)
	}

	outboundCorrelationID := strings.TrimSpace(record.CorrelationID)
	if outboundCorrelationID == "" {
		outboundCorrelationID = strings.TrimSpace(correlationID)
	}
	if outboundCorrelationID == "" {
		return "", "", false, fmt.Errorf("missing correlation id for duplicate dispatch recovery")
	}

	if err := h.enqueueOutbound(
		ctx,
		tenantID,
		provider,
		idempotencyKey,
		recipientID,
		threadTS,
		outboundCorrelationID,
		responseContent,
	); err != nil {
		return "", "", false, fmt.Errorf("re-enqueuing duplicate dispatch failure: %w", err)
	}

	return strings.TrimSpace(metadata.AgentID), responseContent, true, nil
}

// HandleListLinks lists tenant channel links.
// GET /api/v1/channels/links
func (h *Handler) HandleListLinks(w http.ResponseWriter, r *http.Request) {
	tenantID, err := resolveTenantID(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if h.listLinks == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "channel links are not configured"})
		return
	}

	links, err := h.listLinks(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "listing channel links failed"})
		return
	}
	if links == nil {
		links = []ChannelLink{}
	}
	writeJSON(w, http.StatusOK, links)
}

// HandleCreateLink creates or updates a tenant channel link.
// POST /api/v1/channels/links
func (h *Handler) HandleCreateLink(w http.ResponseWriter, r *http.Request) {
	tenantID, err := resolveTenantID(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if h.upsertLink == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "channel links are not configured"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)

	var req struct {
		UserID               string          `json:"user_id"`
		Platform             string          `json:"platform"`
		PlatformUserID       string          `json:"platform_user_id"`
		State                string          `json:"state"`
		VerificationMethod   string          `json:"verification_method"`
		VerificationMetadata json.RawMessage `json:"verification_metadata"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decodeErr := decoder.Decode(&req); decodeErr != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	if strings.TrimSpace(req.UserID) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": ErrUserIDRequired.Error()})
		return
	}
	if _, parseErr := uuid.Parse(strings.TrimSpace(req.UserID)); parseErr != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user_id must be a valid UUID"})
		return
	}

	state, err := parseLinkState(req.State)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	link, err := h.upsertLink(
		r.Context(),
		tenantID,
		strings.TrimSpace(req.UserID),
		strings.TrimSpace(req.Platform),
		strings.TrimSpace(req.PlatformUserID),
		state,
		strings.TrimSpace(req.VerificationMethod),
		req.VerificationMetadata,
	)
	if err != nil {
		switch {
		case errors.Is(err, ErrPlatformEmpty),
			errors.Is(err, ErrIdentityEmpty),
			errors.Is(err, ErrUserIDRequired),
			errors.Is(err, ErrLinkState):
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		case errors.Is(err, ErrUserNotFound):
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "creating channel link failed"})
			return
		}
	}

	writeJSON(w, http.StatusOK, link)
}

// HandleDeleteLink revokes/removes a tenant channel link.
// DELETE /api/v1/channels/links/{id}
func (h *Handler) HandleDeleteLink(w http.ResponseWriter, r *http.Request) {
	tenantID, err := resolveTenantID(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if h.deleteLink == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "channel links are not configured"})
		return
	}

	id := strings.TrimSpace(r.PathValue("id"))
	err = h.deleteLink(r.Context(), tenantID, id)
	if err != nil {
		switch {
		case errors.Is(err, ErrLinkIDRequired), errors.Is(err, ErrLinkIDInvalid):
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		case errors.Is(err, ErrLinkNotFound):
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "deleting channel link failed"})
			return
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// HandleListOutbox lists tenant outbox jobs with optional status filter and limit.
// GET /api/v1/channels/outbox
func (h *Handler) HandleListOutbox(w http.ResponseWriter, r *http.Request) {
	tenantID, err := resolveTenantID(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if h.listOutbox == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "channel outbox is not configured"})
		return
	}

	status := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("status")))
	limit := 100
	if rawLimit := strings.TrimSpace(r.URL.Query().Get("limit")); rawLimit != "" {
		parsedLimit, parseErr := strconv.Atoi(rawLimit)
		if parseErr != nil || parsedLimit <= 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "limit must be a positive integer"})
			return
		}
		limit = parsedLimit
	}

	jobs, err := h.listOutbox(r.Context(), tenantID, status, limit)
	if err != nil {
		if errors.Is(err, ErrOutboxStatus) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "listing channel outbox failed"})
		return
	}
	if jobs == nil {
		jobs = []ChannelOutbox{}
	}

	writeJSON(w, http.StatusOK, jobs)
}

// HandleRequeueOutboxDead requeues a dead outbox job back to pending.
// POST /api/v1/channels/outbox/{id}/requeue
func (h *Handler) HandleRequeueOutboxDead(w http.ResponseWriter, r *http.Request) {
	tenantID, err := resolveTenantID(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if h.requeueOutboxDead == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "channel outbox is not configured"})
		return
	}

	idValue := strings.TrimSpace(r.PathValue("id"))
	if idValue == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "outbox id is required"})
		return
	}
	outboxID, parseErr := uuid.Parse(idValue)
	if parseErr != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "outbox id must be a valid UUID"})
		return
	}

	err = h.requeueOutboxDead(r.Context(), tenantID, outboxID)
	if err != nil {
		if errors.Is(err, ErrOutboxNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "requeueing channel outbox failed"})
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]string{
		"status": "requeued",
		"id":     outboxID.String(),
	})
}

// HandleGetProviderCredential returns tenant-scoped provider credentials in sanitized form.
// GET /api/v1/channels/providers/{provider}/credentials
func (h *Handler) HandleGetProviderCredential(w http.ResponseWriter, r *http.Request) {
	tenantID, err := resolveTenantID(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if h.getProviderCredential == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "provider credentials are not configured"})
		return
	}

	provider := strings.TrimSpace(r.PathValue("provider"))
	credential, err := h.getProviderCredential(r.Context(), tenantID, provider)
	if err != nil {
		switch {
		case errors.Is(err, ErrPlatformEmpty), errors.Is(err, ErrProviderUnsupported):
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		case errors.Is(err, ErrProviderCredentialNotFound):
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "getting provider credential failed"})
			return
		}
	}

	writeJSON(w, http.StatusOK, sanitizeProviderCredentialResponse(credential))
}

// HandleUpsertProviderCredential creates or updates tenant-scoped provider credentials.
// PUT /api/v1/channels/providers/{provider}/credentials
func (h *Handler) HandleUpsertProviderCredential(w http.ResponseWriter, r *http.Request) {
	tenantID, err := resolveTenantID(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if h.upsertProviderCredential == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "provider credentials are not configured"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)

	var req struct {
		AccessToken   string `json:"access_token"`
		SigningSecret string `json:"signing_secret"`
		SecretToken   string `json:"secret_token"`
		APIBaseURL    string `json:"api_base_url"`
		APIVersion    string `json:"api_version"`
		PhoneNumberID string `json:"phone_number_id"`
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decodeErr := decoder.Decode(&req); decodeErr != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	credential, err := h.upsertProviderCredential(r.Context(), tenantID, UpsertProviderCredentialParams{
		Provider:      strings.TrimSpace(r.PathValue("provider")),
		AccessToken:   strings.TrimSpace(req.AccessToken),
		SigningSecret: strings.TrimSpace(req.SigningSecret),
		SecretToken:   strings.TrimSpace(req.SecretToken),
		APIBaseURL:    strings.TrimSpace(req.APIBaseURL),
		APIVersion:    strings.TrimSpace(req.APIVersion),
		PhoneNumberID: strings.TrimSpace(req.PhoneNumberID),
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrPlatformEmpty),
			errors.Is(err, ErrProviderUnsupported),
			errors.Is(err, ErrProviderAccessTokenRequired),
			errors.Is(err, ErrProviderPhoneNumberIDRequired),
			errors.Is(err, ErrProviderSigningSecretRequired),
			errors.Is(err, ErrProviderSecretTokenRequired):
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "upserting provider credential failed"})
			return
		}
	}

	writeJSON(w, http.StatusOK, sanitizeProviderCredentialResponse(credential))
}

// HandleDeleteProviderCredential deletes tenant-scoped provider credentials.
// DELETE /api/v1/channels/providers/{provider}/credentials
func (h *Handler) HandleDeleteProviderCredential(w http.ResponseWriter, r *http.Request) {
	tenantID, err := resolveTenantID(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if h.deleteProviderCredential == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "provider credentials are not configured"})
		return
	}

	provider := strings.TrimSpace(r.PathValue("provider"))
	err = h.deleteProviderCredential(r.Context(), tenantID, provider)
	if err != nil {
		switch {
		case errors.Is(err, ErrPlatformEmpty), errors.Is(err, ErrProviderUnsupported):
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		case errors.Is(err, ErrProviderCredentialNotFound):
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		default:
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "deleting provider credential failed"})
			return
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

type providerCredentialResponse struct {
	Provider         string    `json:"provider"`
	APIBaseURL       string    `json:"api_base_url"`
	APIVersion       string    `json:"api_version"`
	PhoneNumberID    string    `json:"phone_number_id"`
	HasAccessToken   bool      `json:"has_access_token"`
	HasSigningSecret bool      `json:"has_signing_secret"`
	HasSecretToken   bool      `json:"has_secret_token"`
	UpdatedAt        time.Time `json:"updated_at"`
}

func sanitizeProviderCredentialResponse(credential *ProviderCredential) providerCredentialResponse {
	if credential == nil {
		return providerCredentialResponse{}
	}
	return providerCredentialResponse{
		Provider:         credential.Provider,
		APIBaseURL:       credential.APIBaseURL,
		APIVersion:       credential.APIVersion,
		PhoneNumberID:    credential.PhoneNumberID,
		HasAccessToken:   strings.TrimSpace(credential.AccessToken) != "",
		HasSigningSecret: strings.TrimSpace(credential.SigningSecret) != "",
		HasSecretToken:   strings.TrimSpace(credential.SecretToken) != "",
		UpdatedAt:        credential.UpdatedAt,
	}
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

func parseLinkState(raw string) (LinkState, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return LinkStatePendingVerification, nil
	}

	switch LinkState(value) {
	case LinkStatePendingVerification, LinkStateVerified, LinkStateRevoked:
		return LinkState(value), nil
	default:
		return "", ErrLinkState
	}
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
